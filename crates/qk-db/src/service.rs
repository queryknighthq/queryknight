//! Guarded execution service: the single choke point between agent
//! SQL and real databases.
//!
//! ```text
//! authorize_guarded(request, auth)          [crate::auth, zero DB contact]
//!   → resolve cursor (cursor SQL is re-evaluated, never trusted)
//!   → evaluate() the exact SQL that will run
//!   → Deny (or anything unparsable) ⇒ Blocked, no adapter contact
//!   → RequireApproval ⇒ qk-approval resolve (store + provider)
//!   → not executable ⇒ Blocked / PendingApproval, still no contact
//!   → explicit executable Allow ⇒ ExecutionPermit (moved, not cloned)
//!
//! execute_guarded = authorize_guarded + execute_authorized
//! execute_authorized(permit) ⇒ adapter.execute(...) then budgets,
//! paging, post-execution impact estimate, cursor issuance
//! ```
//!
//! The service never interpolates params, never rewrites SQL except
//! the frozen paging append, and never contacts the database while
//! authorizing — not even for an impact EXPLAIN.

use std::sync::Arc;
use std::time::Duration;

use qk_approval::{ApprovalId, ApprovalProvider, ApprovalStore};
use qk_core::{Decision, ExecutionContext, PolicyFile, ReasonCode};

use crate::adapter::{DatabaseAdapter, Param};
use crate::budget::{
    clip_rows, estimate_tokens, is_multi_statement, is_select, trim_trailing_semicolons, with_page,
    ResultBudget,
};
use crate::config::DbConfig;
use crate::cursor::CursorStore;
use crate::error::{DbError, DbErrorKind};
use crate::result::{BudgetedResult, PingResult, RawResult, TableInfo, TableRef};

/// Execution timeout default (`QUERYKNIGHT_DB_TIMEOUT_MS` fallback).
/// Client-side race only: a timed-out statement MAY STILL BE RUNNING
/// server-side (documented on the error, never "rolled back").
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Trusted caller context: integration, environment, and database
/// identity from configuration — never from agent metadata.
#[derive(Debug, Clone)]
pub struct TrustedContext {
    /// Integration name (`mcp`, `cli`, ...).
    pub integration: String,
    /// Policy environment scope (`production`, ...).
    pub environment: String,
    /// Policy database key.
    pub database: String,
    /// Tool/operation source (`db_query`, ...).
    pub tool: String,
    /// Session identity for approval binding, when any.
    pub session_id: Option<String>,
}

impl TrustedContext {
    pub(crate) fn execution_context(&self) -> ExecutionContext {
        ExecutionContext {
            integration: self.integration.clone(),
            environment: self.environment.clone(),
            database: Some(self.database.clone()),
            agent_id: None,
            tool: Some(self.tool.clone()),
            session_id: self.session_id.clone(),
        }
    }
}

/// Approval plumbing for guarded execution (existing qk-approval
/// components; the service never reimplements resolution).
pub struct ApprovalSetup<'a> {
    /// Persistent grant store.
    pub store: &'a dyn ApprovalStore,
    /// Interactive provider, if any (None ⇒ approvals pend).
    pub provider: Option<&'a dyn ApprovalProvider>,
    /// Grant lifetime for newly stored rows.
    pub ttl_ms: u64,
    /// Current time (explicit, no clock reads in the service core).
    pub now_ms: u64,
}

/// Everything a guarded call needs beyond the request itself:
/// trusted adapter, connection, context, approvals, and policy.
pub struct GuardedCall<'a, 'b> {
    /// Trusted adapter (dialect derives from `config`, never the request).
    pub adapter: &'a dyn DatabaseAdapter,
    /// Trusted connection configuration (owns credentials opaquely).
    pub config: &'a DbConfig,
    /// Password-stripped connection key (cursor binding, history).
    pub connection_key: &'a str,
    /// Trusted policy context (integration/environment/database/tool).
    pub auth: &'a TrustedContext,
    /// Approval store + provider plumbing.
    pub approval: &'a ApprovalSetup<'b>,
    /// Validated policy file.
    pub policy: &'a PolicyFile,
}

/// Explain-only call surface (no approval plumbing: explain is
/// allow-only and never creates approvals).
pub struct ExplainCall<'a> {
    /// Trusted adapter.
    pub adapter: &'a dyn DatabaseAdapter,
    /// Trusted connection configuration.
    pub config: &'a DbConfig,
    /// Trusted policy context.
    pub auth: &'a TrustedContext,
    /// Validated policy file.
    pub policy: &'a PolicyFile,
}

/// One guarded execution request (agent-controlled fields only).
#[derive(Debug, Clone)]
pub struct ExecuteRequest {
    /// Untrusted SQL text (or empty when paging via `cursor`).
    pub sql: String,
    /// Bound parameters as JSON scalars (never interpolated).
    pub params: Vec<serde_json::Value>,
    /// Requested row cap (clamped into the budget).
    pub max_rows: Option<usize>,
    /// Continuation cursor from a previous truncated SELECT.
    pub cursor: Option<String>,
    /// Retry with a previously issued approval id.
    pub approval_id: Option<String>,
}

/// Machine-readable execution outcome. Policy/approval results are
/// outcomes, never errors; database failures are typed errors. Every
/// variant carries the audit facts observers need (decision, reason,
/// policy path, approval identity) — observers never re-derive them.
#[derive(Debug, Clone)]
pub enum ExecutionOutcome {
    /// The statement executed; bounded result plus authorization facts.
    Executed(ExecutedReport),
    /// Policy denied or resolution refused execution. The adapter was
    /// never contacted.
    Blocked(BlockedReason),
    /// The provider is waiting on a human. The adapter was never
    /// contacted; retry with `approval_id` after deciding.
    PendingApproval(PendingApproval),
    /// The statement was authorized but the database failed (or the
    /// request was malformed past policy). No policy information.
    Failed(DbError),
}

/// Executed statement: bounded result plus the authorization facts
/// that permitted it (direct allow or resolved approval).
#[derive(Debug, Clone)]
pub struct ExecutedReport {
    /// Bounded agent-facing result.
    pub result: BudgetedResult,
    /// Approval id that authorized execution, when via approval.
    pub approval_id: Option<ApprovalId>,
    /// Final reason code (`AllowRule`-family or `APPROVAL_GRANTED`).
    pub reason_code: ReasonCode,
    /// Decisive policy path, when the evaluation named one.
    pub matched_policy: Option<String>,
}

/// Why execution was refused without database contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedReason {
    /// Final verdict (always `Deny` here; explicit so observers never
    /// infer it).
    pub decision: Decision,
    /// Machine reason code (policy code or approval outcome).
    pub code: String,
    /// Human diagnostic (bounded, secret-free).
    pub message: String,
    /// Decisive policy path, when the evaluation named one.
    pub matched_policy: Option<String>,
}

/// A waiting approval the agent must resolve out of band.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingApproval {
    /// The waiting approval id for retry (`approvalId=<id>`).
    pub approval_id: String,
    /// Policy reason the approval was required.
    pub reason_code: String,
    /// Planner impact estimate for the waiting write, when obtained.
    pub estimated_rows: Option<u64>,
}

/// Guarded execution services: connection factory, policy, approvals,
/// budgets, cursors, timeout.
pub struct ExecutionService {
    cursors: CursorStore,
    budget: ResultBudget,
    timeout: Duration,
}

impl ExecutionService {
    /// Service with frozen defaults (50/64KiB/8000 budgets, 30s timeout).
    pub fn new() -> Self {
        Self {
            cursors: CursorStore::new(),
            budget: ResultBudget::default(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Override the result budget (tests).
    pub fn with_budget(mut self, budget: ResultBudget) -> Self {
        self.budget = budget;
        self
    }

    /// Override the execution timeout (tests).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Build the trusted adapter for a connection (dialect derives
    /// from the variant — never from request metadata).
    pub fn adapter_for(config: &DbConfig) -> Arc<dyn DatabaseAdapter> {
        match config {
            DbConfig::Postgres(_) => Arc::new(crate::adapters::postgres::PostgresAdapter),
            DbConfig::Mysql(_) => Arc::new(crate::adapters::mysql::MysqlAdapter),
            DbConfig::Sqlite(_) => Arc::new(crate::adapters::sqlite::SqliteAdapter),
        }
    }

    /// Guarded query execution: shared authorization first, then
    /// permit-consuming execution. Direct execution and future
    /// session-pinned adapters use the SAME authorization code.
    pub async fn execute_guarded(
        &self,
        call: &GuardedCall<'_, '_>,
        request: &ExecuteRequest,
    ) -> ExecutionOutcome {
        use crate::auth::{authorize_guarded, AuthorizationRequest, ResolveMode};
        let outcome = authorize_guarded(
            &self.cursors,
            &crate::auth::GuardedAuthorizationCall {
                config: call.config,
                connection_key: call.connection_key,
                auth: call.auth,
                approval: Some(call.approval),
                policy: call.policy,
            },
            &AuthorizationRequest {
                sql: request.sql.clone(),
                params: request.params.clone(),
                approval_id: request.approval_id.clone(),
                max_rows: request.max_rows,
                cursor: request.cursor.clone(),
            },
            ResolveMode::ResolveApprovals,
        );
        match outcome {
            crate::auth::AuthorizationOutcome::Permitted(permit) => {
                self.execute_authorized(call.adapter, call.config, *permit)
                    .await
            }
            crate::auth::AuthorizationOutcome::Blocked(reason) => ExecutionOutcome::Blocked(reason),
            crate::auth::AuthorizationOutcome::PendingApproval(pending) => {
                ExecutionOutcome::PendingApproval(pending)
            }
            crate::auth::AuthorizationOutcome::Failed(error) => ExecutionOutcome::Failed(error),
        }
    }

    /// Execute an authorized request, consuming its permit. The ONLY
    /// path from a permit to adapter contact: everything executed here
    /// was bound into the permit at authorization time. Consuming (not
    /// cloning) makes accidental repeated execution harder. `config`
    /// supplies only the connection target; the executed identity
    /// (dialect, SQL, params, paging) comes from the permit, and a
    /// dialect mismatch fails closed.
    pub async fn execute_authorized(
        &self,
        adapter: &dyn DatabaseAdapter,
        config: &DbConfig,
        permit: crate::auth::ExecutionPermit,
    ) -> ExecutionOutcome {
        if config.dialect() != permit.dialect {
            return ExecutionOutcome::Failed(DbError::new(
                DbErrorKind::Query,
                "permit dialect does not match connection dialect",
            ));
        }
        self.run_permitted(adapter, config, permit).await
    }

    /// Guarded EXPLAIN: allow-only (plans leak schema names, so
    /// approval-required statements pend and denied ones block).
    /// Shares the authorization implementation; `EvaluateOnly` means
    /// no provider contact and no rows created.
    pub async fn explain_guarded(
        &self,
        call: &ExplainCall<'_>,
        sql: &str,
        params: &[serde_json::Value],
    ) -> ExecutionOutcome {
        use crate::auth::{authorize_guarded, AuthorizationRequest, ResolveMode};
        let outcome = authorize_guarded(
            &self.cursors,
            &crate::auth::GuardedAuthorizationCall {
                config: call.config,
                // EXPLAIN never pages: no cursor can be supplied or
                // issued, so the key is never compared.
                connection_key: "",
                auth: call.auth,
                approval: None,
                policy: call.policy,
            },
            &AuthorizationRequest {
                sql: sql.to_owned(),
                params: params.to_vec(),
                approval_id: None,
                max_rows: None,
                cursor: None,
            },
            ResolveMode::EvaluateOnly,
        );
        let permit = match outcome {
            crate::auth::AuthorizationOutcome::Permitted(permit) => *permit,
            crate::auth::AuthorizationOutcome::Blocked(reason) => {
                return ExecutionOutcome::Blocked(reason)
            }
            crate::auth::AuthorizationOutcome::PendingApproval(pending) => {
                return ExecutionOutcome::PendingApproval(pending);
            }
            crate::auth::AuthorizationOutcome::Failed(error) => {
                return ExecutionOutcome::Failed(error)
            }
        };
        let bound = match to_driver_params(&permit.params) {
            Ok(params) => params,
            Err(error) => return ExecutionOutcome::Failed(error),
        };
        match with_deadline(
            self.timeout,
            call.adapter
                .explain(url_of(call.config), &permit.sql, &bound),
        )
        .await
        {
            Ok(Ok(plan)) => ExecutionOutcome::Executed(ExecutedReport {
                result: BudgetedResult {
                    columns: vec!["plan".to_owned()],
                    rows: vec![vec![crate::value::DbValue::Text(plan)]],
                    rows_affected: None,
                    rows_shown: 1,
                    estimated_rows_matched: None,
                    truncated: false,
                    bytes_returned: 0,
                    estimated_tokens_returned: 0,
                    estimated_tokens_avoided: None,
                    cursor: None,
                },
                approval_id: permit.approval_id,
                reason_code: permit.reason_code,
                matched_policy: permit.matched_policy,
            }),
            Ok(Err(error)) => ExecutionOutcome::Failed(error),
            Err(_) => ExecutionOutcome::Failed(timeout_error()),
        }
    }

    /// Guarded sampling: the generated SELECT is evaluated like any
    /// SQL (Allow runs, RequireApproval pends, Deny blocks). No
    /// cursors (re-randomization would mislead).
    pub async fn sample_guarded(
        &self,
        call: &GuardedCall<'_, '_>,
        schema: Option<&str>,
        table: &str,
        limit: usize,
    ) -> ExecutionOutcome {
        let limit = limit.clamp(1, 200);
        let sql = call.adapter.sample_sql(schema, table, limit);
        self.execute_guarded(
            call,
            &ExecuteRequest {
                sql,
                params: Vec::new(),
                max_rows: Some(limit),
                cursor: None,
                approval_id: None,
            },
        )
        .await
    }

    /// Ungated identifier-only metadata: list tables (fixed
    /// introspection statements, quoted identifiers — no SQL channel).
    pub async fn list_tables(
        &self,
        adapter: &dyn DatabaseAdapter,
        config: &DbConfig,
        schema: Option<&str>,
        limit: usize,
    ) -> Result<Vec<TableRef>, DbError> {
        let mut tables = with_deadline(self.timeout, adapter.list_tables(url_of(config), schema))
            .await
            .map_err(|_| timeout_error())??;
        tables.truncate(limit);
        Ok(tables)
    }

    /// Ungated identifier-only metadata: describe one table.
    pub async fn describe_table(
        &self,
        adapter: &dyn DatabaseAdapter,
        config: &DbConfig,
        schema: Option<&str>,
        name: &str,
    ) -> Result<TableInfo, DbError> {
        with_deadline(
            self.timeout,
            adapter.describe_table(url_of(config), schema, name),
        )
        .await
        .map_err(|_| timeout_error())?
    }

    /// Unauthenticated-handshake connection test (never user SQL).
    pub async fn test_connection(
        &self,
        adapter: &dyn DatabaseAdapter,
        config: &DbConfig,
    ) -> Result<PingResult, DbError> {
        with_deadline(self.timeout, adapter.test_connection(url_of(config)))
            .await
            .map_err(|_| timeout_error())?
    }

    /// Approval resolution for RequireApproval evaluations lives in
    /// `crate::auth` (shared with the future proxy path).
    /// Execute an explicitly authorized statement with budgets, paging,
    /// impact estimates, and cursor issuance. Every executable input
    /// is read from the permit — none from the original request.
    async fn run_permitted(
        &self,
        adapter: &dyn DatabaseAdapter,
        config: &DbConfig,
        permit: crate::auth::ExecutionPermit,
    ) -> ExecutionOutcome {
        if is_multi_statement(&permit.sql) {
            return ExecutionOutcome::Failed(DbError::new(
                DbErrorKind::Query,
                "multiple statements are not allowed",
            ));
        }
        let bound = match to_driver_params(&permit.params) {
            Ok(params) => params,
            Err(error) => return ExecutionOutcome::Failed(error),
        };
        let max_rows = permit.max_rows.map_or(self.budget.max_rows, |max| {
            max.min(self.budget.max_rows).max(1)
        });
        let trimmed = trim_trailing_semicolons(&permit.sql);
        let select = is_select(&trimmed);
        // Frozen paging: limit-less SELECTs fetch one extra row to
        // detect the cap.
        let statement = if select && !has_limit_word(&trimmed) {
            with_page(&trimmed, max_rows + 1, permit.offset)
        } else {
            trimmed.clone()
        };
        let executed = match with_deadline(
            self.timeout,
            adapter.execute(url_of(config), &statement, &bound),
        )
        .await
        {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => return ExecutionOutcome::Failed(error),
            Err(_) => return ExecutionOutcome::Failed(timeout_error()),
        };
        self.shape_result(
            adapter,
            config,
            executed,
            PermittedShape {
                select,
                max_rows,
                offset: permit.offset,
                sql: trimmed,
                params: permit.params,
                connection_key: permit.connection_key,
                approval_id: permit.approval_id,
                reason_code: permit.reason_code,
                matched_policy: permit.matched_policy,
            },
        )
        .await
    }

    /// Apply row-cap probing, budgets, estimates, and cursor issuance.
    async fn shape_result(
        &self,
        adapter: &dyn DatabaseAdapter,
        config: &DbConfig,
        executed: RawResult,
        shape: PermittedShape,
    ) -> ExecutionOutcome {
        if !shape.select {
            // Mutations bypass paging (rowsAffected instead).
            return ExecutionOutcome::Executed(ExecutedReport {
                result: BudgetedResult {
                    columns: executed.columns,
                    rows: Vec::new(),
                    rows_affected: executed.rows_affected,
                    rows_shown: 0,
                    estimated_rows_matched: None,
                    truncated: false,
                    bytes_returned: 0,
                    estimated_tokens_returned: 0,
                    estimated_tokens_avoided: None,
                    cursor: None,
                },
                approval_id: shape.approval_id,
                reason_code: shape.reason_code,
                matched_policy: shape.matched_policy,
            });
        }
        let fetched = executed.rows;
        let hit_row_cap = fetched.len() > shape.max_rows;
        let page: Vec<_> = if hit_row_cap {
            fetched[..shape.max_rows].to_vec()
        } else {
            fetched
        };
        let page_budget = ResultBudget {
            max_rows: shape.max_rows,
            ..self.budget
        };
        let (rows, bytes, tokens, clipped) = clip_rows(page, page_budget);
        let truncated = clipped || hit_row_cap;
        // Planner estimate (post-execution; failures degrade to None).
        let estimated_rows_matched = match adapter
            .explain(url_of(config), &shape.sql, &to_params(&shape.params))
            .await
        {
            Ok(plan) => parse_rows_estimate(&plan),
            Err(_) => None,
        };
        let estimated_tokens_avoided = match (estimated_rows_matched, rows.len()) {
            (Some(matched), shown) if matched > shown as u64 && shown > 0 => {
                let avg = bytes / shown;
                let full = avg as u64 * matched;
                Some(estimate_tokens(full as usize).saturating_sub(tokens))
            }
            _ => None,
        };
        let cursor = if truncated {
            Some(self.cursors.issue(
                shape.sql,
                shape.params,
                offset_add(shape.offset, rows.len()),
                shape.connection_key,
            ))
        } else {
            None
        };
        ExecutionOutcome::Executed(ExecutedReport {
            result: BudgetedResult {
                columns: executed.columns,
                rows_shown: rows.len(),
                rows,
                rows_affected: executed.rows_affected,
                estimated_rows_matched,
                truncated,
                bytes_returned: bytes,
                estimated_tokens_returned: tokens,
                estimated_tokens_avoided,
                cursor,
            },
            approval_id: shape.approval_id,
            reason_code: shape.reason_code,
            matched_policy: shape.matched_policy,
        })
    }
}

/// Shaping inputs for a SELECT result, all derived from the permit.
struct PermittedShape {
    select: bool,
    max_rows: usize,
    offset: u64,
    sql: String,
    params: Vec<serde_json::Value>,
    connection_key: String,
    approval_id: Option<ApprovalId>,
    reason_code: ReasonCode,
    matched_policy: Option<String>,
}

fn offset_add(offset: u64, shown: usize) -> u64 {
    offset.saturating_add(shown as u64)
}

fn url_of(config: &DbConfig) -> &crate::config::SecretUrl {
    match config {
        DbConfig::Postgres(url) | DbConfig::Mysql(url) | DbConfig::Sqlite(url) => url,
    }
}

fn to_driver_params(params: &[serde_json::Value]) -> Result<Vec<Param>, DbError> {
    params.iter().map(Param::from_json).collect()
}

fn to_params(params: &[serde_json::Value]) -> Vec<Param> {
    params
        .iter()
        .filter_map(|param| Param::from_json(param).ok())
        .collect()
}

fn has_limit_word(sql: &str) -> bool {
    let lower = sql.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut i = 0;
    while i + 5 <= bytes.len() {
        if &bytes[i..i + 5] == b"limit"
            && (i == 0 || !is_word_byte(bytes[i - 1]))
            && (i + 5 >= bytes.len() || !is_word_byte(bytes[i + 5]))
        {
            return true;
        }
        i += 1;
    }
    false
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Frozen unbounded-write sniff for impact estimation. The evaluator
/// owns the real classification; this is only the cheap pre-check for
/// whether an EXPLAIN roundtrip is worthwhile.
/// Frozen planner-estimate parse (`/\brows[=:]?\s*(\d+)/i`: covers pg
/// `rows=` and mysql `rows:` header shapes).
fn parse_rows_estimate(plan: &str) -> Option<u64> {
    let bytes = plan.as_bytes();
    let mut i = 0;
    while i + 4 < bytes.len() {
        if bytes[i..].starts_with(b"rows") && (i == 0 || !is_word_byte(bytes[i - 1])) {
            let mut j = i + 4;
            if j < bytes.len() && (bytes[j] == b'=' || bytes[j] == b':') {
                j += 1;
            }
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            let mut value: u64 = 0;
            let mut digits = 0;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                value = value
                    .saturating_mul(10)
                    .saturating_add(u64::from(bytes[j] - b'0'));
                digits += 1;
                j += 1;
            }
            if digits > 0 {
                return Some(value);
            }
        }
        i += 1;
    }
    None
}

/// Bounded execution race. On timeout the future is dropped; the
/// statement MAY STILL BE RUNNING server-side (documented, never
/// "rolled back"). No detached tasks outlive the request.
async fn with_deadline<T>(
    timeout: Duration,
    operation: impl std::future::Future<Output = T>,
) -> Result<T, ()> {
    match tokio::time::timeout(timeout, operation).await {
        Ok(value) => Ok(value),
        Err(_) => Err(()),
    }
}

fn timeout_error() -> DbError {
    DbError::new(
        DbErrorKind::Timeout,
        "database timed out (the statement may still be running server-side)",
    )
}

impl Default for ExecutionService {
    fn default() -> Self {
        Self::new()
    }
}
