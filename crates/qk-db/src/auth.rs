//! Guarded authorization plane: evaluate + approval resolution with
//! ZERO database contact, issuing an opaque [`ExecutionPermit`] for
//! exactly one concrete executable request.
//!
//! Direct execution (`execute_guarded`) and future session-pinned
//! adapters (wire proxies) share this code: authorize first, then
//! execute/forward only with a permit. There is deliberately no second
//! policy/approval implementation.

use qk_approval::{ApprovalId, ApprovalScope, ResolveRequest};
use qk_core::{
    evaluate, Decision, DigestParam, EvaluateOptions, EvaluationRequest, ExactDigest,
    ExecutionContext, PolicyFile, QueryShapeFingerprint, ReasonCode,
};
use qk_sql::SqlDialect;

use crate::budget::MAX_PARAMS;
use crate::config::DbConfig;
use crate::cursor::CursorStore;
use crate::error::{DbError, DbErrorKind};
use crate::service::{ApprovalSetup, BlockedReason, PendingApproval, TrustedContext};

/// Authorization-only call surface: everything EXCEPT the adapter.
/// The absence of any adapter handle is structural proof that
/// authorization cannot contact the database.
pub struct GuardedAuthorizationCall<'a, 'b> {
    /// Trusted connection configuration (dialect source).
    pub config: &'a DbConfig,
    /// Password-stripped connection key (cursor binding).
    pub connection_key: &'a str,
    /// Trusted policy context.
    pub auth: &'a TrustedContext,
    /// Approval store + provider plumbing. Required in
    /// `ResolveApprovals` mode; unused in `EvaluateOnly` (no provider
    /// contact, so explain can authorize without approval wiring).
    pub approval: Option<&'a ApprovalSetup<'b>>,
    /// Validated policy file.
    pub policy: &'a PolicyFile,
}

/// Authorization input: the executable request under review. Row caps
/// and cursor IDs ride along because they materially shape the
/// executed statement (LIMIT/OFFSET); result formatting never enters
/// authorization identity.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    /// Untrusted SQL text (or empty when paging via `cursor`).
    pub sql: String,
    /// Bound parameters as JSON scalars (never interpolated).
    pub params: Vec<serde_json::Value>,
    /// Retry with a previously issued approval id.
    pub approval_id: Option<String>,
    /// Requested row cap (clamped into the budget at execution).
    pub max_rows: Option<usize>,
    /// Continuation cursor from a previous truncated SELECT.
    pub cursor: Option<String>,
}

/// Whether authorization may resolve approvals (contact providers).
/// `explain_guarded` authorizes evaluate-only: approval-gated SQL
/// pends without provider contact or row creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveMode {
    /// Full flow: evaluate + approval resolution.
    ResolveApprovals,
    /// Evaluate only: Allow → permit, RequireApproval → pending,
    /// Deny → blocked. No provider contact, no rows created.
    EvaluateOnly,
}

/// Authorization verdict: a permit, a refusal, a pending approval,
/// or an input fault. `Permitted` is the ONLY executable state;
/// everything else must never reach an adapter. `Failed` covers
/// cursor/param faults that prevent evaluation (fail-closed, never a
/// policy decision) — preserved from the pre-refactor behavior.
pub enum AuthorizationOutcome {
    /// This exact current request passed authorization (boxed: a
    /// move-only capability that dwarfs the other verdicts).
    Permitted(Box<ExecutionPermit>),
    /// Refused without database contact.
    Blocked(BlockedReason),
    /// Waiting on a human; retry out-of-band.
    PendingApproval(PendingApproval),
    /// Malformed authorization input (unknown cursor, param overflow).
    Failed(DbError),
}

/// Opaque execution capability for exactly one concrete request.
/// Process-local authority: no public constructor, no `Clone`, no
/// `Default`, no serde impls — only [`authorize_guarded`] mints it,
/// and execution consumes it by move. The accessors below expose only
/// read-only identity metadata (never the bound SQL or params), which
/// is what a protocol adapter legitimately needs to check a retry or
/// an existing grant; construction stays impossible from outside.
pub struct ExecutionPermit {
    pub(crate) dialect: SqlDialect,
    pub(crate) shape: QueryShapeFingerprint,
    pub(crate) exact: ExactDigest,
    pub(crate) scope: ApprovalScope,
    pub(crate) reason_code: ReasonCode,
    pub(crate) matched_policy: Option<String>,
    pub(crate) approval_id: Option<ApprovalId>,
    pub(crate) sql: String,
    pub(crate) params: Vec<serde_json::Value>,
    pub(crate) offset: u64,
    pub(crate) max_rows: Option<usize>,
    pub(crate) connection_key: String,
}

impl ExecutionPermit {
    /// Trusted dialect of the authorized statement.
    pub fn dialect(&self) -> SqlDialect {
        self.dialect
    }

    /// Structural fingerprint (statement shape) the permit covers.
    pub fn shape(&self) -> &QueryShapeFingerprint {
        &self.shape
    }

    /// Exact request identity (V1/V2-tagged) the permit covers.
    pub fn exact(&self) -> &ExactDigest {
        &self.exact
    }

    /// Full trusted scope the permit is bound to.
    pub fn scope(&self) -> &ApprovalScope {
        &self.scope
    }

    /// Policy reason code that produced this permit.
    pub fn reason_code(&self) -> &ReasonCode {
        &self.reason_code
    }

    /// Matched policy id, when a policy rule was responsible.
    pub fn matched_policy(&self) -> Option<&str> {
        self.matched_policy.as_deref()
    }

    /// Approval that carried this permit, when one was used.
    pub fn approval_id(&self) -> Option<&ApprovalId> {
        self.approval_id.as_ref()
    }
}

/// Authorize one executable request with zero database contact.
/// Returns a permit for exactly one concrete request, a refusal, or
/// a pending approval. Pure policy/approval flow over trusted
/// inputs; cursor state is the only I/O (in-memory).
pub fn authorize_guarded(
    cursors: &CursorStore,
    call: &GuardedAuthorizationCall<'_, '_>,
    request: &AuthorizationRequest,
    mode: ResolveMode,
) -> AuthorizationOutcome {
    // Cursor paging reuses stored SQL; the resolved text is what gets
    // evaluated (never trust the cursor blindly).
    let (sql, params, offset) = match resolve_cursor(cursors, request, call.connection_key) {
        Ok(resolved) => resolved,
        Err(error) => return AuthorizationOutcome::Failed(error),
    };
    if params.len() > MAX_PARAMS {
        return AuthorizationOutcome::Failed(DbError::new(
            DbErrorKind::Query,
            format!("too many query parameters (max {MAX_PARAMS})"),
        ));
    }
    let context = call.auth.execution_context();
    let evaluation = evaluate(
        &EvaluationRequest {
            context: &context,
            dialect: call.config.dialect(),
            sql: &sql,
            policy: call.policy,
        },
        &EvaluateOptions::default(),
    );
    if evaluation.decision != Decision::Allow && evaluation.decision != Decision::RequireApproval {
        return AuthorizationOutcome::Blocked(BlockedReason {
            decision: Decision::Deny,
            code: evaluation.reason_code.as_str().to_owned(),
            message: evaluation.message.clone(),
            matched_policy: evaluation.matched_policy.clone(),
        });
    }
    if evaluation.decision == Decision::RequireApproval {
        if mode == ResolveMode::EvaluateOnly {
            return AuthorizationOutcome::PendingApproval(PendingApproval {
                approval_id: String::new(),
                reason_code: evaluation.reason_code.as_str().to_owned(),
                estimated_rows: None,
            });
        }
        match resolve_approval(
            call,
            &evaluation,
            &sql,
            &params,
            request.approval_id.as_deref(),
        ) {
            Resolve::Executable(resolved) => {
                return permit_for(
                    call,
                    &sql,
                    &params,
                    offset,
                    request,
                    resolved.approval_id,
                    resolved.reason_code,
                    resolved.matched_policy,
                );
            }
            Resolve::Outcome(outcome) => return *outcome,
        }
    }
    // Direct allow: facts come from the evaluation itself.
    permit_for(
        call,
        &sql,
        &params,
        offset,
        request,
        None,
        evaluation.reason_code,
        evaluation.matched_policy.clone(),
    )
}

/// Mint the permit for an explicitly authorized request.
#[allow(clippy::too_many_arguments)]
fn permit_for(
    call: &GuardedAuthorizationCall<'_, '_>,
    sql: &str,
    params: &[serde_json::Value],
    offset: u64,
    request: &AuthorizationRequest,
    approval_id: Option<qk_approval::ApprovalId>,
    reason_code: ReasonCode,
    matched_policy: Option<String>,
) -> AuthorizationOutcome {
    AuthorizationOutcome::Permitted(Box::new(ExecutionPermit {
        dialect: call.config.dialect(),
        shape: qk_core::sql_fingerprint(sql),
        exact: exact_for(call.config.dialect(), sql, params),
        scope: scope_of(&call.auth.execution_context()),
        reason_code,
        matched_policy,
        approval_id,
        sql: sql.to_owned(),
        params: params.to_vec(),
        offset,
        max_rows: request.max_rows,
        connection_key: call.connection_key.to_owned(),
    }))
}

/// Exact identity for a request (V1 when param-less, V2 otherwise).
fn exact_for(dialect: SqlDialect, sql: &str, params: &[serde_json::Value]) -> qk_core::ExactDigest {
    let digest: Vec<DigestParam> = params.iter().map(param_to_digest).collect();
    if digest.is_empty() {
        qk_core::ExactDigest::V1(qk_core::exact_request_digest(dialect, sql))
    } else {
        qk_core::ExactDigest::V2(qk_core::exact_request_digest_v2(dialect, sql, &digest))
    }
}

/// Canonical digest parameter from a JSON scalar: the same typed
/// value the driver will bind (integers keep integer precision —
/// never routed through f64 for identity).
pub(crate) fn param_to_digest(value: &serde_json::Value) -> DigestParam {
    match value {
        serde_json::Value::Null => DigestParam::Null,
        serde_json::Value::Bool(value) => DigestParam::Bool(*value),
        serde_json::Value::Number(value) => {
            if let Some(int) = value.as_i64() {
                DigestParam::Int(int)
            } else if let Some(uint) = value.as_u64() {
                DigestParam::UInt(uint)
            } else if let Some(float) = value.as_f64() {
                DigestParam::FloatBits(float.to_bits())
            } else {
                DigestParam::Text(value.to_string())
            }
        }
        serde_json::Value::String(text) => DigestParam::Text(text.clone()),
        // Compound values cannot bind as params (rejected later by
        // driver conversion); digest them by canonical JSON text so
        // they still perturb identity deterministically.
        other => DigestParam::Text(other.to_string()),
    }
}

fn scope_of(context: &ExecutionContext) -> ApprovalScope {
    ApprovalScope {
        session_id: context.session_id.clone(),
        integration: context.integration.clone(),
        environment: context.environment.clone(),
        database: context.database.clone().unwrap_or_default(),
        agent_id: context.agent_id.clone().unwrap_or_default(),
        tool: context.tool.clone().unwrap_or_default(),
    }
}

/// Resolve cursor-or-direct input into (sql, params, offset), mirroring
/// the frozen `input.cursor && !sql` branch.
fn resolve_cursor(
    cursors: &CursorStore,
    request: &AuthorizationRequest,
    connection_key: &str,
) -> Result<(String, Vec<serde_json::Value>, u64), DbError> {
    if let Some(cursor_id) = request.cursor.as_deref() {
        if request.sql.trim().is_empty() {
            let stored = cursors.read(cursor_id, connection_key)?;
            return Ok((stored.sql, stored.params, stored.offset));
        }
    }
    Ok((request.sql.clone(), request.params.clone(), 0))
}

/// Internal resolution verdict: executable (with facts) or a final
/// non-executable outcome.
enum Resolve {
    Executable(qk_approval::ResolvedEvaluation),
    Outcome(Box<AuthorizationOutcome>),
}

fn resolve_approval(
    call: &GuardedAuthorizationCall<'_, '_>,
    evaluation: &qk_core::EvaluationResult,
    sql: &str,
    params: &[serde_json::Value],
    approval_id: Option<&str>,
) -> Resolve {
    // Fail closed rather than panic if approval wiring is missing: a
    // caller bug must never become an implicit Allow.
    let Some(setup) = call.approval else {
        return Resolve::Outcome(Box::new(AuthorizationOutcome::Failed(DbError::new(
            DbErrorKind::Query,
            "approval resolution requires approval plumbing",
        ))));
    };
    let context = call.auth.execution_context();
    let digest: Vec<DigestParam> = params.iter().map(param_to_digest).collect();
    let resolved = qk_approval::resolve(
        &ResolveRequest {
            evaluation,
            context: &context,
            dialect: call.config.dialect(),
            sql,
            params: &digest,
            approval_id,
            ttl_ms: setup.ttl_ms,
            now_ms: setup.now_ms,
        },
        setup.store,
        setup.provider,
    );
    use qk_approval::ResolutionOutcome;
    let blocked = || {
        AuthorizationOutcome::Blocked(BlockedReason {
            decision: Decision::Deny,
            code: resolved.reason_code.as_str().to_owned(),
            message: resolved.message.clone(),
            matched_policy: resolved.matched_policy.clone(),
        })
    };
    match resolved.outcome {
        ResolutionOutcome::ExistingGrant | ResolutionOutcome::ProviderApproved => {
            if resolved.decision == Decision::Allow {
                Resolve::Executable(resolved)
            } else {
                Resolve::Outcome(Box::new(blocked()))
            }
        }
        ResolutionOutcome::ProviderWaiting => Resolve::Outcome(Box::new(
            AuthorizationOutcome::PendingApproval(PendingApproval {
                approval_id: resolved
                    .approval_id
                    .map(|id| id.as_str().to_owned())
                    .unwrap_or_default(),
                reason_code: resolved.reason_code.as_str().to_owned(),
                estimated_rows: None,
            }),
        )),
        ResolutionOutcome::ProviderDenied
        | ResolutionOutcome::ProviderUnavailable
        | ResolutionOutcome::ProviderError
        | ResolutionOutcome::NotRequired => Resolve::Outcome(Box::new(blocked())),
    }
}
