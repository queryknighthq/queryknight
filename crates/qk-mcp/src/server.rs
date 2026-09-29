//! rmcp stdio server: the frozen eight tools as thin adapters over
//! `qk-db` guarded execution and the daemon control plane. Tool
//! arguments are untrusted agent input; trusted context (integration,
//! environment, database, dialect) comes from startup configuration
//! only (INV-037).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerConfig};
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use qk_approval::InMemoryApprovalStore;
use qk_db::{
    ApprovalSetup, ExecuteRequest, ExecutionOutcome, ExecutionService, ExplainCall, GuardedCall,
    TrustedContext,
};

use crate::config::McpConnection;
use crate::daemon::{DaemonApprovalProvider, DaemonEndpoint};
use crate::error::{protocol_error, ErrorKind};
use crate::format::{
    format_blocked, format_explain, format_pending_approval, format_query, format_schema_overview,
    format_table, format_tables, parse_table_ref,
};
use crate::history::{HistoryEvent, HistoryRecorder};

/// Server name (frozen).
pub const SERVER_NAME: &str = "queryknight";

/// Frozen instructions template (connection key interpolated).
pub fn instructions(connection_key: &str) -> String {
    [
        format!("Use QueryKnight for every database inspection and SQL against the bound connection ({connection_key}). Prefer these tools over mysql, psql, sqlite3, docker exec, and ad-hoc bash. Do not scan ports or process lists to find a database while these tools are available."),
        "db_tables: list tables. db_describe: columns/PK/indexes/FKs of one table. db_schema: compact table+column overview. db_query: run SQL (result-budgeted; no unbounded SELECT *). db_sample: random rows. db_explain: estimated plan. approvals_list: waiting approvals. approvals_decide: approve/deny a waiting approval by id.".to_owned(),
        "When db_query returns \"Blocked: waiting for approval <id>\", a destructive statement is paused. Ask the user to approve or deny it explicitly, then call approvals_decide(\"<id>\", \"approved\") or approvals_decide(\"<id>\", \"denied\") and retry db_query with the same SQL plus approvalId=\"<id>\". Never approve without the user confirming.".to_owned(),
        "If the user names a different host or database than this connection, say so. Do not silently fall back to a CLI against another server.".to_owned(),
    ]
    .join("\n")
}

/// Shared service state (one bound connection per server instance).
/// Note there is deliberately NO persistent local approval store:
/// the daemon is the system of record for approvals, and a stale
/// local Waiting row would shadow daemon decisions on retry (a retry
/// must always re-consult the daemon). Each call resolves against a
/// fresh store; id stability across retries comes from the daemon
/// row itself (the provider echoes the bind id).
pub struct McpState {
    service: ExecutionService,
    adapter: Arc<dyn qk_db::DatabaseAdapter>,
    connection: McpConnection,
    policy: qk_core::PolicyFile,
    /// Daemon endpoint for history + approvals (`None` degrades to
    /// history-less execution and frozen unavailable texts).
    endpoint: Option<DaemonEndpoint>,
    history: Option<HistoryRecorder>,
    observer: qk_audit::Observer,
}

impl McpState {
    /// Build from a bound connection URL and policy. Daemon discovery
    /// is best-effort (`None` on any failure — tools degrade, never
    /// fail at startup for a missing daemon).
    pub fn new(
        url: &str,
        policy: qk_core::PolicyFile,
        home: Option<std::path::PathBuf>,
    ) -> Result<Self, McpError> {
        let connection = McpConnection::from_url(url)?;
        let adapter = ExecutionService::adapter_for(&connection.config);
        let endpoint = DaemonEndpoint::discover(home);
        let history = endpoint
            .as_ref()
            .and_then(|endpoint| HistoryRecorder::start(endpoint, &connection.connection_key));
        Ok(Self {
            service: ExecutionService::new(),
            adapter,
            connection,
            policy,
            endpoint,
            history,
            observer: qk_audit::Observer::new(vec![]),
        })
    }

    /// Deterministic state without daemon discovery (tests and
    /// single-process embedding): history attached explicitly.
    pub fn without_daemon(
        url: &str,
        policy: qk_core::PolicyFile,
        history: Option<HistoryRecorder>,
    ) -> Result<Self, McpError> {
        let connection = McpConnection::from_url(url)?;
        let adapter = ExecutionService::adapter_for(&connection.config);
        Ok(Self {
            service: ExecutionService::new(),
            adapter,
            connection,
            policy,
            endpoint: None,
            history,
            observer: qk_audit::Observer::new(vec![]),
        })
    }

    /// Shared observer (audit sinks + metrics).
    pub fn observer(&self) -> &qk_audit::Observer {
        &self.observer
    }

    /// Replace the observer (tests inject memory sinks here).
    pub fn set_observer(&mut self, observer: qk_audit::Observer) {
        self.observer = observer;
    }

    fn trusted(&self) -> TrustedContext {
        TrustedContext {
            // Assigned by the server, never claimed by the agent.
            integration: "mcp".to_owned(),
            environment: self.connection.environment.clone(),
            database: self.connection.database_key.clone(),
            tool: "db_query".to_owned(),
            session_id: self
                .history
                .as_ref()
                .map(|history| history.session_id().to_owned()),
        }
    }

    /// Assemble per-call approval plumbing: a fresh local store
    /// (the daemon is the record; see the `McpState` docs) around an
    /// optional provider. The borrow structure keeps `GuardedCall`
    /// assembly at call sites.
    fn approval_setup<'a>(
        provider: Option<&'a dyn qk_approval::ApprovalProvider>,
        store: &'a InMemoryApprovalStore,
    ) -> ApprovalSetup<'a> {
        ApprovalSetup {
            store,
            provider,
            ttl_ms: 60_000,
            now_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_millis() as u64)
                .unwrap_or(0),
        }
    }
}

/// Bound connection URL sources (frozen: `MYSQL_URL`, then
/// `DATABASE_URL`; missing both is a startup usage error).
pub fn connection_url_from_env() -> Option<String> {
    std::env::var("MYSQL_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .or_else(|| {
            std::env::var("DATABASE_URL")
                .ok()
                .filter(|url| !url.trim().is_empty())
        })
}

/// Load the policy file (`QUERYKNIGHT_POLICY_FILE`) or fall back to
/// the built-in demo policy. Invalid files fail startup fast (frozen
/// `QUERYKNIGHT_POLICY_FILE invalid` behavior).
pub fn load_policy() -> Result<qk_core::PolicyFile, String> {
    match std::env::var("QUERYKNIGHT_POLICY_FILE") {
        Ok(path) if !path.trim().is_empty() => {
            let text = std::fs::read_to_string(path.as_str()).map_err(|error| {
                format!("QUERYKNIGHT_POLICY_FILE invalid: cannot read {path}: {error}")
            })?;
            qk_core::parse_policy(&text)
                .map_err(|error| format!("QUERYKNIGHT_POLICY_FILE invalid: {error}"))
        }
        _ => {
            qk_core::demo_policy().map_err(|error| format!("internal demo policy invalid: {error}"))
        }
    }
}

// ---------------------------------------------------------------------------
// Tool argument schemas (frozen shapes; unknown fields ignored).
// ---------------------------------------------------------------------------

/// `db_query` arguments (frozen: sql 1–1M chars, params ≤1000,
/// maxRows 1–200, cursor, approvalId).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DbQueryArgs {
    /// SQL to execute.
    #[schemars(length(min = 1, max = 1_000_000))]
    pub sql: String,
    /// Bound parameters.
    #[schemars(length(max = 1000))]
    #[serde(default)]
    pub params: Option<Vec<serde_json::Value>>,
    /// Requested row cap.
    #[schemars(range(min = 1, max = 200))]
    #[serde(default)]
    pub max_rows: Option<u32>,
    /// Continuation cursor.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Retry a waiting approval after approvals_decide(<id>, "approved").
    #[serde(default)]
    pub approval_id: Option<String>,
}

/// `db_tables` arguments (frozen limits).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DbTablesArgs {
    /// Database/schema name.
    #[serde(default)]
    pub schema: Option<String>,
    /// Include views.
    #[serde(default)]
    pub include_views: Option<bool>,
    /// Listing cap.
    #[schemars(range(min = 1, max = 200))]
    #[serde(default)]
    pub limit: Option<u32>,
}

/// `db_describe` arguments.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DbDescribeArgs {
    /// Table name, optionally schema.table.
    pub table: String,
    /// Explicit schema.
    #[serde(default)]
    pub schema: Option<String>,
}

/// `db_schema` arguments.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DbSchemaArgs {
    /// Database/schema name.
    #[serde(default)]
    pub schema: Option<String>,
    /// Table cap.
    #[schemars(range(min = 1, max = 200))]
    #[serde(default)]
    pub limit: Option<u32>,
}

/// `db_explain` arguments.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DbExplainArgs {
    /// SQL to plan.
    pub sql: String,
    /// Bound parameters.
    #[serde(default)]
    pub params: Option<Vec<serde_json::Value>>,
}

/// `db_sample` arguments.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DbSampleArgs {
    /// Table name, optionally schema.table.
    pub table: String,
    /// Explicit schema.
    /// Database/schema name.
    #[serde(default)]
    pub schema: Option<String>,
    /// Table cap.
    #[schemars(range(min = 1, max = 200))]
    #[serde(default)]
    pub limit: Option<u32>,
}

/// `approvals_decide` arguments (frozen enum).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalsDecideArgs {
    /// Approval id, e.g. qka_4e40db0b.
    pub id: String,
    /// Verdict.
    pub status: ApprovalStatus,
}

/// Frozen approval verdict strings.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalStatus {
    /// Human approved.
    Approved,
    /// Human denied.
    Denied,
}

// ---------------------------------------------------------------------------
// rmcp server.
// ---------------------------------------------------------------------------

/// Thin MCP server: argument validation → trusted context → qk-db or
/// daemon control plane → frozen text. No security logic here.
#[derive(Clone)]
pub struct QueryKnightServer {
    state: Arc<McpState>,
    tool_router: ToolRouter<Self>,
}

impl QueryKnightServer {
    /// Build from service state.
    pub fn new(state: McpState) -> Self {
        Self {
            state: Arc::new(state),
            tool_router: Self::tool_router(),
        }
    }

    /// Underlying state (tests drive handlers without MCP framing).
    pub fn state(&self) -> &McpState {
        &self.state
    }

    /// Mutable state (tests inject observers/sinks here).
    pub fn state_mut(&mut self) -> &mut McpState {
        Arc::get_mut(&mut self.state).expect("unshared server state")
    }

    /// Registered tools for schema-snapshot tests.
    pub fn tools_snapshot(&self) -> Vec<rmcp::model::Tool> {
        let mut tools = self.tool_router.list_all();
        tools.sort_by(|a, b| a.name.cmp(&b.name));
        tools
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for QueryKnightServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(SERVER_NAME, env!("CARGO_PKG_VERSION")))
            .with_instructions(instructions(&self.state.connection.connection_key))
    }
}

#[tool_router(router = tool_router)]
impl QueryKnightServer {
    /// List tables (and optionally views). Prefer over SHOW TABLES / \dt / .tables. Use db_describe for columns.
    #[tool(
        name = "db_tables",
        description = "List tables (and optionally views). Prefer over SHOW TABLES / \\dt / .tables. Use db_describe for columns.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    pub async fn db_tables(&self, params: Parameters<DbTablesArgs>) -> Result<String, McpError> {
        self.db_tables_impl(params.0).await
    }

    /// Describe one table: columns, primary key, indexes, foreign keys.
    #[tool(
        name = "db_describe",
        description = "Describe one table: columns, primary key, indexes, foreign keys.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    pub async fn db_describe(
        &self,
        params: Parameters<DbDescribeArgs>,
    ) -> Result<String, McpError> {
        self.db_describe_impl(params.0).await
    }

    /// Bounded schema overview: table names and column names only.
    #[tool(
        name = "db_schema",
        description = "Bounded schema overview: table names and column names only.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    pub async fn db_schema(&self, params: Parameters<DbSchemaArgs>) -> Result<String, McpError> {
        self.db_schema_impl(params.0).await
    }

    /// Execute SQL through QueryKnight with result budgets. Prefer over mysql/psql CLI and unbounded SELECT *.
    #[tool(
        name = "db_query",
        description = "Execute SQL through QueryKnight with result budgets. Prefer over mysql/psql CLI and unbounded SELECT *.",
        annotations(read_only_hint = false, destructive_hint = true)
    )]
    pub async fn db_query(&self, params: Parameters<DbQueryArgs>) -> Result<String, McpError> {
        self.db_query_impl(params.0).await
    }

    /// EXPLAIN a query. Returns an estimated plan, not measured runtime.
    #[tool(
        name = "db_explain",
        description = "EXPLAIN a query. Returns an estimated plan, not measured runtime.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    pub async fn db_explain(&self, params: Parameters<DbExplainArgs>) -> Result<String, McpError> {
        self.db_explain_impl(params.0).await
    }

    /// Sample N random rows from a table (ORDER BY RANDOM), bypassing the biased first-N of SELECT *. Use when db_query on SELECT * would return thousands of rows.
    #[tool(
        name = "db_sample",
        description = "Sample N random rows from a table (ORDER BY RANDOM), bypassing the biased first-N of SELECT *. Use when db_query on SELECT * would return thousands of rows.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    pub async fn db_sample(&self, params: Parameters<DbSampleArgs>) -> Result<String, McpError> {
        self.db_sample_impl(params.0).await
    }

    /// List waiting approvals (id, risk, operation, reason, current schema). Use when db_query returns "Blocked: waiting for approval" to see what is paused.
    #[tool(
        name = "approvals_list",
        description = "List waiting approvals (id, risk, operation, reason, current schema). Use when db_query returns \"Blocked: waiting for approval\" to see what is paused.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    pub async fn approvals_list(&self) -> Result<String, McpError> {
        self.approvals_list_impl().await
    }

    /// Approve or deny a waiting approval by id. Only after the user explicitly confirms; never self-approve destructive SQL.
    #[tool(
        name = "approvals_decide",
        description = "Approve or deny a waiting approval by id. Only after the user explicitly confirms; never self-approve destructive SQL.",
        annotations(read_only_hint = false, destructive_hint = true)
    )]
    pub async fn approvals_decide(
        &self,
        params: Parameters<ApprovalsDecideArgs>,
    ) -> Result<String, McpError> {
        self.approvals_decide_impl(params.0).await
    }
}

impl QueryKnightServer {
    fn approval_provider(&self, approval_id: Option<String>) -> Option<DaemonApprovalProvider> {
        let endpoint = self.state.endpoint.clone()?;
        Some(DaemonApprovalProvider::new(
            endpoint,
            self.state
                .history
                .as_ref()
                .map(|history| history.session_id().to_owned()),
            self.state.connection.connection_key.clone(),
            approval_id,
        ))
    }

    /// Observe one guarded outcome: exactly one audit event plus
    /// metric increments. Sink failures go to stderr (bounded,
    /// secret-free) and never affect results.
    fn observe_outcome(&self, sql: &str, started: SystemTime, outcome: &ExecutionOutcome) {
        let trusted = self.state.trusted();
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);
        let observation = qk_audit::Observation::from_outcome(
            qk_audit::new_event_id(),
            now_ms,
            started
                .elapsed()
                .map(|elapsed| elapsed.as_millis() as u64)
                .unwrap_or(0),
            None,
            None,
            trusted.integration,
            trusted.environment,
            Some(trusted.database),
            None,
            trusted.session_id,
            None,
            Some(trusted.tool),
            self.state.connection.config.dialect(),
            sql.to_owned(),
            outcome,
        );
        for failure in self
            .state
            .observer()
            .observe(&observation, qk_audit::SqlLogLevel::Fingerprint)
        {
            eprintln!("audit sink failed: {failure}");
        }
    }

    /// Handler entry (public for integration tests).
    pub async fn db_query_impl(&self, args: DbQueryArgs) -> Result<String, McpError> {
        validate_query(&args)?;
        let started = SystemTime::now();
        let provider = self.approval_provider(args.approval_id.clone());
        let auth = self.state.trusted();
        let store = InMemoryApprovalStore::new();
        let approval =
            McpState::approval_setup(provider.as_ref().map(|provider| provider as _), &store);
        let call = GuardedCall {
            adapter: self.state.adapter.as_ref(),
            config: &self.state.connection.config,
            connection_key: &self.state.connection.connection_key,
            auth: &auth,
            approval: &approval,
            policy: &self.state.policy,
        };
        let outcome = self
            .state
            .service
            .execute_guarded(
                &call,
                &ExecuteRequest {
                    sql: args.sql.clone(),
                    params: args.params.clone().unwrap_or_default(),
                    max_rows: args.max_rows.map(|max| max as usize),
                    cursor: args.cursor.clone(),
                    approval_id: args.approval_id.clone(),
                },
            )
            .await;
        self.observe_outcome(&args.sql, started, &outcome);
        self.finish_query(args.sql, started, outcome)
    }

    /// Map an execution outcome to frozen MCP text + best-effort history.
    /// Database failures become protocol errors (frozen: throw); every
    /// other outcome is a successful text result.
    fn finish_query(
        &self,
        sql: String,
        started: SystemTime,
        outcome: ExecutionOutcome,
    ) -> Result<String, McpError> {
        let duration_ms = started
            .elapsed()
            .map(|elapsed| elapsed.as_millis() as u64)
            .ok();
        match outcome {
            ExecutionOutcome::Executed(report) => {
                let result = &report.result;
                self.record(HistoryEvent {
                    sql,
                    decision: Some("executed".to_owned()),
                    duration_ms,
                    rows_returned: Some(result.rows_shown),
                    rows_affected: result.rows_affected,
                    bytes_returned: Some(result.bytes_returned),
                    estimated_tokens_returned: Some(result.estimated_tokens_returned),
                    estimated_tokens_avoided: result.estimated_tokens_avoided,
                    ..Default::default()
                });
                Ok(format_query(result))
            }
            ExecutionOutcome::Blocked(reason) => {
                self.record(HistoryEvent {
                    sql,
                    decision: Some("denied".to_owned()),
                    error_code: Some(reason.code.clone()),
                    duration_ms,
                    ..Default::default()
                });
                Ok(format_blocked(&format!(
                    "{} [{}]",
                    reason.message, reason.code
                )))
            }
            ExecutionOutcome::PendingApproval(pending) => {
                // `wait:false` agent flow never blocks here; the pending
                // template carries the retry instructions.
                Ok(format_pending_approval(&pending.approval_id))
            }
            ExecutionOutcome::Failed(error) => {
                self.record(HistoryEvent {
                    sql,
                    decision: Some("error".to_owned()),
                    error_code: Some(error.to_string()),
                    duration_ms,
                    ..Default::default()
                });
                Err(protocol_error(ErrorKind::Database(error)))
            }
        }
    }

    /// Handler entry (public for integration tests).
    pub async fn db_explain_impl(&self, args: DbExplainArgs) -> Result<String, McpError> {
        if args.sql.trim().is_empty() {
            return Err(protocol_error(ErrorKind::Schema(
                "sql is required".to_owned(),
            )));
        }
        let started = SystemTime::now();
        let auth = self.state.trusted();
        let call = ExplainCall {
            adapter: self.state.adapter.as_ref(),
            config: &self.state.connection.config,
            auth: &auth,
            policy: &self.state.policy,
        };
        let outcome = self
            .state
            .service
            .explain_guarded(&call, &args.sql, &args.params.unwrap_or_default())
            .await;
        self.observe_outcome(&args.sql, started, &outcome);
        match outcome {
            ExecutionOutcome::Executed(report) => {
                let plan = report.result.rows.first().and_then(|row| row.first());
                let text = match plan {
                    Some(qk_db::DbValue::Text(text)) => text.clone(),
                    _ => String::new(),
                };
                self.record(HistoryEvent {
                    sql: format!("EXPLAIN {}", args.sql),
                    decision: Some("executed".to_owned()),
                    duration_ms: started
                        .elapsed()
                        .map(|elapsed| elapsed.as_millis() as u64)
                        .ok(),
                    ..Default::default()
                });
                Ok(format_explain(&text))
            }
            ExecutionOutcome::Blocked(reason) => Ok(format_blocked(&format!(
                "{} [{}]",
                reason.message, reason.code
            ))),
            ExecutionOutcome::PendingApproval(pending) => {
                Ok(format_pending_approval(&pending.approval_id))
            }
            ExecutionOutcome::Failed(error) => Err(protocol_error(ErrorKind::Database(error))),
        }
    }

    /// Handler entry (public for integration tests).
    pub async fn db_sample_impl(&self, args: DbSampleArgs) -> Result<String, McpError> {
        validate_table(&args.table)?;
        let started = SystemTime::now();
        let provider = self.approval_provider(None);
        let auth = self.state.trusted();
        let store = InMemoryApprovalStore::new();
        let approval =
            McpState::approval_setup(provider.as_ref().map(|provider| provider as _), &store);
        let call = GuardedCall {
            adapter: self.state.adapter.as_ref(),
            config: &self.state.connection.config,
            connection_key: &self.state.connection.connection_key,
            auth: &auth,
            approval: &approval,
            policy: &self.state.policy,
        };
        let (schema, name) = parse_table_ref(&args.table, args.schema.as_deref());
        let limit = args.limit.unwrap_or(20) as usize;
        // The exact generated SELECT (pure constructor — same text the
        // service evaluates and executes).
        let sample_sql = self
            .state
            .adapter
            .sample_sql(schema.as_deref(), &name, limit);
        let outcome = self
            .state
            .service
            .sample_guarded(&call, schema.as_deref(), &name, limit)
            .await;
        self.observe_outcome(&sample_sql, started, &outcome);
        match outcome {
            ExecutionOutcome::Executed(report) => {
                let result = &report.result;
                self.record(HistoryEvent {
                    sql: format!("SAMPLE {}", args.table),
                    decision: Some("executed".to_owned()),
                    duration_ms: started
                        .elapsed()
                        .map(|elapsed| elapsed.as_millis() as u64)
                        .ok(),
                    rows_returned: Some(result.rows_shown),
                    ..Default::default()
                });
                Ok(format_query(result))
            }
            ExecutionOutcome::Blocked(reason) => Ok(format_blocked(&format!(
                "{} [{}]",
                reason.message, reason.code
            ))),
            ExecutionOutcome::PendingApproval(pending) => {
                Ok(format_pending_approval(&pending.approval_id))
            }
            ExecutionOutcome::Failed(error) => Err(protocol_error(ErrorKind::Database(error))),
        }
    }

    /// Handler entry (public for integration tests).
    pub async fn db_tables_impl(&self, args: DbTablesArgs) -> Result<String, McpError> {
        let started = SystemTime::now();
        let mut tables = self
            .state
            .service
            .list_tables(
                self.state.adapter.as_ref(),
                &self.state.connection.config,
                args.schema.as_deref(),
                args.limit.unwrap_or(50) as usize,
            )
            .await
            .map_err(|error| protocol_error(ErrorKind::Database(error)))?;
        if !args.include_views.unwrap_or(false) {
            tables.retain(|table| table.kind == qk_db::TableKind::Table);
        }
        let sql = match args.schema.as_deref() {
            Some(schema) => format!("SHOW TABLES FROM {schema}"),
            None => "SHOW TABLES".to_owned(),
        };
        self.record(HistoryEvent {
            sql,
            decision: Some("executed".to_owned()),
            duration_ms: started
                .elapsed()
                .map(|elapsed| elapsed.as_millis() as u64)
                .ok(),
            ..Default::default()
        });
        // Truncation flag mirrors the reference (`tables.length > limit`
        // before slicing); our service already truncates, so recompute
        // from the request limit honestly: truncated when the listing
        // hit the cap exactly.
        let truncated = tables.len() >= args.limit.unwrap_or(50) as usize;
        Ok(format_tables(&tables, truncated))
    }

    /// Handler entry (public for integration tests).
    pub async fn db_describe_impl(&self, args: DbDescribeArgs) -> Result<String, McpError> {
        validate_table(&args.table)?;
        let started = SystemTime::now();
        let (schema, name) = parse_table_ref(&args.table, args.schema.as_deref());
        let info = self
            .state
            .service
            .describe_table(
                self.state.adapter.as_ref(),
                &self.state.connection.config,
                schema.as_deref(),
                &name,
            )
            .await
            .map_err(|error| protocol_error(ErrorKind::Database(error)))?;
        self.record(HistoryEvent {
            sql: format!("DESCRIBE {}", args.table),
            decision: Some("executed".to_owned()),
            duration_ms: started
                .elapsed()
                .map(|elapsed| elapsed.as_millis() as u64)
                .ok(),
            ..Default::default()
        });
        Ok(format_table(&info))
    }

    /// Handler entry (public for integration tests).
    pub async fn db_schema_impl(&self, args: DbSchemaArgs) -> Result<String, McpError> {
        let started = SystemTime::now();
        let limit = args.limit.unwrap_or(50) as usize;
        let mut tables = self
            .state
            .service
            .list_tables(
                self.state.adapter.as_ref(),
                &self.state.connection.config,
                args.schema.as_deref(),
                limit,
            )
            .await
            .map_err(|error| protocol_error(ErrorKind::Database(error)))?;
        tables.retain(|table| table.kind == qk_db::TableKind::Table);
        let mut defs = Vec::new();
        for table in tables.iter().take(limit) {
            let info = self
                .state
                .service
                .describe_table(
                    self.state.adapter.as_ref(),
                    &self.state.connection.config,
                    table.schema.as_deref(),
                    &table.name,
                )
                .await
                .map_err(|error| protocol_error(ErrorKind::Database(error)))?;
            defs.push(info);
        }
        self.record(HistoryEvent {
            sql: "SHOW TABLES -- schema".to_owned(),
            decision: Some("executed".to_owned()),
            duration_ms: started
                .elapsed()
                .map(|elapsed| elapsed.as_millis() as u64)
                .ok(),
            ..Default::default()
        });
        Ok(format_schema_overview(&defs, defs.len() >= limit))
    }

    /// Handler entry (public for integration tests).
    pub async fn approvals_list_impl(&self) -> Result<String, McpError> {
        let Some(endpoint) = self.state.endpoint.clone() else {
            return Ok("daemon unavailable; start queryknight".to_owned());
        };
        let views = endpoint
            .list_approvals()
            .map_err(|_: crate::daemon::DaemonFailure| {
                protocol_error(ErrorKind::Daemon("approvals listing failed".to_owned()))
            })?;
        let waiting: Vec<&serde_json::Value> = views
            .iter()
            .filter(|view| view.get("status").and_then(|status| status.as_str()) == Some("waiting"))
            .collect();
        if waiting.is_empty() {
            return Ok("No waiting approvals.".to_owned());
        }
        Ok(waiting
            .iter()
            .map(|view| format_approval(view))
            .collect::<Vec<_>>()
            .join("\n\n"))
    }

    /// Handler entry (public for integration tests).
    pub async fn approvals_decide_impl(
        &self,
        args: ApprovalsDecideArgs,
    ) -> Result<String, McpError> {
        let Some(endpoint) = self.state.endpoint.clone() else {
            return Ok("daemon unavailable; start queryknight".to_owned());
        };
        if args.id.trim().is_empty() {
            return Err(protocol_error(ErrorKind::Schema(
                "id is required".to_owned(),
            )));
        }
        let status = match args.status {
            ApprovalStatus::Approved => "approved",
            ApprovalStatus::Denied => "denied",
        };
        let decided =
            endpoint
                .decide(&args.id, status)
                .map_err(|_: crate::daemon::DaemonFailure| {
                    protocol_error(ErrorKind::Daemon("approval decision failed".to_owned()))
                })?;
        Ok(format!("approval {}: {decided}", args.id))
    }

    /// Best-effort history (synchronous loopback call; failures
    /// swallowed inside the recorder — never affects results).
    fn record(&self, event: HistoryEvent) {
        if let Some(history) = self.state.history.as_ref() {
            history.record(event);
        }
    }
}

/// Format one waiting approval (frozen `approvalsList` shape).
fn format_approval(view: &serde_json::Value) -> String {
    let text = |key: &str| view.get(key).and_then(|value| value.as_str()).unwrap_or("");
    let mut lines = vec![
        format!(
            "{}  {}  {}",
            text("id"),
            text("risk"),
            text("operationSummary")
        ),
        format!("  {}", text("reason")),
    ];
    if let Some(snaps) = view.get("schemaDdl").and_then(|value| value.as_array()) {
        for snap in snaps {
            let name = snap
                .get("ref")
                .map(|reference| {
                    let schema = reference
                        .get("schema")
                        .and_then(|value| value.as_str())
                        .unwrap_or("");
                    let name = reference
                        .get("name")
                        .and_then(|value| value.as_str())
                        .unwrap_or("");
                    if schema.is_empty() {
                        name.to_owned()
                    } else {
                        format!("{schema}.{name}")
                    }
                })
                .unwrap_or_else(|| "schema".to_owned());
            lines.push(format!("  schema (current) [{name}]:"));
            for line in snap
                .get("ddl")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .lines()
            {
                lines.push(format!("    {line}"));
            }
        }
    }
    lines.join("\n")
}

/// Schema-level `db_query` validation (frozen bounds; rejects before
/// any service contact).
fn validate_query(args: &DbQueryArgs) -> Result<(), McpError> {
    if args.sql.is_empty() || args.sql.len() > 1_000_000 {
        return Err(protocol_error(ErrorKind::Schema(
            "sql must be 1..1000000 characters".to_owned(),
        )));
    }
    if args
        .params
        .as_ref()
        .is_some_and(|params| params.len() > 1000)
    {
        return Err(protocol_error(ErrorKind::Schema(
            "too many query parameters (max 1000)".to_owned(),
        )));
    }
    if args.max_rows.is_some_and(|max| !(1..=200).contains(&max)) {
        return Err(protocol_error(ErrorKind::Schema(
            "maxRows must be 1..200".to_owned(),
        )));
    }
    Ok(())
}

fn validate_table(table: &str) -> Result<(), McpError> {
    if table.trim().is_empty() {
        return Err(protocol_error(ErrorKind::Schema(
            "table is required".to_owned(),
        )));
    }
    Ok(())
}

/// Serve stdio until EOF (stdout is protocol-only; diagnostics go to
/// stderr via tracing on the binary side).
pub async fn serve_stdio(server: QueryKnightServer) -> Result<(), McpError> {
    use rmcp::ServiceExt;
    let transport = rmcp::transport::io::stdio();
    let running = server.serve(transport).await.map_err(|error| {
        protocol_error(ErrorKind::Internal(format!("stdio serve failed: {error}")))
    })?;
    running.waiting().await.map(|_| ()).map_err(|error| {
        protocol_error(ErrorKind::Internal(format!(
            "stdio runtime failed: {error}"
        )))
    })
}
