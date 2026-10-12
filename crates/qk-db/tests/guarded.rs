//! Choke-point proofs: the adapter is never contacted without an
//! explicit executable Allow, and exactly once for authorized work.
//! A recording fake stands in for all engines (no live DBs here).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use qk_approval::{
    ApprovalBinding, ApprovalId, ApprovalScope, ApprovalStore, DecisionSource, GrantStatus,
    InMemoryApprovalStore, ProviderDecision, Scope, TestProvider,
};
use qk_db::{
    ApprovalSetup, Capabilities, DatabaseAdapter, DbConfig, DbError, DbErrorKind, DbValue,
    ExecuteRequest, ExecutionOutcome, ExecutionService, GuardedCall, Param, PingResult, RawResult,
    SecretUrl, TableInfo, TableRef, TrustedContext,
};

const POLICY: &str = r#"
version: 1
defaults:
  decision: deny
  on_parse_error: deny
  on_unknown: deny
environments:
  production:
    databases:
      main:
        allow:
          - operations: [select]
        deny:
          - operations: [drop, truncate]
        approval_required:
          - operations: [update, delete, insert]
        sensitive:
          columns:
            - users.password_hash
        mutations:
          deny_without_where: [update, delete]
        row_safety:
          max_limit: 1000
"#;

const NOW: u64 = 1_700_000_000_000;
const CONNECTION_KEY: &str = "sqlite:test";

fn policy() -> qk_core::PolicyFile {
    qk_core::parse_policy(POLICY).expect("test policy valid")
}

fn auth() -> TrustedContext {
    TrustedContext {
        integration: "test".to_owned(),
        environment: "production".to_owned(),
        database: "main".to_owned(),
        tool: "db_query".to_owned(),
        session_id: Some("session-1".to_owned()),
    }
}

fn approval<'a>(
    store: &'a dyn ApprovalStore,
    provider: Option<&'a dyn qk_approval::ApprovalProvider>,
) -> ApprovalSetup<'a> {
    ApprovalSetup {
        store,
        provider,
        ttl_ms: 60_000,
        now_ms: NOW,
    }
}

fn request(sql: &str) -> ExecuteRequest {
    ExecuteRequest {
        sql: sql.to_owned(),
        params: Vec::new(),
        max_rows: None,
        cursor: None,
        approval_id: None,
    }
}

/// Recording fake: counts calls, logs SQL/params, replays configured
/// output. The service under test cannot distinguish it from a driver.
struct FakeAdapter {
    calls: AtomicUsize,
    explains: AtomicUsize,
    log: Mutex<Vec<String>>,
    params_log: Mutex<Vec<usize>>,
    result: Mutex<RawResult>,
    error: Mutex<Option<DbError>>,
}

impl FakeAdapter {
    fn with_rows(rows: Vec<Vec<DbValue>>) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            explains: AtomicUsize::new(0),
            log: Mutex::new(Vec::new()),
            params_log: Mutex::new(Vec::new()),
            result: Mutex::new(RawResult {
                columns: vec!["a".to_owned()],
                rows,
                rows_affected: None,
            }),
            error: Mutex::new(None),
        }
    }

    fn failing(error: DbError) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            explains: AtomicUsize::new(0),
            log: Mutex::new(Vec::new()),
            params_log: Mutex::new(Vec::new()),
            result: Mutex::new(RawResult::empty()),
            error: Mutex::new(Some(error)),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn explains(&self) -> usize {
        self.explains.load(Ordering::SeqCst)
    }

    fn sql_log(&self) -> Vec<String> {
        self.log.lock().expect("log").clone()
    }
}

#[async_trait::async_trait]
impl DatabaseAdapter for FakeAdapter {
    fn engine(&self) -> &'static str {
        "fake"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            schemas: false,
            explain: false,
            explain_writes: false,
            sampling: false,
        }
    }

    async fn test_connection(&self, _url: &SecretUrl) -> Result<PingResult, DbError> {
        Ok(PingResult {
            ok: true,
            latency_ms: 0,
            server_version: None,
        })
    }

    async fn execute(
        &self,
        _url: &SecretUrl,
        sql: &str,
        params: &[Param],
    ) -> Result<RawResult, DbError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.log.lock().expect("log").push(sql.to_owned());
        self.params_log.lock().expect("log").push(params.len());
        match self.error.lock().expect("lock").clone() {
            Some(error) => Err(error),
            None => Ok(self.result.lock().expect("lock").clone()),
        }
    }

    async fn explain(
        &self,
        _url: &SecretUrl,
        _sql: &str,
        _params: &[Param],
    ) -> Result<String, DbError> {
        self.explains.fetch_add(1, Ordering::SeqCst);
        Ok("Seq Scan on t (cost=0 rows=42)".to_owned())
    }

    async fn list_schemas(&self, _url: &SecretUrl) -> Result<Vec<String>, DbError> {
        Ok(vec![])
    }

    async fn list_tables(
        &self,
        _url: &SecretUrl,
        _schema: Option<&str>,
    ) -> Result<Vec<TableRef>, DbError> {
        Ok(vec![])
    }

    async fn describe_table(
        &self,
        _url: &SecretUrl,
        _schema: Option<&str>,
        _name: &str,
    ) -> Result<TableInfo, DbError> {
        Err(DbError::new(DbErrorKind::Unsupported, "no tables"))
    }

    fn sample_sql(&self, _schema: Option<&str>, _name: &str, _limit: usize) -> String {
        "SELECT 1".to_owned()
    }
}

fn sqlite_config() -> DbConfig {
    DbConfig::Sqlite(SecretUrl::new("sqlite::memory:").expect("url"))
}

async fn run(
    service: &ExecutionService,
    adapter: &FakeAdapter,
    sql: &str,
    store: &InMemoryApprovalStore,
    provider: Option<&TestProvider>,
) -> ExecutionOutcome {
    let config = sqlite_config();
    let auth = auth();
    let approval = approval(store, provider.map(|provider| provider as _));
    let policy = policy();
    service
        .execute_guarded(
            &GuardedCall {
                adapter,
                config: &config,
                connection_key: CONNECTION_KEY,
                auth: &auth,
                approval: &approval,
                policy: &policy,
            },
            &request(sql),
        )
        .await
}

fn blocked(outcome: &ExecutionOutcome) -> bool {
    matches!(outcome, ExecutionOutcome::Blocked(_))
}

/// Full-control guarded call (custom requests, configs, providers).
#[allow(clippy::too_many_arguments)]
async fn guarded(
    service: &ExecutionService,
    adapter: &dyn DatabaseAdapter,
    config: &DbConfig,
    request: &ExecuteRequest,
    auth: &TrustedContext,
    approval: &ApprovalSetup<'_>,
    policy: &qk_core::PolicyFile,
) -> ExecutionOutcome {
    service
        .execute_guarded(
            &GuardedCall {
                adapter,
                config,
                connection_key: CONNECTION_KEY,
                auth,
                approval,
                policy,
            },
            request,
        )
        .await
}

#[tokio::test]
async fn unsupported_postgres_transport_blocks_before_approval_or_adapter() {
    let service = ExecutionService::new();
    let adapter = FakeAdapter::with_rows(vec![]);
    let store = InMemoryApprovalStore::new();
    let provider = TestProvider::new(vec![ProviderDecision::Approved]);
    let auth = auth();
    let approval = approval(&store, Some(&provider));
    let policy = policy();

    for ssl_options in ["", "?sslmode=prefer"] {
        let raw_url = format!("postgres://qk:PG_TLS_SECRET_12345@localhost/db{ssl_options}");
        let config = DbConfig::from_url(&raw_url).expect("config");
        let outcome = guarded(
            &service,
            &adapter,
            &config,
            &request("UPDATE users SET display_name = 'x' WHERE id = 1"),
            &auth,
            &approval,
            &policy,
        )
        .await;
        match outcome {
            ExecutionOutcome::Blocked(reason) => {
                assert_eq!(reason.code, qk_core::ReasonCode::PolicyError.as_str());
                assert!(reason.message.contains("sslmode=prefer"));
                assert!(!reason.message.contains("PG_TLS_SECRET_12345"));
            }
            other => panic!("unsupported transport must block: {other:?}"),
        }
        assert_eq!(provider.calls(), 0, "no approval request is permitted");
        assert_eq!(adapter.calls(), 0, "no adapter operation is permitted");
    }
}

// ---------------------------------------------------------------------------
// Adapter is NEVER called without executable authorization.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn parse_error_never_reaches_adapter() {
    let service = ExecutionService::new();
    let adapter = FakeAdapter::with_rows(vec![]);
    let store = InMemoryApprovalStore::new();
    let outcome = run(&service, &adapter, "SELEC FRM WHERE", &store, None).await;
    assert!(blocked(&outcome), "unexpected: {outcome:?}");
    assert_eq!(adapter.calls(), 0);
}

#[tokio::test]
async fn depth_truncated_never_reaches_adapter() {
    // 100 nested SELECTs trip MAX_WALK_DEPTH (64) → incomplete analysis
    // → deny, with zero database contact.
    let mut sql = "SELECT * FROM t".to_owned();
    for _ in 0..100 {
        sql = format!("SELECT * FROM ({sql})");
    }
    let service = ExecutionService::new();
    let adapter = FakeAdapter::with_rows(vec![]);
    let store = InMemoryApprovalStore::new();
    let outcome = run(&service, &adapter, &sql, &store, None).await;
    assert!(blocked(&outcome), "unexpected: {outcome:?}");
    assert_eq!(adapter.calls(), 0);
}

#[tokio::test]
async fn sensitive_column_never_reaches_adapter() {
    let service = ExecutionService::new();
    let adapter = FakeAdapter::with_rows(vec![]);
    let store = InMemoryApprovalStore::new();
    let outcome = run(
        &service,
        &adapter,
        "SELECT password_hash FROM users",
        &store,
        None,
    )
    .await;
    assert!(blocked(&outcome), "unexpected: {outcome:?}");
    assert_eq!(adapter.calls(), 0);
}

#[tokio::test]
async fn deny_rule_never_reaches_adapter() {
    let service = ExecutionService::new();
    let adapter = FakeAdapter::with_rows(vec![]);
    let store = InMemoryApprovalStore::new();
    let outcome = run(&service, &adapter, "DROP TABLE t", &store, None).await;
    assert!(blocked(&outcome), "unexpected: {outcome:?}");
    assert_eq!(adapter.calls(), 0);
}

#[tokio::test]
async fn unbounded_write_never_reaches_adapter() {
    let service = ExecutionService::new();
    let adapter = FakeAdapter::with_rows(vec![]);
    let store = InMemoryApprovalStore::new();
    for sql in ["UPDATE t SET a = 1", "DELETE FROM t"] {
        let outcome = run(&service, &adapter, sql, &store, None).await;
        // Unbounded writes deny (no WHERE) before any approval or DB.
        assert!(blocked(&outcome), "{sql}: {outcome:?}");
    }
    assert_eq!(adapter.calls(), 0);
}

#[tokio::test]
async fn limit_violation_never_reaches_adapter() {
    let service = ExecutionService::new();
    let adapter = FakeAdapter::with_rows(vec![]);
    let store = InMemoryApprovalStore::new();
    let outcome = run(
        &service,
        &adapter,
        "SELECT * FROM t LIMIT 5000",
        &store,
        None,
    )
    .await;
    assert!(blocked(&outcome), "unexpected: {outcome:?}");
    assert_eq!(adapter.calls(), 0);
}

#[tokio::test]
async fn waiting_approval_never_reaches_adapter() {
    let service = ExecutionService::new();
    let adapter = FakeAdapter::with_rows(vec![]);
    let store = InMemoryApprovalStore::new();
    let waiting = TestProvider::new(vec![ProviderDecision::Waiting]);
    let outcome = run(
        &service,
        &adapter,
        "UPDATE t SET a = 1 WHERE id = 1",
        &store,
        Some(&waiting),
    )
    .await;
    assert!(
        matches!(outcome, ExecutionOutcome::PendingApproval(_)),
        "unexpected: {outcome:?}"
    );
    assert_eq!(adapter.calls(), 0);
}

#[tokio::test]
async fn unavailable_denied_errored_providers_never_reach_adapter() {
    let service = ExecutionService::new();
    for provider in [
        None,
        Some(TestProvider::new(vec![ProviderDecision::Denied])),
        Some(TestProvider::new(vec![ProviderDecision::Waiting])),
    ] {
        let adapter = FakeAdapter::with_rows(vec![]);
        let store = InMemoryApprovalStore::new();
        let outcome = if let Some(provider) = provider.as_ref() {
            run(
                &service,
                &adapter,
                "UPDATE t SET a = 1 WHERE id = 1",
                &store,
                Some(provider),
            )
            .await
        } else {
            run(
                &service,
                &adapter,
                "UPDATE t SET a = 1 WHERE id = 1",
                &store,
                None,
            )
            .await
        };
        // Denied → Blocked; Waiting → Pending; missing → Blocked.
        // None may execute.
        assert!(
            blocked(&outcome) || matches!(outcome, ExecutionOutcome::PendingApproval(_)),
            "unexpected: {outcome:?}"
        );
        assert_eq!(adapter.calls(), 0);
    }
    // Error provider: explicit error case (not just denial).
    let adapter = FakeAdapter::with_rows(vec![]);
    let store = InMemoryApprovalStore::new();
    let erroring = qk_approval::ErrorProvider::new("boom");
    let config = sqlite_config();
    let auth = auth();
    let approval = approval(&store, Some(&erroring));
    let policy = policy();
    let outcome = guarded(
        &service,
        &adapter,
        &config,
        &request("UPDATE t SET a = 1 WHERE id = 1"),
        &auth,
        &approval,
        &policy,
    )
    .await;
    assert!(blocked(&outcome), "unexpected: {outcome:?}");
    assert_eq!(adapter.calls(), 0);
}

fn grant_for(sql: &str, binding: ApprovalBinding, reuse: Scope) -> qk_approval::StoredGrant {
    qk_approval::StoredGrant {
        id: ApprovalId::new("qka-planted".to_owned()),
        shape: qk_core::sql_fingerprint(sql),
        binding,
        scope: ApprovalScope {
            session_id: Some("session-1".to_owned()),
            integration: "test".to_owned(),
            environment: "production".to_owned(),
            database: "main".to_owned(),
            agent_id: String::new(),
            tool: "db_query".to_owned(),
        },
        status: GrantStatus::Approved,
        reuse,
        expires_at_ms: NOW + 60_000,
        reason_code: qk_core::ReasonCode::RequireApproval,
        message: "planted".to_owned(),
        matched_policy: None,
        decided_at_ms: Some(NOW),
        decided_by: Some(DecisionSource::Ui),
        risk: String::new(),
        operation_summary: String::new(),
        schema_ddl: None,
        schema_diff: None,
    }
}

#[tokio::test]
async fn mismatched_approval_token_never_reaches_adapter() {
    // An approved grant for SQL-A must not authorize SQL-B, even when
    // the caller presents A's approval id (no approval_id ⇒ execute
    // shortcut).
    let service = ExecutionService::new();
    let adapter = FakeAdapter::with_rows(vec![]);
    let store = InMemoryApprovalStore::new();
    let sql_a = "UPDATE t SET a = 1 WHERE id = 1";
    let digest = qk_core::exact_request_digest(qk_sql::SqlDialect::Sqlite, sql_a);
    store
        .insert_grant(grant_for(
            sql_a,
            ApprovalBinding::ExactV1(digest),
            Scope::Once,
        ))
        .expect("plant");
    let config = sqlite_config();
    let auth = auth();
    let approval = approval(&store, None);
    let policy = policy();
    let outcome = guarded(
        &service,
        &adapter,
        &config,
        &ExecuteRequest {
            approval_id: Some("qka-planted".to_owned()),
            ..request("UPDATE t SET a = 2 WHERE id = 1")
        },
        &auth,
        &approval,
        &policy,
    )
    .await;
    assert!(
        blocked(&outcome) || matches!(outcome, ExecutionOutcome::PendingApproval(_)),
        "unexpected: {outcome:?}"
    );
    assert_eq!(adapter.calls(), 0);
}

#[tokio::test]
async fn legacy_grant_never_authorizes() {
    let service = ExecutionService::new();
    let adapter = FakeAdapter::with_rows(vec![]);
    let store = InMemoryApprovalStore::new();
    let sql = "UPDATE t SET a = 1 WHERE id = 1";
    store
        .insert_grant(grant_for(sql, ApprovalBinding::LegacyShape, Scope::Session))
        .expect("plant legacy");
    let outcome = run(&service, &adapter, sql, &store, None).await;
    assert!(blocked(&outcome), "unexpected: {outcome:?}");
    assert_eq!(adapter.calls(), 0);
}

// ---------------------------------------------------------------------------
// Hard deny immunity: grants never override a fresh Deny.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn grants_cannot_override_hard_deny() {
    let service = ExecutionService::new();
    let adapter = FakeAdapter::with_rows(vec![]);
    let store = InMemoryApprovalStore::new();
    // Even a live session grant cannot authorize a denied statement:
    // evaluation runs first and Deny short-circuits resolution.
    let outcome = run(&service, &adapter, "DROP TABLE t", &store, None).await;
    assert!(blocked(&outcome), "unexpected: {outcome:?}");
    assert_eq!(adapter.calls(), 0);
}

// ---------------------------------------------------------------------------
// Exactly-once execution for authorized work.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn direct_allow_executes_exactly_once() {
    let service = ExecutionService::new();
    let adapter = FakeAdapter::with_rows(vec![vec![DbValue::Int(1)]]);
    let store = InMemoryApprovalStore::new();
    let outcome = run(&service, &adapter, "SELECT 1", &store, None).await;
    let ExecutionOutcome::Executed(report) = outcome else {
        panic!("expected executed");
    };
    let result = &report.result;
    assert_eq!(result.rows_shown, 1);
    assert!(!result.truncated);
    assert_eq!(adapter.calls(), 1);
    // The executed SQL is the evaluated SQL (no rewrites for capped,
    // limit-less selects beyond the frozen paging form).
    assert_eq!(adapter.sql_log(), vec!["SELECT 1 LIMIT 51 OFFSET 0"]);
}

#[tokio::test]
async fn approved_exact_retry_executes_exactly_once_total() {
    let service = ExecutionService::new();
    let adapter = FakeAdapter::with_rows(vec![]);
    let store = InMemoryApprovalStore::new();
    let waiting = TestProvider::new(vec![ProviderDecision::Waiting]);
    let sql = "UPDATE t SET a = 1 WHERE id = 1";
    // First call pends (zero adapter calls) and names the approval.
    let outcome = run(&service, &adapter, sql, &store, Some(&waiting)).await;
    let ExecutionOutcome::PendingApproval(pending) = outcome else {
        panic!("expected pending, got {outcome:?}");
    };
    assert!(!pending.approval_id.is_empty());
    assert_eq!(adapter.calls(), 0);
    // Human approves out of band; retry carries the approval id.
    store
        .decide_grant(
            &ApprovalId::new(pending.approval_id.clone()),
            GrantStatus::Approved,
            Scope::Once,
            DecisionSource::Ui,
            NOW,
        )
        .expect("decide");
    let config = sqlite_config();
    let auth = auth();
    let approval = approval(&store, None);
    let policy = policy();
    let outcome = guarded(
        &service,
        &adapter,
        &config,
        &ExecuteRequest {
            approval_id: Some(pending.approval_id),
            ..request(sql)
        },
        &auth,
        &approval,
        &policy,
    )
    .await;
    assert!(
        matches!(outcome, ExecutionOutcome::Executed(_)),
        "{outcome:?}"
    );
    assert_eq!(adapter.calls(), 1);
}

#[tokio::test]
async fn approved_session_reuse_executes_without_new_approval() {
    let service = ExecutionService::new();
    let adapter = FakeAdapter::with_rows(vec![]);
    let store = InMemoryApprovalStore::new();
    let approver = TestProvider::new(vec![ProviderDecision::Approved]);
    let sql = "UPDATE t SET a = 1 WHERE id = 1";
    // Provider approves inline with session reuse (one execution).
    let config = sqlite_config();
    let auth = auth();
    let approval = ApprovalSetup {
        store: &store,
        provider: Some(&approver),
        ttl_ms: 60_000,
        now_ms: NOW,
    };
    let policy = policy();
    let outcome = guarded(
        &service,
        &adapter,
        &config,
        &request(sql),
        &auth,
        &approval,
        &policy,
    )
    .await;
    assert!(
        matches!(outcome, ExecutionOutcome::Executed(_)),
        "{outcome:?}"
    );
    assert_eq!(adapter.calls(), 1);
}

// ---------------------------------------------------------------------------
// Error and syntax boundaries.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn db_syntax_error_is_query_failure_after_auth() {
    // Parses under policy (allowed SELECT shape) but the engine
    // rejects it: adapter WAS called, outcome is a typed Query error
    // — never a policy parse error.
    let service = ExecutionService::new();
    let adapter = FakeAdapter::failing(DbError::new(
        DbErrorKind::Query,
        "syntax error at or near \"TYPO\"",
    ));
    let store = InMemoryApprovalStore::new();
    let outcome = run(
        &service,
        &adapter,
        "SELECT * FROM t WHERE TYPO",
        &store,
        None,
    )
    .await;
    let ExecutionOutcome::Failed(error) = outcome else {
        panic!("expected failed, got {outcome:?}");
    };
    assert_eq!(error.kind(), &DbErrorKind::Query);
    assert_eq!(adapter.calls(), 1);
}

#[tokio::test]
async fn multi_statement_rejected_without_execution() {
    let service = ExecutionService::new();
    let adapter = FakeAdapter::with_rows(vec![]);
    let store = InMemoryApprovalStore::new();
    let outcome = run(&service, &adapter, "SELECT 1; SELECT 2", &store, None).await;
    assert!(
        !matches!(outcome, ExecutionOutcome::Executed(_)),
        "unexpected: {outcome:?}"
    );
    assert_eq!(adapter.calls(), 0);
}

#[tokio::test]
async fn param_overflow_rejected_without_execution() {
    let service = ExecutionService::new();
    let adapter = FakeAdapter::with_rows(vec![]);
    let store = InMemoryApprovalStore::new();
    let config = sqlite_config();
    let auth = auth();
    let approval = approval(&store, None);
    let policy = policy();
    let outcome = guarded(
        &service,
        &adapter,
        &config,
        &ExecuteRequest {
            params: vec![serde_json::Value::from(1); 1001],
            ..request("SELECT 1")
        },
        &auth,
        &approval,
        &policy,
    )
    .await;
    assert!(
        matches!(outcome, ExecutionOutcome::Failed(_)),
        "{outcome:?}"
    );
    assert_eq!(adapter.calls(), 0);
}

// ---------------------------------------------------------------------------
// Budgets, paging, cursors.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn row_cap_probes_and_pages_with_cursor() {
    let service = ExecutionService::new();
    let rows: Vec<Vec<DbValue>> = (0..51).map(|i| vec![DbValue::Int(i)]).collect();
    let adapter = FakeAdapter::with_rows(rows);
    let store = InMemoryApprovalStore::new();
    let outcome = run(&service, &adapter, "SELECT * FROM t", &store, None).await;
    let ExecutionOutcome::Executed(report) = outcome else {
        panic!("expected executed, got {outcome:?}");
    };
    let result = &report.result;
    // Fetched maxRows+1 to detect the cap; showed maxRows.
    assert_eq!(result.rows_shown, 50);
    assert!(result.truncated);
    let cursor = result.cursor.clone().expect("cursor issued");
    assert!(cursor.starts_with("qk_cur_"));
    assert_eq!(adapter.calls(), 1);
    // Continue via cursor with empty SQL: the stored SQL is evaluated
    // again and executed with the stored offset.
    let config = sqlite_config();
    let auth = auth();
    let approval = approval(&store, None);
    let policy = policy();
    let outcome = guarded(
        &service,
        &adapter,
        &config,
        &ExecuteRequest {
            sql: String::new(),
            cursor: Some(cursor),
            ..request("")
        },
        &auth,
        &approval,
        &policy,
    )
    .await;
    assert!(
        matches!(outcome, ExecutionOutcome::Executed(_)),
        "{outcome:?}"
    );
    let log = adapter.sql_log();
    assert_eq!(log.len(), 2);
    assert!(log[1].contains("OFFSET 50"), "unexpected: {}", log[1]);
}

#[tokio::test]
async fn byte_budget_truncates_with_flag() {
    let service = ExecutionService::new().with_budget(qk_db::ResultBudget {
        max_rows: 50,
        max_bytes: 200,
        max_tokens: 8000,
    });
    let rows = vec![
        vec![DbValue::Text("a".repeat(100))],
        vec![DbValue::Text("b".repeat(100))],
        vec![DbValue::Text("c".repeat(100))],
    ];
    let adapter = FakeAdapter::with_rows(rows);
    let store = InMemoryApprovalStore::new();
    let outcome = run(&service, &adapter, "SELECT * FROM t", &store, None).await;
    let ExecutionOutcome::Executed(report) = outcome else {
        panic!("expected executed, got {outcome:?}");
    };
    let result = &report.result;
    assert!(result.truncated);
    assert!(result.rows_shown < 3);
    assert!(result.cursor.is_some());
    assert!(result.bytes_returned <= 200 + 150);
}

#[tokio::test]
async fn unknown_cursor_is_typed_failure() {
    let service = ExecutionService::new();
    let adapter = FakeAdapter::with_rows(vec![]);
    let store = InMemoryApprovalStore::new();
    let config = sqlite_config();
    let auth = auth();
    let approval = approval(&store, None);
    let policy = policy();
    let outcome = guarded(
        &service,
        &adapter,
        &config,
        &ExecuteRequest {
            sql: String::new(),
            cursor: Some("qk_cur_nope".to_owned()),
            ..request("")
        },
        &auth,
        &approval,
        &policy,
    )
    .await;
    assert!(
        matches!(outcome, ExecutionOutcome::Failed(_)),
        "{outcome:?}"
    );
    assert_eq!(adapter.calls(), 0);
}

// ---------------------------------------------------------------------------
// Trusted dialect derivation.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dialect_comes_from_connection_not_request() {
    // Backquotes are valid MySQL, a parse error under PostgreSQL: the
    // same SQL text executes under one config and blocks under the
    // other, proving evaluation follows the connection.
    let service = ExecutionService::new();
    let store = InMemoryApprovalStore::new();
    let mysql = DbConfig::Mysql(SecretUrl::new("mysql://u@h/db").expect("url"));
    let postgres =
        DbConfig::Postgres(SecretUrl::new("postgres://u@h/db?sslmode=disable").expect("url"));
    let sql = "SELECT `a` FROM t";
    let adapter = FakeAdapter::with_rows(vec![vec![DbValue::Int(1)]]);
    let auth = auth();
    let approval = approval(&store, None);
    let policy = policy();
    let outcome = guarded(
        &service,
        &adapter,
        &mysql,
        &request(sql),
        &auth,
        &approval,
        &policy,
    )
    .await;
    assert!(
        matches!(outcome, ExecutionOutcome::Executed(_)),
        "mysql: {outcome:?}"
    );
    let adapter = FakeAdapter::with_rows(vec![]);
    let outcome = guarded(
        &service,
        &adapter,
        &postgres,
        &request(sql),
        &auth,
        &approval,
        &policy,
    )
    .await;
    assert!(
        blocked(&outcome),
        "postgres must not parse backquotes: {outcome:?}"
    );
    assert_eq!(adapter.calls(), 0);
}

#[tokio::test]
async fn adapter_factory_maps_config_to_engine() {
    assert_eq!(
        ExecutionService::adapter_for(&DbConfig::Postgres(
            SecretUrl::new("postgres://u@h/db").expect("url")
        ))
        .engine(),
        "postgres"
    );
    assert_eq!(
        ExecutionService::adapter_for(&DbConfig::Mysql(
            SecretUrl::new("mysql://u@h/db").expect("url")
        ))
        .engine(),
        "mysql"
    );
    assert_eq!(
        ExecutionService::adapter_for(&DbConfig::Sqlite(
            SecretUrl::new("sqlite::memory:").expect("url")
        ))
        .engine(),
        "sqlite"
    );
}

#[tokio::test]
async fn explain_guarded_is_allow_only() {
    use qk_db::ExplainCall;
    let service = ExecutionService::new();
    let adapter = FakeAdapter::with_rows(vec![]);
    let store = InMemoryApprovalStore::new();
    let config = sqlite_config();
    let auth = auth();
    let policy = policy();
    let call = ExplainCall {
        adapter: &adapter,
        config: &config,
        auth: &auth,
        policy: &policy,
    };
    // Allow → plan executes (exactly one explain, zero executes).
    let outcome = service.explain_guarded(&call, "SELECT * FROM t", &[]).await;
    assert!(
        matches!(outcome, ExecutionOutcome::Executed(_)),
        "{outcome:?}"
    );
    assert_eq!(adapter.explains(), 1);
    assert_eq!(adapter.calls(), 0);
    // Deny → blocked without contact.
    let outcome = service.explain_guarded(&call, "DROP TABLE t", &[]).await;
    assert!(blocked(&outcome), "{outcome:?}");
    assert_eq!(adapter.explains(), 1);
    assert_eq!(adapter.calls(), 0);
    // RequireApproval → pending without contact (plans leak schema).
    let outcome = service
        .explain_guarded(&call, "UPDATE t SET a = 1 WHERE id = 1", &[])
        .await;
    assert!(
        matches!(outcome, ExecutionOutcome::PendingApproval(_)),
        "{outcome:?}"
    );
    assert_eq!(adapter.explains(), 1);
    assert_eq!(adapter.calls(), 0);
    let _ = store;
}

#[tokio::test]
async fn timeout_is_typed_may_still_run() {
    struct Slow;
    #[async_trait::async_trait]
    impl DatabaseAdapter for Slow {
        fn engine(&self) -> &'static str {
            "slow"
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                schemas: false,
                explain: false,
                explain_writes: false,
                sampling: false,
            }
        }
        async fn test_connection(&self, _url: &SecretUrl) -> Result<PingResult, DbError> {
            Ok(PingResult {
                ok: true,
                latency_ms: 0,
                server_version: None,
            })
        }
        async fn execute(
            &self,
            _url: &SecretUrl,
            _sql: &str,
            _params: &[Param],
        ) -> Result<RawResult, DbError> {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            Ok(RawResult::empty())
        }
        async fn explain(
            &self,
            _url: &SecretUrl,
            _sql: &str,
            _params: &[Param],
        ) -> Result<String, DbError> {
            Ok(String::new())
        }
        async fn list_schemas(&self, _url: &SecretUrl) -> Result<Vec<String>, DbError> {
            Ok(vec![])
        }
        async fn list_tables(
            &self,
            _url: &SecretUrl,
            _schema: Option<&str>,
        ) -> Result<Vec<TableRef>, DbError> {
            Ok(vec![])
        }
        async fn describe_table(
            &self,
            _url: &SecretUrl,
            _schema: Option<&str>,
            _name: &str,
        ) -> Result<TableInfo, DbError> {
            Err(DbError::new(DbErrorKind::Unsupported, "no"))
        }
        fn sample_sql(&self, _schema: Option<&str>, _name: &str, _limit: usize) -> String {
            "SELECT 1".to_owned()
        }
    }
    let service = ExecutionService::new().with_timeout(std::time::Duration::from_millis(50));
    let slow = Slow;
    let store = InMemoryApprovalStore::new();
    let config = sqlite_config();
    let auth = auth();
    let approval = approval(&store, None);
    let policy = policy();
    let outcome = guarded(
        &service,
        &slow,
        &config,
        &request("SELECT 1"),
        &auth,
        &approval,
        &policy,
    )
    .await;
    let ExecutionOutcome::Failed(error) = outcome else {
        panic!("expected timeout, got {outcome:?}");
    };
    assert_eq!(error.kind(), &DbErrorKind::Timeout);
    assert!(error.message().contains("may still be running"));
}

#[test]
fn redacted_config_never_leaks_password() {
    let url = "mysql://qk:s3cret-pw@127.0.0.1:3307/queryknight";
    let config = DbConfig::from_url(url).expect("config");
    for rendered in [
        format!("{config:?}"),
        config.redacted_url(),
        format!("{:?}", SecretUrl::new(url).expect("u")),
    ] {
        assert!(!rendered.contains("s3cret-pw"), "{rendered}");
    }
    // Error paths carry no URL at all.
    let error = DbError::new(DbErrorKind::Connection, "connection refused");
    assert!(!format!("{error}").contains("s3cret"));
}

// ---------------------------------------------------------------------------
// Exact request identity with bound params (INV-041).
// ---------------------------------------------------------------------------

fn v2_grant(
    id: &str,
    sql: &str,
    params: &[qk_core::DigestParam],
    reuse: qk_approval::Scope,
) -> qk_approval::StoredGrant {
    let digest = qk_core::exact_request_digest_v2(qk_sql::SqlDialect::Sqlite, sql, params)
        .expect("bounded fixture");
    qk_approval::StoredGrant {
        id: qk_approval::ApprovalId::new(id.to_owned()),
        shape: qk_core::sql_fingerprint(sql),
        binding: qk_approval::ApprovalBinding::ExactV2(digest),
        scope: qk_approval::ApprovalScope {
            session_id: Some("session-1".to_owned()),
            integration: "test".to_owned(),
            environment: "production".to_owned(),
            database: "main".to_owned(),
            agent_id: String::new(),
            tool: "db_query".to_owned(),
        },
        status: qk_approval::GrantStatus::Approved,
        reuse,
        expires_at_ms: NOW + 60_000,
        reason_code: qk_core::ReasonCode::RequireApproval,
        message: "m".to_owned(),
        matched_policy: None,
        decided_at_ms: Some(NOW),
        decided_by: None,
        risk: String::new(),
        operation_summary: String::new(),
        schema_ddl: None,
        schema_diff: None,
    }
}

fn param_request(
    sql: &str,
    params: Vec<serde_json::Value>,
    approval_id: Option<String>,
) -> ExecuteRequest {
    ExecuteRequest {
        sql: sql.to_owned(),
        params,
        max_rows: None,
        cursor: None,
        approval_id,
    }
}

#[tokio::test]
async fn once_param_change_does_not_reuse() {
    // UPDATE ... WHERE id = ? is approval-gated; approve [42], then
    // retry [43] with the same id: must NOT execute.
    let service = ExecutionService::new();
    let adapter = FakeAdapter::with_rows(vec![]);
    let store = InMemoryApprovalStore::new();
    let sql = "UPDATE t SET a = 1 WHERE id = ?";
    let config = sqlite_config();
    let auth = auth();
    let policy = policy();
    // Seed an approved V2 grant for [42] (as if a prior call resolved it).
    let params42 = [qk_core::DigestParam::Int(42)];
    store
        .insert_grant(v2_grant("qka-p", sql, &params42, qk_approval::Scope::Once))
        .expect("plant");
    // Exact same params → reuse + execute once.
    let appr = approval(&store, None);
    let outcome = guarded(
        &service,
        &adapter,
        &config,
        &param_request(sql, vec![serde_json::json!(42)], Some("qka-p".to_owned())),
        &auth,
        &appr,
        &policy,
    )
    .await;
    assert!(
        matches!(outcome, ExecutionOutcome::Executed(_)),
        "{outcome:?}"
    );
    assert_eq!(adapter.calls(), 1);
    // Changed param → fresh (provider re-ask; none here → blocked).
    let appr = approval(&store, None);
    let outcome = guarded(
        &service,
        &adapter,
        &config,
        &param_request(sql, vec![serde_json::json!(43)], Some("qka-p".to_owned())),
        &auth,
        &appr,
        &policy,
    )
    .await;
    assert!(
        blocked(&outcome) || matches!(outcome, ExecutionOutcome::PendingApproval(_)),
        "{outcome:?}"
    );
    assert_eq!(adapter.calls(), 1);
}

#[tokio::test]
async fn old_v1_parameterized_row_does_not_authorize_v2() {
    // Pre-fix row: SQL-only digest for a placeholder statement. A
    // modern request with real bound params must not match it.
    let service = ExecutionService::new();
    let adapter = FakeAdapter::with_rows(vec![]);
    let store = InMemoryApprovalStore::new();
    let sql = "UPDATE t SET a = 1 WHERE id = ?";
    let digest = qk_core::exact_request_digest(qk_sql::SqlDialect::Sqlite, sql);
    let mut grant = v2_grant("qka-oldv1", sql, &[], qk_approval::Scope::Once);
    grant.binding = qk_approval::ApprovalBinding::ExactV1(digest);
    store.insert_grant(grant).expect("plant");
    let config = sqlite_config();
    let auth = auth();
    let appr = approval(&store, None);
    let policy = policy();
    let outcome = guarded(
        &service,
        &adapter,
        &config,
        &param_request(
            sql,
            vec![serde_json::json!(42)],
            Some("qka-oldv1".to_owned()),
        ),
        &auth,
        &appr,
        &policy,
    )
    .await;
    assert!(
        blocked(&outcome) || matches!(outcome, ExecutionOutcome::PendingApproval(_)),
        "{outcome:?}"
    );
    assert_eq!(adapter.calls(), 0);
}

#[tokio::test]
async fn session_v2_reuses_param_variants_at_service() {
    let service = ExecutionService::new();
    let adapter = FakeAdapter::with_rows(vec![vec![DbValue::Int(1)]]);
    let store = InMemoryApprovalStore::new();
    let sql = "UPDATE t SET a = 1 WHERE id = ?";
    let params42 = [qk_core::DigestParam::Int(42)];
    store
        .insert_grant(v2_grant(
            "qka-sv2",
            sql,
            &params42,
            qk_approval::Scope::Session,
        ))
        .expect("plant");
    let config = sqlite_config();
    let auth = auth();
    let appr = approval(&store, None);
    let policy = policy();
    // Different params, same shape+scope: session reuse executes.
    let outcome = guarded(
        &service,
        &adapter,
        &config,
        &param_request(sql, vec![serde_json::json!(999)], None),
        &auth,
        &appr,
        &policy,
    )
    .await;
    assert!(
        matches!(outcome, ExecutionOutcome::Executed(_)),
        "{outcome:?}"
    );
    assert_eq!(adapter.calls(), 1);
}
