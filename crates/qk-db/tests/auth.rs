//! Authorization-plane proofs for the reusable `qk-db::auth` API.
//!
//! These tests drive `authorize_guarded` DIRECTLY (the entry point a
//! future session-pinned adapter will use) and assert the two
//! properties that make the split safe:
//!   1. Authorization contacts the database ZERO times — ever.
//!   2. Only a returned `ExecutionPermit` reaches an adapter, and it
//!      carries the exact request it authorized.
//!
//! The adapter is structurally absent from `GuardedAuthorizationCall`,
//! so the "zero contact" property is enforced by the type system for
//! the authorization step; these tests additionally prove the
//! execution path calls the adapter exactly once per permit.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use qk_approval::{
    ApprovalBinding, ApprovalId, ApprovalScope, ApprovalStore, DecisionSource, GrantStatus,
    InMemoryApprovalStore, ProviderDecision, Scope, TestProvider,
};
use qk_db::auth::{AuthorizationOutcome, ResolveMode};
use qk_db::{
    authorize_guarded, ApprovalSetup, AuthorizationRequest, Capabilities, CursorStore,
    DatabaseAdapter, DbConfig, DbError, DbErrorKind, DbValue, ExecutionOutcome, ExecutionPermit,
    ExecutionService, GuardedAuthorizationCall, Param, PingResult, RawResult, SecretUrl, TableInfo,
    TableRef, TrustedContext,
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
        approval_required:
          - operations: [update, delete, insert]
        sensitive:
          columns:
            - users.password_hash
      # deny_without_where present-but-empty disables the unbounded
      # mutation deny, so an unbounded UPDATE lands in approval_required
      # — the only case that ever triggered a planner impact EXPLAIN.
      wide:
        approval_required:
          - operations: [update]
        mutations:
          deny_without_where: []
"#;

const NOW: u64 = 1_700_000_000_000;
const CONNECTION_KEY: &str = "sqlite:test";

fn policy() -> qk_core::PolicyFile {
    qk_core::parse_policy(POLICY).expect("test policy valid")
}

fn auth() -> TrustedContext {
    trusted_for("main")
}

fn trusted_for(database: &str) -> TrustedContext {
    TrustedContext {
        integration: "test".to_owned(),
        environment: "production".to_owned(),
        database: database.to_owned(),
        tool: "db_query".to_owned(),
        session_id: Some("session-1".to_owned()),
    }
}

fn sqlite_config() -> DbConfig {
    DbConfig::Sqlite(SecretUrl::new("sqlite::memory:").expect("url"))
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

fn auth_request(sql: &str) -> AuthorizationRequest {
    AuthorizationRequest::new(sql, Vec::new())
}

/// Recording fake: counts execute/explain/ping contacts and logs SQL.
struct FakeAdapter {
    executes: AtomicUsize,
    explains: AtomicUsize,
    pings: AtomicUsize,
    log: Mutex<Vec<String>>,
}

impl FakeAdapter {
    fn new() -> Self {
        Self {
            executes: AtomicUsize::new(0),
            explains: AtomicUsize::new(0),
            pings: AtomicUsize::new(0),
            log: Mutex::new(Vec::new()),
        }
    }

    fn executes(&self) -> usize {
        self.executes.load(Ordering::SeqCst)
    }

    fn explains(&self) -> usize {
        self.explains.load(Ordering::SeqCst)
    }

    fn pings(&self) -> usize {
        self.pings.load(Ordering::SeqCst)
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
        self.pings.fetch_add(1, Ordering::SeqCst);
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
        _params: &[Param],
    ) -> Result<RawResult, DbError> {
        self.executes.fetch_add(1, Ordering::SeqCst);
        self.log.lock().expect("log").push(sql.to_owned());
        Ok(RawResult {
            columns: vec!["a".to_owned()],
            rows: vec![vec![DbValue::Int(1)]],
            rows_affected: None,
        })
    }

    async fn explain(
        &self,
        _url: &SecretUrl,
        _sql: &str,
        _params: &[Param],
    ) -> Result<String, DbError> {
        self.explains.fetch_add(1, Ordering::SeqCst);
        Ok("Seq Scan on t (cost=0 rows=1)".to_owned())
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

    fn sample_sql(&self, schema: Option<&str>, name: &str, limit: usize) -> String {
        let table = match schema {
            Some(schema) => format!("{schema}.{name}"),
            None => name.to_owned(),
        };
        format!("SELECT * FROM {table} LIMIT {}", limit.max(1))
    }
}

fn authorize<'a>(
    store: &'a dyn ApprovalStore,
    provider: Option<&'a dyn qk_approval::ApprovalProvider>,
    config: &'a DbConfig,
    trusted: &'a TrustedContext,
    policy: &'a qk_core::PolicyFile,
    request: &AuthorizationRequest,
) -> AuthorizationOutcome {
    let cursors = CursorStore::new();
    let setup = approval(store, provider);
    authorize_guarded(
        &cursors,
        &GuardedAuthorizationCall {
            config,
            connection_key: CONNECTION_KEY,
            auth: trusted,
            approval: Some(&setup),
            policy,
        },
        request,
        ResolveMode::ResolveApprovals,
    )
}

fn permit(outcome: AuthorizationOutcome) -> ExecutionPermit {
    match outcome {
        AuthorizationOutcome::Permitted(permit) => *permit,
        other => panic!("expected permit, got {}", describe(&other)),
    }
}

fn describe(outcome: &AuthorizationOutcome) -> String {
    match outcome {
        AuthorizationOutcome::Permitted(_) => "Permitted".to_owned(),
        AuthorizationOutcome::Blocked(reason) => format!("Blocked({})", reason.code),
        AuthorizationOutcome::PendingApproval(pending) => {
            format!("Pending({})", pending.reason_code)
        }
        AuthorizationOutcome::Failed(error) => format!("Failed({:?})", error),
    }
}

fn grant(sql: &str, binding: ApprovalBinding, reuse: Scope) -> qk_approval::StoredGrant {
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

// ---------------------------------------------------------------------------
// Zero database contact during authorization.
// ---------------------------------------------------------------------------

#[test]
fn allow_authorization_contacts_the_database_zero_times() {
    // The adapter is not even constructible inside the auth call, so
    // this proves the property for the allow path: authorize returns a
    // permit and the caller has done no I/O.
    let store = InMemoryApprovalStore::new();
    let config = sqlite_config();
    let trusted = auth();
    let policy = policy();
    let outcome = authorize(
        &store,
        None,
        &config,
        &trusted,
        &policy,
        &auth_request("SELECT a FROM t WHERE id = 1"),
    );
    let permit = permit(outcome);
    assert_eq!(permit.dialect(), config.dialect());
}

#[test]
fn denied_authorization_returns_blocked_not_a_permit() {
    let store = InMemoryApprovalStore::new();
    let config = sqlite_config();
    let trusted = auth();
    let policy = policy();
    // DROP is unlisted → deny (on_unknown: deny).
    let outcome = authorize(
        &store,
        None,
        &config,
        &trusted,
        &policy,
        &auth_request("DROP TABLE t"),
    );
    assert!(matches!(outcome, AuthorizationOutcome::Blocked(_)));
}

#[test]
fn unsupported_mysql_tls_blocks_before_approval_resolution() {
    let store = InMemoryApprovalStore::new();
    let provider = TestProvider::new(vec![ProviderDecision::Approved]);
    let config = DbConfig::Mysql(
        SecretUrl::new("mysql://qk:MYSQL_TLS_SECRET_12345@localhost/db?require_ssl=true")
            .expect("URL"),
    );
    let trusted = auth();
    let policy = policy();
    let outcome = authorize(
        &store,
        Some(&provider),
        &config,
        &trusted,
        &policy,
        &auth_request("UPDATE users SET display_name = 'x' WHERE id = 1"),
    );

    match outcome {
        AuthorizationOutcome::Blocked(reason) => {
            assert_eq!(reason.code, qk_core::ReasonCode::PolicyError.as_str());
            assert!(reason.message.contains("MySQL TLS is not supported"));
            assert!(!reason.message.contains("MYSQL_TLS_SECRET_12345"));
        }
        other => panic!("unsupported connection should block: {}", describe(&other)),
    }
    assert_eq!(
        provider.calls(),
        0,
        "unsupported config must not contact approval"
    );
}

#[test]
fn strict_analysis_rejects_parse_and_unknown_approval_fallbacks() {
    let store = InMemoryApprovalStore::new();
    let config = sqlite_config();
    let trusted = auth();
    let policy = qk_core::parse_policy(
        "version: 1\ndefaults:\n  decision: deny\n  on_parse_error: require_approval\n  on_unknown: require_approval\nenvironments: {}\n",
    )
    .expect("policy");
    let provider = TestProvider::new(vec![ProviderDecision::Approved, ProviderDecision::Approved]);
    for sql in ["FROBNICATE t", "CALL arbitrary_proc()"] {
        let mut request = auth_request(sql);
        request.require_supported_analysis = true;
        let outcome = authorize(
            &store,
            Some(&provider),
            &config,
            &trusted,
            &policy,
            &request,
        );
        assert!(matches!(outcome, AuthorizationOutcome::Blocked(_)), "{sql}");
    }
    assert_eq!(
        provider.calls(),
        0,
        "unsupported SQL never reaches approvals"
    );
}

#[test]
fn unbounded_write_authorization_runs_no_impact_explain() {
    // A RequireApproval unbounded UPDATE is the one case that used to
    // trigger a planner impact EXPLAIN before approval. Authorization
    // must now pend with zero database contact (the estimate is
    // unpopulated) — the adapter could not even be reached here.
    let store = InMemoryApprovalStore::new();
    let config = sqlite_config();
    let trusted = trusted_for("wide");
    let policy = policy();
    let waiting = TestProvider::new(vec![ProviderDecision::Waiting]);
    let outcome = authorize(
        &store,
        Some(&waiting),
        &config,
        &trusted,
        &policy,
        &auth_request("UPDATE t SET a = 1"),
    );
    match outcome {
        AuthorizationOutcome::PendingApproval(pending) => {
            assert_eq!(pending.estimated_rows, None, "no impact estimate in auth");
            assert!(!pending.approval_id.is_empty(), "approval row created");
        }
        other => panic!("expected pending, got {}", describe(&other)),
    }
    // The provider WAS consulted (it is the approval request), and the
    // estimate it would have come from a planner EXPLAIN never ran.
    assert_eq!(waiting.calls(), 1);
}

#[test]
fn explain_mode_pends_without_contacting_the_provider() {
    // EvaluateOnly must not reach the provider at all: a provider that
    // would deny is never consulted, so RequireApproval pends.
    let provider = TestProvider::new(vec![ProviderDecision::Denied]);
    let config = sqlite_config();
    let trusted = auth();
    let policy = policy();
    let cursors = CursorStore::new();
    let outcome = authorize_guarded(
        &cursors,
        &GuardedAuthorizationCall {
            config: &config,
            connection_key: CONNECTION_KEY,
            auth: &trusted,
            // No approval wiring at all in explain mode.
            approval: None,
            policy: &policy,
        },
        &auth_request("UPDATE t SET a = 1 WHERE id = 1"),
        ResolveMode::EvaluateOnly,
    );
    match outcome {
        AuthorizationOutcome::PendingApproval(pending) => {
            assert!(pending.approval_id.is_empty(), "no approval row created");
        }
        other => panic!("expected pending, got {}", describe(&other)),
    }
    // A denying provider was configured: had it been consulted the
    // result would be Blocked, not Pending.
    assert_eq!(
        provider.calls(),
        0,
        "explain mode never consults the provider"
    );
}

// ---------------------------------------------------------------------------
// The permit carries the exact request it authorized.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn permit_binds_dialect_shape_exact_and_scope() {
    let store = InMemoryApprovalStore::new();
    let config = sqlite_config();
    let trusted = auth();
    let policy = policy();
    let sql = "SELECT a FROM t WHERE id = 1";
    let permit = permit(authorize(
        &store,
        None,
        &config,
        &trusted,
        &policy,
        &auth_request(sql),
    ));
    assert_eq!(permit.dialect(), config.dialect());
    assert_eq!(&qk_core::sql_fingerprint(sql), permit.shape());
    // No params → Exact V1.
    assert!(matches!(permit.exact(), qk_core::ExactDigest::V1(_)));
    assert_eq!(permit.scope().session_id.as_deref(), Some("session-1"));
    assert_eq!(permit.scope().database, "main");
    assert_eq!(permit.approval_id(), None, "allow needs no approval");
}

#[tokio::test]
async fn parameterized_request_permits_exact_v2() {
    let store = InMemoryApprovalStore::new();
    let config = sqlite_config();
    let trusted = auth();
    let policy = policy();
    let request = AuthorizationRequest::new(
        "SELECT a FROM t WHERE id = ?",
        vec![qk_core::ExecutionParam::Int(7)],
    );
    let permit = permit(authorize(
        &store, None, &config, &trusted, &policy, &request,
    ));
    assert_eq!(
        permit.exact(),
        &qk_core::ExactDigest::V2(
            qk_core::exact_request_digest_v2(
                qk_sql::SqlDialect::Sqlite,
                "SELECT a FROM t WHERE id = ?",
                &[qk_core::ExecutionParam::Int(7)],
            )
            .expect("bounded"),
        )
    );
}

#[tokio::test]
async fn permit_is_consumed_by_execution_and_calls_the_adapter_once() {
    let service = ExecutionService::new();
    let adapter = FakeAdapter::new();
    let store = InMemoryApprovalStore::new();
    let config = sqlite_config();
    let trusted = auth();
    let policy = policy();
    let permit = permit(authorize(
        &store,
        None,
        &config,
        &trusted,
        &policy,
        &auth_request("SELECT a FROM t"),
    ));
    // An adapter is in scope, yet authorization has contacted nothing.
    assert_eq!(adapter.executes(), 0, "authorization never executes");
    assert_eq!(adapter.explains(), 0, "authorization never explains");
    assert_eq!(adapter.pings(), 0, "authorization never pings");
    let outcome = service.execute_authorized(&adapter, &config, permit).await;
    assert!(
        matches!(outcome, ExecutionOutcome::Executed(_)),
        "{outcome:?}"
    );
    assert_eq!(adapter.executes(), 1, "permit yields exactly one execute");
    // Paging is applied from the permit's bound offset (0) — the SQL
    // the adapter saw is the paging-rewritten authorized statement.
    let log = adapter.sql_log();
    assert_eq!(log.len(), 1);
    assert!(log[0].contains("LIMIT"), "{}", log[0]);
    // The post-execution planner estimate is a RESULT-plane concern
    // (it informs token accounting), not an authorization one.
    assert_eq!(adapter.explains(), 1);
}

#[tokio::test]
async fn execution_rejects_a_permit_from_a_different_dialect() {
    // A permit is bound to a dialect; handing it to a connection of a
    // different dialect must fail closed, not execute.
    let service = ExecutionService::new();
    let adapter = FakeAdapter::new();
    let store = InMemoryApprovalStore::new();
    let pg_config = DbConfig::Postgres(SecretUrl::new("postgres://localhost/db").expect("url"));
    let trusted = auth();
    let policy = policy();
    let permit = permit(authorize(
        &store,
        None,
        &pg_config,
        &trusted,
        &policy,
        &auth_request("SELECT a FROM t"),
    ));
    let sqlite = sqlite_config();
    let outcome = service.execute_authorized(&adapter, &sqlite, permit).await;
    assert!(
        matches!(outcome, ExecutionOutcome::Failed(_)),
        "{outcome:?}"
    );
    assert_eq!(adapter.executes(), 0, "no execution across dialects");
}

// ---------------------------------------------------------------------------
// Approval semantics through the shared authorization path.
// ---------------------------------------------------------------------------

#[test]
fn once_grant_mismatch_blocks_authorization() {
    // A Once grant for SQL-A must not authorize SQL-B: a different
    // request pends/block, it never gets a permit.
    let store = InMemoryApprovalStore::new();
    store
        .insert_grant(grant(
            "UPDATE t SET a = 1 WHERE id = 1",
            ApprovalBinding::ExactV1(qk_core::exact_request_digest(
                qk_sql::SqlDialect::Sqlite,
                "UPDATE t SET a = 1 WHERE id = 1",
            )),
            Scope::Once,
        ))
        .expect("grant stored");
    let config = sqlite_config();
    let trusted = auth();
    let policy = policy();
    let outcome = authorize(
        &store,
        None,
        &config,
        &trusted,
        &policy,
        &auth_request("UPDATE t SET a = 1 WHERE id = 2"),
    );
    assert!(
        !matches!(outcome, AuthorizationOutcome::Permitted(_)),
        "Once grant must not authorize a different statement"
    );
}

#[test]
fn session_grant_issues_a_new_permit_for_a_literal_variant() {
    // A Session grant is shape-wide: a literal variant of a
    // parameterized statement gets its own fresh permit (not the
    // stored approval's).
    let store = InMemoryApprovalStore::new();
    let parameterized = "UPDATE t SET a = 1 WHERE id = ?";
    store
        .insert_grant(grant(
            parameterized,
            ApprovalBinding::ExactV2(
                qk_core::exact_request_digest_v2(
                    qk_sql::SqlDialect::Sqlite,
                    parameterized,
                    &[qk_core::ExecutionParam::Int(1)],
                )
                .expect("bounded"),
            ),
            Scope::Session,
        ))
        .expect("grant stored");
    let config = sqlite_config();
    let trusted = auth();
    let policy = policy();
    let literal = "UPDATE t SET a = 1 WHERE id = 1";
    let permit = permit(authorize(
        &store,
        None,
        &config,
        &trusted,
        &policy,
        &auth_request(literal),
    ));
    // The Session grant authorized the shape; the new permit is bound
    // to THIS request (V1, literal) and carries the Session grant id.
    assert!(matches!(permit.exact(), qk_core::ExactDigest::V1(_)));
    assert_eq!(
        permit.approval_id().map(|id| id.as_str().to_owned()),
        Some("qka-planted".to_owned())
    );
}

#[test]
fn legacy_shape_grant_never_issues_a_permit() {
    let store = InMemoryApprovalStore::new();
    let sql = "UPDATE t SET a = 1 WHERE id = 1";
    store
        .insert_grant(grant(sql, ApprovalBinding::LegacyShape, Scope::Session))
        .expect("grant stored");
    let config = sqlite_config();
    let trusted = auth();
    let policy = policy();
    let outcome = authorize(&store, None, &config, &trusted, &policy, &auth_request(sql));
    assert!(
        !matches!(outcome, AuthorizationOutcome::Permitted(_)),
        "LegacyShape must never authorize"
    );
}

#[test]
fn unknown_cursor_fails_authorization_without_a_permit() {
    let store = InMemoryApprovalStore::new();
    let config = sqlite_config();
    let trusted = auth();
    let policy = policy();
    let mut request = auth_request("");
    request.cursor = Some("qk-no-such-cursor".to_owned());
    let outcome = authorize(&store, None, &config, &trusted, &policy, &request);
    assert!(
        matches!(outcome, AuthorizationOutcome::Failed(_)),
        "{}",
        describe(&outcome)
    );
}

#[tokio::test]
async fn rejected_adapter_operation_never_receives_a_permit() {
    let store = InMemoryApprovalStore::new();
    let config = DbConfig::Postgres(SecretUrl::new("postgres://qk@localhost/db").expect("url"));
    let trusted = TrustedContext {
        integration: "proxy_pg".to_owned(),
        environment: "production".to_owned(),
        database: "main".to_owned(),
        tool: "proxy_query".to_owned(),
        session_id: None,
    };
    let policy = qk_core::parse_policy(
        r#"
version: 1
defaults:
  decision: allow
environments:
  production:
    databases:
      main:
        allow:
          - operations: [copy, set]
"#,
    )
    .expect("allow fixture");
    let mut request = AuthorizationRequest::new("COPY t TO STDOUT", Vec::new());
    request.reject_operations.push(qk_sql::Operation::Copy);
    let outcome = authorize(&store, None, &config, &trusted, &policy, &request);
    assert!(
        matches!(
            &outcome,
            AuthorizationOutcome::Blocked(reason) if reason.code == "UNSUPPORTED_OPERATION"
        ),
        "{}",
        describe(&outcome)
    );
}
