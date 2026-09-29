//! SQLite-backed approval end to end: policy -> evaluate -> resolve with
//! a real `qk_store::Store` as the `ApprovalStore`, including close/reopen
//! persistence, session-shape reuse, scope rejection, and legacy reopen
//! quarantine. Rust-only infrastructure tests (no frozen expectations).

use qk_approval::{
    resolve, ApprovalProvider, ProviderDecision, ResolutionOutcome, ResolveRequest, TestProvider,
    DEFAULT_APPROVAL_TTL_MS,
};
use qk_core::{
    evaluate, parse_policy, Decision, EvaluateOptions, EvaluationRequest, ExecutionContext,
    PolicyFile, ReasonCode,
};

const POLICY: &str = "version: 1\ndefaults:\n  decision: deny\nenvironments:\n  production:\n    databases:\n      main:\n        allow:\n          - operations: [select]\n        approval_required:\n          - operations: [delete]\n";

const SQL: &str = "DELETE FROM customers WHERE id = 42";
const NOW: u64 = 1_000_000;

fn policy() -> PolicyFile {
    parse_policy(POLICY).expect("policy")
}

fn context() -> ExecutionContext {
    ExecutionContext {
        integration: "mcp".to_owned(),
        environment: "production".to_owned(),
        database: Some("main".to_owned()),
        agent_id: Some("agent-1".to_owned()),
        tool: Some("db_query".to_owned()),
        session_id: Some("session-1".to_owned()),
    }
}

fn evaluate_sql(context: &ExecutionContext, sql: &str) -> qk_core::EvaluationResult {
    let result = evaluate(
        &EvaluationRequest {
            context,
            dialect: qk_sql::SqlDialect::PostgreSql,
            sql,
            policy: &policy(),
        },
        &EvaluateOptions::default(),
    );
    assert_eq!(result.decision, Decision::RequireApproval);
    result
}

fn temp_db(name: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    std::env::temp_dir().join(format!(
        "qk-compat-sqlite-{}-{}-{name}.db",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ))
}

fn resolve_against(
    evaluation: &qk_core::EvaluationResult,
    context: &ExecutionContext,
    sql: &str,
    approval_id: Option<&str>,
    store: &dyn qk_approval::ApprovalStore,
    provider: Option<&dyn ApprovalProvider>,
) -> qk_approval::ResolvedEvaluation {
    resolve(
        &ResolveRequest {
            evaluation,
            context,
            dialect: qk_sql::SqlDialect::PostgreSql,
            sql,
            approval_id,
            ttl_ms: DEFAULT_APPROVAL_TTL_MS,
            now_ms: NOW,
        },
        store,
        provider,
    )
}

#[test]
fn sqlite_approval_end_to_end() {
    let path = temp_db("e2e");
    let evaluation = evaluate_sql(&context(), SQL);
    // First pass: provider approves, grant persists as ExactV1.
    let approved = TestProvider::with_prefix("e2e", vec![ProviderDecision::Approved]);
    let first = {
        let store = qk_store::Store::open(&path).expect("open");
        let resolved = resolve_against(&evaluation, &context(), SQL, None, &store, Some(&approved));
        assert_eq!(resolved.decision, Decision::Allow);
        assert_eq!(resolved.reason_code, ReasonCode::ApprovalGranted);
        assert_eq!(approved.calls(), 1);
        let id = resolved.approval_id.expect("id").to_string();
        let stored = store.get_grant(&id).expect("get").expect("row");
        assert_eq!(stored.status, qk_approval::GrantStatus::Approved);
        id
    };
    // Close and reopen: the persisted grant authorizes the retry with no
    // provider contact.
    {
        let store = qk_store::Store::open(&path).expect("reopen");
        let silent = TestProvider::with_prefix("silent", vec![ProviderDecision::Waiting]);
        let retried = resolve_against(
            &evaluation,
            &context(),
            SQL,
            Some(&first),
            &store,
            Some(&silent),
        );
        assert_eq!(retried.decision, Decision::Allow);
        assert_eq!(retried.outcome, ResolutionOutcome::ExistingGrant);
        assert_eq!(silent.calls(), 0, "persisted grant must not re-ask");
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn sqlite_session_shape_reuse() {
    let path = temp_db("session");
    let context = context();
    let evaluation = evaluate_sql(&context, SQL);
    let store = qk_store::Store::open(&path).expect("open");
    // Provider parks the request; a session-scoped human decision follows.
    let pending_provider = TestProvider::with_prefix("pend", vec![ProviderDecision::Waiting]);
    let pending = resolve_against(
        &evaluation,
        &context,
        SQL,
        None,
        &store,
        Some(&pending_provider),
    );
    let id = pending.approval_id.expect("pending id").to_string();
    store
        .decide_grant(
            id.as_str(),
            qk_approval::GrantStatus::Approved,
            qk_approval::Scope::Session,
            qk_approval::DecisionSource::Cli,
            NOW,
        )
        .expect("decide");
    // Literal variant, same shape and scope: reused without provider contact.
    let variant_sql = "DELETE FROM customers WHERE id = 43";
    let variant_eval = evaluate_sql(&context, variant_sql);
    let idle = TestProvider::with_prefix("idle", vec![ProviderDecision::Waiting]);
    let reused = resolve_against(
        &variant_eval,
        &context,
        variant_sql,
        None,
        &store,
        Some(&idle),
    );
    assert_eq!(reused.decision, Decision::Allow);
    assert_eq!(idle.calls(), 0);
    // Changed scope: no reuse.
    let mut other = context.clone();
    other.database = Some("other".to_owned());
    let other_eval = evaluate(
        &EvaluationRequest {
            context: &other,
            dialect: qk_sql::SqlDialect::PostgreSql,
            sql: variant_sql,
            policy: &policy(),
        },
        &EvaluateOptions::default(),
    );
    // Unknown database falls to default deny (not approval-gated at all).
    assert_eq!(other_eval.decision, Decision::Deny);
    let _ = std::fs::remove_file(&path);
}

/// Legacy database reopened through the adapter: migrated rows stay
/// historical and require reapproval through a fresh provider request.
#[test]
fn sqlite_legacy_reopen_requires_reapproval() {
    let path = temp_db("legacy-reopen");
    {
        let conn = rusqlite::Connection::open(&path).expect("raw");
        conn.execute_batch(
            "CREATE TABLE connections (id TEXT PRIMARY KEY, name TEXT NOT NULL, engine TEXT NOT NULL,
               environment TEXT NOT NULL DEFAULT 'unknown', source TEXT NOT NULL, database TEXT, host_label TEXT);
             CREATE TABLE sessions (id TEXT PRIMARY KEY, connection_id TEXT NOT NULL, agent TEXT,
               started_at INTEGER NOT NULL, ended_at INTEGER, source TEXT NOT NULL);
             CREATE TABLE query_events (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, connection_id TEXT NOT NULL,
               source TEXT NOT NULL, sql_fingerprint TEXT NOT NULL, sql TEXT, query_class TEXT NOT NULL,
               risk TEXT NOT NULL, decision TEXT NOT NULL, started_at INTEGER NOT NULL, duration_ms INTEGER,
               rows_returned INTEGER, rows_affected INTEGER, bytes_returned INTEGER,
               estimated_tokens_returned INTEGER, estimated_tokens_avoided INTEGER, error_code TEXT);
             CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE approvals (id TEXT PRIMARY KEY, session_id TEXT, connection_id TEXT,
               fingerprint TEXT NOT NULL, status TEXT NOT NULL, reason TEXT NOT NULL, risk TEXT NOT NULL,
               operation_summary TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
               decided_at INTEGER, decision_source TEXT, scope TEXT, schema_ddl TEXT, schema_diff TEXT);
             CREATE TABLE session_allows (session_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
               PRIMARY KEY (session_id, fingerprint));",
        )
        .expect("legacy ddl");
        let shape = qk_core::sql_fingerprint(SQL);
        conn.execute(
            "INSERT INTO approvals (id, session_id, fingerprint, status, reason, risk,
               operation_summary, created_at, expires_at, decided_at, decision_source, scope)
             VALUES ('qka_legacy', 'session-1', ?1, 'approved',
               'matched approval rule', 'high', 'delete customers', 1000, 9999999999999,
               2000, 'cli', 'session')",
            [shape.as_str()],
        )
        .expect("legacy row");
    }
    let context = context();
    let evaluation = evaluate_sql(&context, SQL);
    let store = qk_store::Store::open(&path).expect("migrate");
    // The legacy session-shape grant cannot authorize: reapproval required.
    let ask_again = TestProvider::with_prefix("reask", vec![ProviderDecision::Waiting]);
    let out = resolve_against(&evaluation, &context, SQL, None, &store, Some(&ask_again));
    assert_eq!(out.outcome, ResolutionOutcome::ProviderWaiting);
    assert_eq!(
        ask_again.calls(),
        1,
        "legacy row must force a fresh request"
    );
    // The legacy retry token is equally inert.
    let ask_again2 = TestProvider::with_prefix("reask2", vec![ProviderDecision::Waiting]);
    let out = resolve_against(
        &evaluation,
        &context,
        SQL,
        Some("qka_legacy"),
        &store,
        Some(&ask_again2),
    );
    assert_eq!(out.outcome, ResolutionOutcome::ProviderWaiting);
    assert_eq!(ask_again2.calls(), 1);
    let _ = std::fs::remove_file(&path);
}
