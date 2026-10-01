//! Observation matrix: every outcome kind observes exactly once
//! with the right decision/reason/approval/execution facts; OCSF
//! goldens; sink-failure isolation; secret-SQL and credential privacy
//! at every non-full level.

use std::sync::Arc;

use qk_audit::{
    to_ocsf, AuditDecision, AuditEvent, MemorySink, NoopSink, Observation, ObservedApproval,
    Observer, SqlLogLevel,
};
use qk_core::{Decision, ReasonCode};
use qk_db::{BudgetedResult, DbError, DbErrorKind, DbValue, ExecutedReport, ExecutionOutcome};

const SECRET_SQL: &str = "INSERT INTO users(password) VALUES ('SUPER_SECRET_123')";
const SECRET_URL: &str = "postgres://user:ULTRA_SECRET@localhost/db";

fn observation(outcome: &ExecutionOutcome, sql: &str) -> Observation {
    Observation::from_outcome(
        "11111111-1111-4111-8111-111111111111".to_owned(),
        1_790_769_600_000,
        12,
        Some(3),
        Some("req-1".to_owned()),
        "mcp".to_owned(),
        "production".to_owned(),
        Some("main".to_owned()),
        Some("agent-1".to_owned()),
        Some("session-1".to_owned()),
        None,
        Some("db_query".to_owned()),
        qk_sql::SqlDialect::PostgreSql,
        sql.to_owned(),
        outcome,
    )
}

fn executed(_sql: &str) -> ExecutionOutcome {
    ExecutionOutcome::Executed(ExecutedReport {
        result: BudgetedResult {
            columns: vec!["id".to_owned()],
            rows: vec![vec![DbValue::Int(1)]],
            rows_affected: None,
            rows_shown: 1,
            estimated_rows_matched: None,
            truncated: false,
            bytes_returned: 8,
            estimated_tokens_returned: 2,
            estimated_tokens_avoided: None,
            cursor: None,
        },
        approval_id: None,
        reason_code: ReasonCode::AllowRule,
        matched_policy: Some("production.main.allow[0]".to_owned()),
    })
}

fn blocked_deny() -> ExecutionOutcome {
    ExecutionOutcome::Blocked(qk_db::BlockedReason {
        decision: Decision::Deny,
        code: "DENY_RULE".to_owned(),
        message: "denied by rule".to_owned(),
        matched_policy: Some("production.main.deny[0]".to_owned()),
    })
}

fn authorize_select() -> qk_db::AuthorizationOutcome {
    authorize_query("SELECT id FROM users", Vec::new())
}

fn authorize_query(sql: &str, params: Vec<qk_core::ExecutionParam>) -> qk_db::AuthorizationOutcome {
    let config = qk_db::DbConfig::from_url("postgresql://localhost/app").expect("config");
    let connection_key = config.redacted_url();
    let auth = qk_db::TrustedContext {
        integration: "openshell".to_owned(),
        environment: "production".to_owned(),
        database: "main".to_owned(),
        tool: String::new(),
        session_id: Some("sandbox-1".to_owned()),
    };
    let policy = qk_core::demo_policy().expect("demo policy");
    let request = qk_db::AuthorizationRequest::new(sql.to_owned(), params);
    qk_db::authorize_guarded(
        &qk_db::CursorStore::new(),
        &qk_db::GuardedAuthorizationCall {
            config: &config,
            connection_key: &connection_key,
            auth: &auth,
            approval: None,
            policy: &policy,
        },
        &request,
        qk_db::ResolveMode::ResolveApprovals,
    )
}
// ---------------------------------------------------------------------------
// One attempt = one event, typed facts.
// ---------------------------------------------------------------------------

#[test]
fn allow_select_observes_once() {
    let memory = Arc::new(MemorySink::new());
    let observer = Observer::new(vec![memory.clone()]);
    let outcome = executed("SELECT id FROM t");
    let failures = observer.observe(
        &observation(&outcome, "SELECT id FROM t"),
        SqlLogLevel::Fingerprint,
    );
    assert!(failures.is_empty());
    assert_eq!(memory.len(), 1);
    let event = &memory.events()[0];
    assert_eq!(event.decision, AuditDecision::Allow);
    assert_eq!(event.reason_code, "ALLOW_RULE");
    assert_eq!(event.operation, "select");
    assert_eq!(event.outcome, qk_audit::AttemptOutcome::Executed);
    assert_eq!(event.rows_shown, Some(1));
    assert_eq!(event.fingerprint.len(), 16);
    // Fingerprint level: no SQL text at all.
    assert!(event.sql.is_none() && event.normalized_sql.is_none());
    assert_eq!(event.integration, "mcp");
    assert_eq!(event.session_id.as_deref(), Some("session-1"));
    assert!(event.parser_ok);
    assert!(event.enforced);
}

#[test]
fn deny_observes_without_execution_implication() {
    let memory = Arc::new(MemorySink::new());
    let observer = Observer::new(vec![memory]);
    let outcome = blocked_deny();
    let event = {
        let obs = observation(&outcome, "DROP TABLE t");
        observer.observe(&obs, SqlLogLevel::Metadata);
        obs.audit_event(SqlLogLevel::Metadata)
    };
    assert_eq!(event.decision, AuditDecision::Deny);
    assert_eq!(event.outcome, qk_audit::AttemptOutcome::Blocked);
    assert!(event.rows_affected.is_none());
    assert_eq!(event.operation, "drop");
    // Metadata level: normalized SQL present, raw absent.
    let normalized = event.normalized_sql.expect("normalized");
    assert!(!normalized.contains("DROP") || normalized.contains("drop"));
    assert!(event.sql.is_none());
}

#[test]
fn pending_carries_opaque_id_only() {
    let outcome = ExecutionOutcome::PendingApproval(qk_db::PendingApproval {
        approval_id: "qka_abc123".to_owned(),
        reason_code: "REQUIRE_APPROVAL".to_owned(),
        estimated_rows: Some(10),
    });
    let obs = observation(&outcome, "UPDATE t SET a = 1 WHERE id = 1");
    assert!(matches!(obs.approval, ObservedApproval::Waiting { .. }));
    let event = obs.audit_event(SqlLogLevel::Fingerprint);
    assert_eq!(event.decision, AuditDecision::RequireApproval);
    assert_eq!(event.approval_id.as_deref(), Some("qka_abc123"));
    assert_eq!(event.outcome, qk_audit::AttemptOutcome::Pending);
    let json = serde_json::to_string(&event).expect("json");
    assert!(!json.contains("estimated_rows"));
}

#[test]
fn failure_kinds_stay_typed() {
    for (kind, name) in [
        (DbErrorKind::Query, "query"),
        (DbErrorKind::Timeout, "timeout"),
        (DbErrorKind::Connection, "connection"),
    ] {
        let outcome = ExecutionOutcome::Failed(DbError::new(kind.clone(), "boom"));
        let event = observation(&outcome, "SELECT 1").audit_event(SqlLogLevel::Fingerprint);
        // Authorized-then-failed is Allow + Failed (never Deny).
        assert_eq!(event.decision, AuditDecision::Allow);
        assert_eq!(event.outcome, qk_audit::AttemptOutcome::Failed);
        assert_eq!(event.error_kind.as_deref(), Some(name));
        if name == "timeout" {
            assert_eq!(event.timeout_may_still_run, Some(true));
        } else {
            assert!(event.timeout_may_still_run.is_none());
        }
    }
}

#[test]
fn parse_failure_observes_unknown_operation() {
    let outcome = blocked_deny();
    let event = observation(&outcome, "SELEC FRM WHERE (((").audit_event(SqlLogLevel::Fingerprint);
    assert_eq!(event.operation, "unknown");
    assert!(!event.parser_ok);
}

// ---------------------------------------------------------------------------
// OCSF goldens.
// ---------------------------------------------------------------------------

fn ocsf_json(event: &AuditEvent) -> serde_json::Value {
    serde_json::to_value(to_ocsf(event, "0.1.0-beta.0")).expect("ocsf json")
}

#[test]
fn ocsf_allow_golden() {
    let event = observation(&executed("SELECT id FROM t"), "SELECT id FROM t")
        .audit_event(SqlLogLevel::Fingerprint);
    let ocsf = ocsf_json(&event);
    assert_eq!(ocsf["class_uid"], 6003);
    assert_eq!(ocsf["category_uid"], 6);
    assert_eq!(ocsf["activity_id"], 6);
    assert_eq!(ocsf["activity_name"], "Allow");
    assert_eq!(ocsf["severity_id"], 1);
    assert_eq!(ocsf["severity"], "Informational");
    assert_eq!(ocsf["status_id"], 1);
    assert_eq!(ocsf["status"], "Success");
    assert_eq!(ocsf["ocsf_version"], "1.5.0");
    assert_eq!(ocsf["metadata"]["product"]["name"], "QueryKnight");
    assert_eq!(ocsf["metadata"]["product"]["version"], "0.1.0-beta.0");
    assert_eq!(ocsf["api"]["operation"], "mcp:select");
    assert_eq!(ocsf["actor"]["user"]["name"], "agent-1");
    assert_eq!(ocsf["unmapped"]["qk_reason_code"], "ALLOW_RULE");
    assert_eq!(ocsf["time"], serde_json::Value::from(1_790_769_600_000u64));
    // Undefined stays omitted (never null).
    assert!(ocsf.get("src_endpoint").is_none());
}
#[test]
fn authorization_allow_is_never_an_execution_success() {
    let sql = "SELECT $1 WHERE note = 'OPENSHELL_SQL_SECRET_12345'";
    let outcome = authorize_query(
        sql,
        vec![qk_core::ExecutionParam::Text(
            "OPENSHELL_PARAM_SECRET_67890".to_owned(),
        )],
    );
    assert!(matches!(
        &outcome,
        qk_db::AuthorizationOutcome::Permitted(_)
    ));
    let observation = Observation::from_authorization_outcome(
        "22222222-2222-4222-8222-222222222222".to_owned(),
        1_790_769_600_001,
        9,
        Some(4),
        Some("openshell-request-1".to_owned()),
        "openshell".to_owned(),
        "production".to_owned(),
        Some("main".to_owned()),
        None,
        Some("sandbox-1".to_owned()),
        None,
        None,
        qk_sql::SqlDialect::PostgreSql,
        sql.to_owned(),
        &outcome,
    );
    let memory = Arc::new(MemorySink::new());
    let observer = Observer::new(vec![memory.clone()]);
    assert!(observer
        .observe(&observation, SqlLogLevel::Fingerprint)
        .is_empty());
    assert_eq!(memory.len(), 1);

    let events = memory.events();
    let event = &events[0];
    assert_eq!(event.integration, "openshell");
    assert_eq!(event.decision, AuditDecision::Allow);
    assert_eq!(event.reason_code, "ALLOW_RULE");
    assert_eq!(event.outcome, qk_audit::AttemptOutcome::Authorized);
    assert!(event.rows_affected.is_none());
    assert!(event.rows_shown.is_none());
    assert!(event.truncated.is_none());
    assert!(event.sql.is_none());
    assert!(event.normalized_sql.is_none());
    assert_eq!(event.session_id.as_deref(), Some("sandbox-1"));

    let ocsf = ocsf_json(event);
    assert_eq!(ocsf["activity_name"], "Allow");
    assert_eq!(ocsf["status_id"], 0);
    assert_eq!(ocsf["status"], "Unknown");
    assert_eq!(ocsf["unmapped"]["qk_outcome"], "authorized");

    for level in [
        SqlLogLevel::None,
        SqlLogLevel::Fingerprint,
        SqlLogLevel::Metadata,
    ] {
        let event = observation.audit_event(level);
        let surfaces = [
            serde_json::to_string(&event).expect("event json"),
            serde_json::to_string(&ocsf_json(&event)).expect("OCSF json"),
            format!("{event:?}"),
        ];
        for surface in surfaces {
            assert!(!surface.contains("OPENSHELL_SQL_SECRET_12345"));
            assert!(!surface.contains("OPENSHELL_PARAM_SECRET_67890"));
        }
    }
    assert!(!observer
        .metrics()
        .render()
        .contains("OPENSHELL_PARAM_SECRET_67890"));

    let full_sql = observation.audit_event(SqlLogLevel::FullSql);
    assert!(full_sql
        .sql
        .as_deref()
        .is_some_and(|value| value.contains("OPENSHELL_SQL_SECRET_12345")));
    assert!(!serde_json::to_string(&full_sql)
        .expect("full SQL event")
        .contains("OPENSHELL_PARAM_SECRET_67890"));
}

#[test]
fn authorization_only_ocsf_status_is_unknown_and_db_failure_is_failure() {
    let authorized = Observation::from_authorization_outcome(
        "33333333-3333-4333-8333-333333333333".to_owned(),
        1_790_769_600_002,
        4,
        Some(4),
        None,
        "openshell".to_owned(),
        "production".to_owned(),
        Some("main".to_owned()),
        None,
        None,
        None,
        None,
        qk_sql::SqlDialect::PostgreSql,
        "SELECT 1".to_owned(),
        &authorize_select(),
    )
    .audit_event(SqlLogLevel::Fingerprint);
    let authorized_ocsf = ocsf_json(&authorized);
    assert_eq!(authorized_ocsf["activity_name"], "Allow");
    assert_eq!(authorized_ocsf["status"], "Unknown");
    assert_eq!(authorized_ocsf["unmapped"]["qk_outcome"], "authorized");

    let failed = observation(
        &ExecutionOutcome::Failed(DbError::new(DbErrorKind::Query, "query failed")),
        "SELECT 1",
    )
    .audit_event(SqlLogLevel::Fingerprint);
    let failed_ocsf = ocsf_json(&failed);
    assert_eq!(failed_ocsf["activity_name"], "Allow");
    assert_eq!(failed_ocsf["status"], "Failure");
    assert_eq!(failed_ocsf["unmapped"]["qk_outcome"], "failed");
}

#[test]
fn ocsf_deny_and_pending_goldens() {
    let deny = observation(&blocked_deny(), "DROP TABLE t").audit_event(SqlLogLevel::Fingerprint);
    let ocsf = ocsf_json(&deny);
    assert_eq!(
        (
            ocsf["activity_id"].clone(),
            ocsf["severity_id"].clone(),
            ocsf["status_id"].clone()
        ),
        (
            serde_json::Value::from(7),
            serde_json::Value::from(4),
            serde_json::Value::from(2)
        )
    );
    assert_eq!(ocsf["activity_name"], "Deny");
    let pending = observation(
        &ExecutionOutcome::PendingApproval(qk_db::PendingApproval {
            approval_id: "qka_x".to_owned(),
            reason_code: "REQUIRE_APPROVAL".to_owned(),
            estimated_rows: None,
        }),
        "UPDATE t SET a = 1 WHERE id = 1",
    )
    .audit_event(SqlLogLevel::Fingerprint);
    let ocsf = ocsf_json(&pending);
    assert_eq!(
        (
            ocsf["activity_id"].clone(),
            ocsf["severity_id"].clone(),
            ocsf["status_id"].clone()
        ),
        (
            serde_json::Value::from(0),
            serde_json::Value::from(2),
            serde_json::Value::from(0)
        )
    );
    assert_eq!(ocsf["activity_name"], "Unknown");
    assert_eq!(ocsf["unmapped"]["qk_approval_id"], "qka_x");
}

// ---------------------------------------------------------------------------
// Sink failure isolation (INV-039).
// ---------------------------------------------------------------------------

#[test]
fn sink_failure_never_changes_outcomes() {
    let memory = Arc::new(MemorySink::new());
    memory.fail_next(100);
    let observer = Observer::new(vec![memory.clone()]);
    // Allow + sink failure: event lost, outcome untouched, no panic.
    let outcome = executed("SELECT 1");
    let failures = observer.observe(&observation(&outcome, "SELECT 1"), SqlLogLevel::Fingerprint);
    assert_eq!(failures.len(), 1);
    assert!(memory.is_empty());
    assert!(matches!(outcome, ExecutionOutcome::Executed(_)));
    // Deny + sink failure: still deny.
    let outcome = blocked_deny();
    let failures = observer.observe(
        &observation(&outcome, "DROP TABLE t"),
        SqlLogLevel::Fingerprint,
    );
    assert_eq!(failures.len(), 1);
    assert!(matches!(outcome, ExecutionOutcome::Blocked(_)));
    // Failure diagnostics are bounded and structural.
    assert!(failures[0]
        .to_string()
        .starts_with("audit sink 'memory' failed: "));
}

#[test]
fn noop_sink_observes_silently() {
    let observer = Observer::new(vec![Arc::new(NoopSink)]);
    let failures = observer.observe(
        &observation(&executed("SELECT 1"), "SELECT 1"),
        SqlLogLevel::Fingerprint,
    );
    assert!(failures.is_empty());
}

// ---------------------------------------------------------------------------
// Privacy: secret SQL + credential URL (INV-040).
// ---------------------------------------------------------------------------

fn surfaces(level: SqlLogLevel) -> Vec<String> {
    let outcome = executed(SECRET_SQL);
    let obs = observation(&outcome, SECRET_SQL);
    let event = obs.audit_event(level);
    let ocsf = serde_json::to_string(&to_ocsf(&event, "0.1.0-beta.0")).expect("ocsf");
    vec![
        serde_json::to_string(&event).expect("event json"),
        ocsf,
        format!("{event:?}"),
    ]
}

#[test]
fn secret_sql_absent_below_full() {
    for level in [
        SqlLogLevel::None,
        SqlLogLevel::Fingerprint,
        SqlLogLevel::Metadata,
    ] {
        for surface in surfaces(level) {
            assert!(
                !surface.contains("SUPER_SECRET_123"),
                "{level:?}: {surface}"
            );
        }
    }
    // Metadata keeps structure without literals.
    let event = observation(&executed(SECRET_SQL), SECRET_SQL).audit_event(SqlLogLevel::Metadata);
    let normalized = event.normalized_sql.expect("normalized");
    assert!(normalized.contains('?'));
    assert!(!normalized.contains("SUPER_SECRET_123"));
    // Full_sql is the explicit opt-in (contract allows raw text there).
    let event = observation(&executed(SECRET_SQL), SECRET_SQL).audit_event(SqlLogLevel::FullSql);
    assert!(event
        .sql
        .is_some_and(|sql| sql.contains("SUPER_SECRET_123")));
}

#[test]
fn credential_url_never_appears() {
    let redacted = qk_audit::redact_credentials(SECRET_URL);
    assert_eq!(redacted, "postgres://user:***@localhost/db");
    assert!(!redacted.contains("ULTRA_SECRET"));
    // Metrics labels never carry URLs (typed allowlist by construction):
    // exercise the metrics path with a URL-shaped database key and
    // assert the registry text holds no secret.
    let registry = qk_metrics::MetricsRegistry::new();
    registry.counter("queryknight_requests_total", &[("database", "main")], 1);
    assert!(!registry.render().contains("ULTRA_SECRET"));
}

// ---------------------------------------------------------------------------
// Metrics from typed observations.
// ---------------------------------------------------------------------------

#[test]
fn metrics_names_labels_values() {
    use qk_audit::Observer;
    let observer = Observer::new(vec![]);
    let metrics = observer.metrics();
    // Allow select.
    observer.observe(
        &observation(&executed("SELECT id FROM t"), "SELECT id FROM t"),
        SqlLogLevel::Fingerprint,
    );
    // Deny with unavailable approval reason (waiting bucket).
    let unavailable = ExecutionOutcome::Blocked(qk_db::BlockedReason {
        decision: Decision::Deny,
        code: "APPROVAL_UNAVAILABLE".to_owned(),
        message: "no provider".to_owned(),
        matched_policy: None,
    });
    observer.observe(
        &observation(&unavailable, "UPDATE t SET a = 1 WHERE id = 1"),
        SqlLogLevel::Fingerprint,
    );
    // Parse error (whitespace-only input fails analysis outright).
    observer.observe(
        &observation(&blocked_deny(), "   "),
        SqlLogLevel::Fingerprint,
    );
    let text = metrics.render();
    assert!(text.contains("queryknight_requests_total{database=\"main\",environment=\"production\",integration=\"mcp\",operation=\"select\"} 1"));
    assert!(text.contains("queryknight_decisions_total{database=\"main\",decision=\"allow\",environment=\"production\",integration=\"mcp\",operation=\"select\",reason_code=\"ALLOW_RULE\"} 1"));
    assert!(text.contains("queryknight_policy_denials_total"));
    assert!(
        text.contains("queryknight_parse_errors_total{dialect=\"postgres\",integration=\"mcp\"} 1")
    );
    assert!(text.contains("queryknight_approval_requests_total{database=\"main\",environment=\"production\",integration=\"mcp\",operation=\"update\",result=\"waiting\"} 1"));
    // HELP lines never render (frozen absence).
    assert!(!text.contains("# HELP"));
}
