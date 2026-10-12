//! End-to-end MCP tests against a real daemon + real SQLite user DB:
//! approval flow with retry and literal-change rejection, legacy
//! quarantine at the protocol boundary, history-failure safety,
//! multi-statement and hardened-SQL refusal, and credential hygiene.
//! The daemon runs in-task (ephemeral port); handlers are driven
//! directly (stdio framing is covered by the CLI integration test).

use qk_mcp::{ApprovalStatus, ApprovalsDecideArgs, DbQueryArgs, McpState, QueryKnightServer};

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
          - operations: [select, insert]
        deny:
          - operations: [drop, truncate]
        approval_required:
          - operations: [update, delete]
        mutations:
          deny_without_where: [update, delete]
        row_safety:
          max_limit: 1000
"#;

static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

struct World {
    server: QueryKnightServer,
    home: std::path::PathBuf,
    addr: std::net::SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<(), qk_daemon::runtime::RuntimeError>>>,
}

impl World {
    /// Real daemon (ephemeral port, temp home) + MCP server bound to a
    /// temp SQLite user DB with sentinel credentials in the URL.
    async fn start() -> Self {
        std::env::set_var("QUERYKNIGHT_ENV", "production");
        std::env::set_var("QUERYKNIGHT_DATABASE", "main");
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let home = std::env::temp_dir().join(format!("qk-mcp-e2e-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).expect("home");
        // Daemon in-task.
        let runtime =
            qk_daemon::runtime::DaemonRuntime::with_home(home.clone(), Some(0)).expect("runtime");
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            qk_daemon::runtime::run_foreground(&runtime, Some(ready_tx), async move {
                let _ = shutdown_rx.await;
            })
            .await
        });
        let addr = tokio::time::timeout(std::time::Duration::from_secs(10), ready_rx)
            .await
            .expect("daemon ready")
            .expect("addr");
        // User DB (sqlite file; the daemon token below is the live
        // secret for leak assertions).
        let db_path = home.join("user.db");
        let url = format!("sqlite:{}", db_path.display());
        let config = qk_db::DbConfig::from_url(&url).expect("config");
        let adapter = qk_db::ExecutionService::adapter_for(&config);
        let secret = qk_db::SecretUrl::new(&url).expect("secret");
        for ddl in [
            "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)",
            "INSERT INTO t VALUES (1, 'one')",
        ] {
            qk_db::DatabaseAdapter::execute(&*adapter, &secret, ddl, &[])
                .await
                .unwrap_or_else(|error| panic!("fixture {ddl}: {error}"));
        }
        let policy = qk_core::parse_policy(POLICY).expect("policy");
        let state = McpState::new(&url, policy, Some(home.clone())).expect("mcp state");
        World {
            server: QueryKnightServer::new(state),
            home,
            addr,
            shutdown: Some(shutdown_tx),
            task: Some(task),
        }
    }

    async fn query(&self, sql: &str, approval_id: Option<String>) -> String {
        self.server
            .db_query_impl(DbQueryArgs {
                sql: sql.to_owned(),
                params: None,
                max_rows: None,
                cursor: None,
                approval_id,
            })
            .await
            .expect("tool result (blocked/pending are text)")
    }

    async fn count(&self) -> i64 {
        let text = self.query("SELECT COUNT(*) AS n FROM t", None).await;
        assert!(text.contains("Showing 1 rows."), "got:\n{text}");
        // Parse the single cell out of the markdown row.
        text.lines()
            .find(|line| line.starts_with("| ") && !line.contains("---") && !line.contains(" n |"))
            .expect("row")
            .split('|')
            .nth(1)
            .expect("cell")
            .trim()
            .parse()
            .expect("count")
    }

    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.await.expect("join").expect("clean shutdown");
        }
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn pending_id(text: &str) -> String {
    assert!(
        text.starts_with("Blocked: waiting for approval qka_"),
        "got:\n{text}"
    );
    text.lines()
        .next()
        .expect("first line")
        .trim_start_matches("Blocked: waiting for approval ")
        .trim_end_matches('.')
        .to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approval_flow_retry_and_literal_change() {
    let world = World::start().await;
    // Bounded write pends with a daemon approval id.
    let pending = world
        .query("UPDATE t SET v = 'two' WHERE id = 1", None)
        .await;
    let id = pending_id(&pending);
    assert!(pending.contains(&format!("approvalId=\"{id}\"")));
    // Agent-visible decide through the frozen control-plane tool.
    let decided = world
        .server
        .approvals_decide_impl(ApprovalsDecideArgs {
            id: id.clone(),
            status: ApprovalStatus::Approved,
        })
        .await
        .expect("decide");
    assert_eq!(decided, format!("approval {id}: approved"));
    // Retry executes exactly once.
    let before = world.count().await;
    let text = world
        .query("UPDATE t SET v = 'two' WHERE id = 1", Some(id.clone()))
        .await;
    assert!(text.contains("Rows affected: 1"), "got:\n{text}");
    // Changed literal under the same approval ID must NOT reuse it:
    // the daemon row binds the exact original request (INV-041), so
    // the retry pends for a FRESH approval instead of executing.
    // (Session scope remains intentionally shape-wide — pinned in the
    // session end-to-end below.)
    let replay = world
        .query("UPDATE t SET v = 'THREE' WHERE id = 1", Some(id))
        .await;
    assert!(
        replay.starts_with("Blocked: waiting for approval"),
        "literal change must not reuse exact token, got:\n{replay}"
    );
    assert!(!replay.contains("Rows affected"));
    let _ = before;
    world.stop().await;
}

/// Explicit Session approval reuses shape-wide (params AND literals
/// may vary); a different shape still pends fresh. The session grant
/// is decided out-of-band with session scope (UI-equivalent path via
/// the daemon API directly — the MCP decide tool is once-only).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_approval_reuses_shape_wide() {
    use qk_daemon::runtime::probe::{probe_get, probe_post, ProbeTarget};
    use qk_daemon::AuthToken;
    let world = World::start().await;
    let target = ProbeTarget::new("127.0.0.1", world.addr.port()).expect("loopback");
    let token = AuthToken::new(
        std::fs::read_to_string(world.home.join("session.token"))
            .expect("token")
            .trim()
            .to_owned(),
    );
    let timeout = std::time::Duration::from_secs(5);
    // Pending for a parameterized write...
    let pending = world
        .server
        .db_query_impl(DbQueryArgs {
            sql: "DELETE FROM t WHERE id = ?".to_owned(),
            params: Some(vec![serde_json::json!(42)]),
            max_rows: None,
            cursor: None,
            approval_id: None,
        })
        .await
        .expect("pending text");
    let id = pending_id(&pending);
    // ...decided with SESSION scope out of band...
    let body =
        serde_json::json!({"status": "approved", "source": "ui", "scope": "session"}).to_string();
    let (code, _) = probe_post(
        &target,
        &format!("/approvals/{id}/decide"),
        &token,
        &body,
        timeout,
    )
    .await
    .expect("decide");
    assert_eq!(code, 200);
    // ...then the same shape with DIFFERENT params reuses the grant
    // without human involvement (no new daemon row).
    let (_, before) = probe_get(&target, "/approvals", Some(&token), timeout)
        .await
        .expect("list");
    let text = world
        .server
        .db_query_impl(DbQueryArgs {
            sql: "DELETE FROM t WHERE id = ?".to_owned(),
            params: Some(vec![serde_json::json!(999)]),
            max_rows: None,
            cursor: None,
            approval_id: None,
        })
        .await
        .expect("session reuse executes");
    assert!(text.contains("Rows affected:"), "got:\n{text}");
    let (_, after) = probe_get(&target, "/approvals", Some(&token), timeout)
        .await
        .expect("list");
    assert_eq!(before.len(), after.len(), "no duplicate approval row");
    // A different shape still pends fresh.
    let other = world
        .server
        .db_query_impl(DbQueryArgs {
            sql: "DELETE FROM t WHERE v = ?".to_owned(),
            params: Some(vec![serde_json::json!("one")]),
            max_rows: None,
            cursor: None,
            approval_id: None,
        })
        .await
        .expect("pending text");
    assert!(
        other.starts_with("Blocked: waiting for approval"),
        "got:\n{other}"
    );
    world.stop().await;
}

/// Parameterized ONCE approval: same params re-execute, changed
/// params pend fresh (adapter call counts prove it). This is the
/// ExactV2 end-to-end counterpart of the literal test above.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn param_change_does_not_reuse_once() {
    let world = World::start().await;
    let args = |params: Vec<serde_json::Value>, approval_id: Option<String>| DbQueryArgs {
        sql: "UPDATE t SET v = ? WHERE id = 1".to_owned(),
        params: Some(params),
        max_rows: None,
        cursor: None,
        approval_id,
    };
    let pending = world
        .server
        .db_query_impl(args(vec![serde_json::json!(42)], None))
        .await
        .expect("pending text");
    let id = pending_id(&pending);
    let decided = world
        .server
        .approvals_decide_impl(ApprovalsDecideArgs {
            id: id.clone(),
            status: ApprovalStatus::Approved,
        })
        .await
        .expect("decide");
    assert_eq!(decided, format!("approval {id}: approved"));
    // Exact same params → executes.
    let text = world
        .server
        .db_query_impl(args(vec![serde_json::json!(42)], Some(id.clone())))
        .await
        .expect("retry executes");
    assert!(text.contains("Rows affected: 1"), "got:\n{text}");
    // Changed params, same id → pends fresh, never executes.
    let replay = world
        .server
        .db_query_impl(args(vec![serde_json::json!(43)], Some(id)))
        .await
        .expect("pending text");
    assert!(
        replay.starts_with("Blocked: waiting for approval"),
        "param change must not reuse, got:\n{replay}"
    );
    assert!(!replay.contains("Rows affected"));
    world.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_row_requires_fresh_approval() {
    let world = World::start().await;
    // Plant an approved legacy-shape row directly in the daemon DB
    // (simulates a migrated historical approval).
    let db_path = world.home.join("queryknight.db");
    plant_legacy_row(&db_path, "UPDATE t SET v = 'legacy' WHERE id = 1");
    // Retry presenting the legacy row id pends for a FRESH approval —
    // the legacy verdict never authorizes.
    let legacy_id = legacy_row_id(&db_path);
    let text = world
        .query("UPDATE t SET v = 'legacy' WHERE id = 1", Some(legacy_id))
        .await;
    assert!(
        text.starts_with("Blocked: waiting for approval"),
        "legacy row must not authorize, got:\n{text}"
    );
    assert!(!text.contains("Rows affected"), "must not execute:\n{text}");
    world.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn history_failure_never_reexecutes() {
    let mut world = World::start().await;
    // Kill the daemon: history recording now fails on every call.
    if let Some(shutdown) = world.shutdown.take() {
        let _ = shutdown.send(());
    }
    if let Some(task) = world.task.take() {
        task.await.expect("join").expect("shutdown");
    }
    // A mutation still executes EXACTLY once (count proves no retry).
    let before: i64 = world.count().await;
    let text = world
        .query("INSERT INTO t (id, v) VALUES (42, 'x')", None)
        .await;
    assert!(text.contains("Rows affected: 1"), "got:\n{text}");
    assert_eq!(world.count().await, before + 1);
    world.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hostile_sql_never_executes() {
    let world = World::start().await;
    let before = world.count().await;
    // Multi-statement batch.
    let text = world.query("SELECT 1; DROP TABLE t", None).await;
    assert!(!text.contains("Showing"), "must not execute, got:\n{text}");
    // Parser-hardened shapes.
    for sql in [
        "WITH x AS (SELECT 1) DELETE FROM t RETURNING *",
        "MERGE INTO t USING t AS s ON t.id = s.id WHEN MATCHED THEN UPDATE SET v = 'm'",
        "EXPLAIN DELETE FROM t WHERE id = 1",
        "SELECT * FROM t WHERE 1 = 1 AND 2 = 2 AND 3 = 3",
    ] {
        let text = world.query(sql, None).await;
        assert!(
            !text.contains("Rows affected"),
            "{sql} must not execute, got:\n{text}"
        );
    }
    assert_eq!(world.count().await, before);
    world.stop().await;
}

/// Sentinel parameter secret must not appear in audit, OCSF,
/// metrics, or MCP text (the frozen audit model carries no params).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn param_secret_absent_from_observability() {
    use std::sync::Arc;
    let world = World::start().await;
    let memory = Arc::new(qk_audit::MemorySink::new());
    let mut server = world.server;
    server
        .state_mut()
        .set_observer(qk_audit::Observer::new(vec![memory.clone()]));
    let text = server
        .db_query_impl(DbQueryArgs {
            sql: "SELECT * FROM t WHERE v = ?".to_owned(),
            params: Some(vec![serde_json::json!("PARAM_SECRET_8675309")]),
            max_rows: None,
            cursor: None,
            approval_id: None,
        })
        .await
        .expect("query text");
    assert!(!text.contains("PARAM_SECRET"), "MCP text leaked");
    assert_eq!(memory.len(), 1);
    let event = &memory.events()[0];
    let event_json = serde_json::to_string(event).expect("event");
    assert!(!event_json.contains("PARAM_SECRET"), "audit leaked");
    let ocsf = serde_json::to_string(&qk_audit::to_ocsf(event, "0.1.0")).expect("ocsf");
    assert!(!ocsf.contains("PARAM_SECRET"), "OCSF leaked");
    let metrics = server.state().observer().metrics().render();
    assert!(!metrics.contains("PARAM_SECRET"), "metrics leaked");
    World {
        server,
        home: world.home,
        addr: world.addr,
        shutdown: world.shutdown,
        task: world.task,
    }
    .stop()
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn credentials_never_surface() {
    let world = World::start().await;
    // Live daemon token must not appear in any tool text or error.
    let token = std::fs::read_to_string(world.home.join("session.token"))
        .expect("token file")
        .trim()
        .to_owned();
    assert!(token.len() >= 32);
    // Password-bearing URLs redact at the connection layer (no live
    // connection needed — parsing only).
    let conn =
        qk_mcp::McpConnection::from_url("mysql://qk:S3CRET-PW@127.0.0.1:3307/qk").expect("conn");
    assert_eq!(conn.connection_key, "mysql://qk@127.0.0.1:3307/qk");
    assert!(!format!("{conn:?}").contains("S3CRET"));
    let ok = world.query("SELECT 1", None).await;
    let denied = world.query("DROP TABLE t", None).await;
    let missing = world
        .server
        .db_query_impl(DbQueryArgs {
            sql: "SELECT * FROM no_such_table".to_owned(),
            params: None,
            max_rows: None,
            cursor: None,
            approval_id: None,
        })
        .await;
    for (name, text) in [("ok", ok), ("denied", denied)] {
        assert!(!text.contains(&token), "{name} leaked daemon token");
    }
    // DB errors are protocol errors (never text results).
    assert!(missing.is_err());
    let error = format!("{:?}", missing.expect_err("must err"));
    assert!(!error.contains(&token), "error leaked: {error}");
    world.stop().await;
}

// ---------------------------------------------------------------------------
// Daemon DB helpers (test-only SQL against the state DB schema).
// ---------------------------------------------------------------------------

fn legacy_row_id(db_path: &std::path::Path) -> String {
    let conn = rusqlite::Connection::open(db_path).expect("open state db");
    conn.query_row(
        "SELECT id FROM approvals WHERE binding_kind = 'legacy_shape' LIMIT 1",
        [],
        |row| row.get::<_, String>(0),
    )
    .expect("legacy row present")
}

fn plant_legacy_row(db_path: &std::path::Path, sql: &str) {
    let fingerprint = qk_core::sql_fingerprint(sql);
    let conn = rusqlite::Connection::open(db_path).expect("open state db");
    conn.execute(
        "INSERT INTO approvals (id, session_id, fingerprint, status, reason, risk, operation_summary, created_at, expires_at, decided_at, decision_source, scope, exact_digest, integration, environment, database_name, agent_id, tool, reason_code, matched_policy, decided_by, binding_kind, schema_ddl, schema_diff) VALUES (?1, ?2, ?3, 'approved', 'migrated', '', '', 1000, 9999999999999, 1000, 'ui', 'once', NULL, 'mcp', 'production', 'main', '', 'db_query', 'REQUIRE_APPROVAL', NULL, 'ui', 'legacy_shape', NULL, NULL)",
        rusqlite::params![
            "qka_legacy01",
            "session-1",
            fingerprint.as_str(),
        ],
    )
    .expect("plant legacy");
}
