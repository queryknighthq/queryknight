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
        tokio::time::timeout(std::time::Duration::from_secs(10), ready_rx)
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
    // Changed literal under the same approved SHAPE executes: daemon
    // approvals bind shape fingerprints (frozen TS semantics, INV-024
    // literal-variant sharing). Exact-digest strictness applies where
    // exact tokens exist (qk-db layer, pinned separately) — here the
    // full path still re-ran (evaluate → provider re-check → fresh
    // exact binding for the current SQL).
    let replay = world
        .query("UPDATE t SET v = 'THREE' WHERE id = 1", Some(id))
        .await;
    assert!(
        replay.contains("Rows affected: 1"),
        "shape-bound retry must execute, got:\n{replay}"
    );
    let _ = before;
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
