use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use mysql_async::prelude::Queryable;
use mysql_async::{Conn, Opts};
use qk_control_plane::{ApprovalDecision, ControlPlaneClient};
use qk_db::DbConfig;
use qk_proxy_mysql::{ProxyConfig, ProxyServer};
use tokio::sync::oneshot;

#[path = "common/live_mysql_wire.rs"]
mod live_mysql_wire;
const LIVE_URL_DEFAULT: &str = "mysql://root:root@127.0.0.1:3306/qk";
const TABLE: &str = "qk_proxy_mysql_live";
const PREPARED_TABLE: &str = "qk_proxy_mysql_live_prepared";

const LIVE_POLICY: &str = r#"
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
          - operations: [select, insert, set, transaction]
        deny:
          - operations: [update, drop]
        approval_required:
          - operations: [delete]
"#;

struct RunningProxy {
    addr: std::net::SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<(), qk_proxy_mysql::ProxyError>>>,
}

impl RunningProxy {
    async fn start(url: &str, control_plane: ControlPlaneClient) -> Self {
        let db_config = DbConfig::from_url(url).expect("trusted MySQL URL");
        let connection_key = qk_mcp::config::connection_key_from_url(url);
        let policy = qk_core::parse_policy(LIVE_POLICY).expect("policy");
        let config = ProxyConfig::new(
            0,
            db_config,
            connection_key,
            "production".to_owned(),
            "main".to_owned(),
            policy,
            Some(control_plane),
        )
        .expect("proxy config");
        let proxy = ProxyServer::bind(config).await.expect("bind proxy");
        let addr = proxy.local_addr().expect("proxy address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            proxy
                .run_until(async move {
                    let _ = shutdown_rx.await;
                })
                .await
        });
        Self {
            addr,
            shutdown: Some(shutdown_tx),
            task: Some(task),
        }
    }

    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.await.expect("proxy task").expect("proxy stop");
        }
    }
}

async fn connect(url: &str) -> Conn {
    Conn::new(Opts::from_url(url).expect("MySQL options"))
        .await
        .expect("MySQL connection")
}

async fn connect_proxy(proxy: &RunningProxy, backend_url: &str) -> Conn {
    let options: Opts = mysql_async::OptsBuilder::from_opts(
        Opts::from_url(backend_url).expect("backend URL options"),
    )
    .ip_or_hostname("127.0.0.1")
    .tcp_port(proxy.addr.port())
    .into();
    Conn::new(options).await.expect("proxy client connection")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires MySQL 8.4 on 127.0.0.1:3306; set MYSQL_PROXY_TEST_URL to override"]
async fn mysql_84_live_proxy_contract() {
    let backend_url =
        std::env::var("MYSQL_PROXY_TEST_URL").unwrap_or_else(|_| LIVE_URL_DEFAULT.to_owned());
    let backend_opts = Opts::from_url(&backend_url).expect("backend MySQL options");
    let mut direct = connect(&backend_url).await;
    let version: Option<String> = direct
        .query_first("SELECT VERSION()")
        .await
        .expect("server version");
    assert!(
        version
            .as_deref()
            .is_some_and(|version| version.starts_with("8.4.")),
        "expected MySQL 8.4"
    );

    direct
        .query_drop(format!("DROP TABLE IF EXISTS {TABLE}"))
        .await
        .expect("drop prior fixture");
    direct
        .query_drop(format!("DROP TABLE IF EXISTS {PREPARED_TABLE}"))
        .await
        .expect("drop prior prepared fixture");
    direct
        .query_drop(format!(
            "CREATE TABLE {TABLE} (id INT PRIMARY KEY, value VARCHAR(64) NOT NULL)"
        ))
        .await
        .expect("create fixture");
    direct
        .query_drop(format!(
            "CREATE TABLE {PREPARED_TABLE} (id INT PRIMARY KEY, value VARCHAR(64) NOT NULL)"
        ))
        .await
        .expect("create prepared fixture");
    direct
        .exec_drop(
            format!("INSERT INTO {TABLE} (id, value) VALUES (?, ?), (?, ?), (?, ?), (?, ?)"),
            (1, "before", 2, "once", 3, "session", 4, "legacy"),
        )
        .await
        .expect("insert fixture");
    direct
        .exec_drop(
            format!(
                "INSERT INTO {PREPARED_TABLE} (id, value) VALUES (?, ?), (?, ?), (?, ?), (?, ?)"
            ),
            (
                7,
                "prepared-once",
                8,
                "prepared-session",
                9,
                "prepared-session-2",
                10,
                "other-session",
            ),
        )
        .await
        .expect("insert prepared fixture");

    let daemon = TestControlPlane::start().await;
    let proxy = RunningProxy::start(&backend_url, daemon.client.clone()).await;
    let mut client = connect_proxy(&proxy, &backend_url).await;
    let one: Option<u64> = client.query_first("SELECT 1").await.expect("SELECT 1");
    assert_eq!(one, Some(1));
    let prepared_select = client.prep("SELECT ?").await.expect("prepare SELECT");
    let selected: Option<u64> = client
        .exec_first(&prepared_select, (42u64,))
        .await
        .expect("binary prepared SELECT");
    assert_eq!(selected, Some(42));

    client
        .query_drop(format!(
            "INSERT INTO {TABLE} (id, value) VALUES (5, 'inserted')"
        ))
        .await
        .expect("permitted insert");
    let inserted: Option<String> = client
        .query_first(format!("SELECT value FROM {TABLE} WHERE id = 5"))
        .await
        .expect("read inserted row");
    assert_eq!(inserted.as_deref(), Some("inserted"));

    client
        .query_drop("SET @qk_proxy_session = 123")
        .await
        .expect("set variable");
    let variable: Option<u64> = client
        .query_first("SELECT @qk_proxy_session")
        .await
        .expect("read variable");
    assert_eq!(variable, Some(123));

    client
        .query_drop("START TRANSACTION")
        .await
        .expect("start transaction");
    assert!(client
        .query_drop(format!("UPDATE {TABLE} SET value = 'blocked' WHERE id = 1"))
        .await
        .is_err());
    let prepared_update = client
        .prep(format!("UPDATE {TABLE} SET value = ? WHERE id = ?"))
        .await
        .expect("prepare bounded UPDATE");
    assert!(client
        .exec_drop(&prepared_update, ("blocked".to_owned(), 1u64))
        .await
        .is_err());
    let unbounded_update = client
        .prep(format!("UPDATE {TABLE} SET value = ?"))
        .await
        .expect("prepare unbounded UPDATE");
    assert!(client
        .exec_drop(&unbounded_update, ("blocked".to_owned(),))
        .await
        .is_err());
    let in_transaction: Option<String> = client
        .query_first(format!("SELECT value FROM {TABLE} WHERE id = 1"))
        .await
        .expect("transaction continues after local block");
    assert_eq!(in_transaction.as_deref(), Some("before"));
    client
        .query_drop("COMMIT")
        .await
        .expect("commit after local block");
    let unchanged: Option<String> = direct
        .query_first(format!("SELECT value FROM {TABLE} WHERE id = 1"))
        .await
        .expect("independent direct verification");
    assert_eq!(unchanged.as_deref(), Some("before"));

    client
        .query_drop("START TRANSACTION")
        .await
        .expect("start rollback transaction");
    client
        .query_drop(format!(
            "INSERT INTO {TABLE} (id, value) VALUES (6, 'rolled-back')"
        ))
        .await
        .expect("insert inside transaction");
    client.query_drop("ROLLBACK").await.expect("rollback");
    let rolled_back: Option<String> = direct
        .query_first(format!("SELECT value FROM {TABLE} WHERE id = 6"))
        .await
        .expect("independent rollback verification");
    assert_eq!(rolled_back, None);
    let prepared_insert = client
        .prep(format!("INSERT INTO {TABLE} (id, value) VALUES (?, ?)"))
        .await
        .expect("prepare transactional INSERT");
    client
        .query_drop("START TRANSACTION")
        .await
        .expect("start prepared rollback transaction");
    client
        .exec_drop(&prepared_insert, (6u64, "prepared-rolled-back"))
        .await
        .expect("prepared insert in transaction");
    client
        .query_drop("ROLLBACK")
        .await
        .expect("rollback prepared row");
    let prepared_rolled_back: Option<String> = direct
        .query_first(format!("SELECT value FROM {TABLE} WHERE id = 6"))
        .await
        .expect("direct prepared rollback check");
    assert_eq!(prepared_rolled_back, None);
    client
        .exec_drop(&prepared_insert, (6u64, "prepared-committed"))
        .await
        .expect("same prepared statement after rollback");
    let prepared_committed: Option<String> = direct
        .query_first(format!("SELECT value FROM {TABLE} WHERE id = 6"))
        .await
        .expect("direct prepared commit check");
    assert_eq!(prepared_committed.as_deref(), Some("prepared-committed"));

    client
        .query_drop("SET autocommit = 0")
        .await
        .expect("disable autocommit");
    client
        .query_drop("SET @qk_proxy_session = 456")
        .await
        .expect("set with autocommit off");
    let variable: Option<u64> = client
        .query_first("SELECT @qk_proxy_session")
        .await
        .expect("read with autocommit off");
    assert_eq!(variable, Some(456));
    client
        .query_drop("COMMIT")
        .await
        .expect("commit autocommit-off work");
    client
        .query_drop("SET autocommit = 1")
        .await
        .expect("restore autocommit");

    let syntax = client
        .query_first::<String, _>(format!("SELECT missing_qk_live_column FROM {TABLE}"))
        .await;
    assert!(syntax.is_err(), "backend syntax error is relayed");
    assert!(client
        .query_drop(format!("SELECT 1; DROP TABLE {TABLE}"))
        .await
        .is_err());
    assert!(client
        .query_drop(format!(
            "LOAD DATA LOCAL INFILE '/tmp/qk-never-read' INTO TABLE {TABLE}"
        ))
        .await
        .is_err());
    assert!(
        client
            .prep(format!("SELECT missing_qk_live_column FROM {TABLE}"))
            .await
            .is_err(),
        "prepared syntax errors are relayed"
    );
    assert!(
        client
            .prep(format!("SELECT 1; DROP TABLE {TABLE}"))
            .await
            .is_err(),
        "multi-statement PREPARE remains unsupported"
    );

    // Once: exact SQL retry succeeds, changed literal cannot consume the grant.
    let once_sql = format!("DELETE FROM {TABLE} WHERE id = 2");
    assert!(client.query_drop(&once_sql).await.is_err());
    let pending = daemon.client.list_approvals().expect("Once pending");
    let once_id = pending
        .iter()
        .find(|approval| approval.status == qk_control_plane::ApprovalStatus::Waiting)
        .expect("waiting approval")
        .id
        .clone();
    daemon
        .client
        .decide_approval(
            &once_id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Once),
        )
        .expect("approve Once");
    client
        .query_drop(&once_sql)
        .await
        .expect("exact Once retry");
    assert!(client
        .query_drop(format!("DELETE FROM {TABLE} WHERE id = 7"))
        .await
        .is_err());

    // Session: same shape/new literal may obtain a fresh permit on this connection.
    let session_sql = format!("DELETE FROM {TABLE} WHERE id = 3");
    assert!(client.query_drop(&session_sql).await.is_err());
    let waiting = daemon
        .client
        .list_approvals()
        .expect("Session pending")
        .into_iter()
        .find(|approval| approval.status == qk_control_plane::ApprovalStatus::Waiting)
        .expect("waiting Session approval");
    daemon
        .client
        .decide_approval(
            &waiting.id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Session),
        )
        .expect("approve Session");
    client
        .query_drop(&session_sql)
        .await
        .expect("Session retry");
    client
        .query_drop(format!("DELETE FROM {TABLE} WHERE id = 5"))
        .await
        .expect("same-shape Session permit");
    assert!(client
        .query_drop("DELETE FROM other_qk_table WHERE id = 6")
        .await
        .is_err());

    // Prepared Once binds the SQL placeholder, type, and value into ExactV2.
    let mut prepared_client = connect_proxy(&proxy, &backend_url).await;
    let prepared_sql = format!("DELETE FROM {PREPARED_TABLE} WHERE id = ?");
    let prepared_fingerprint = qk_core::sql_fingerprint(&prepared_sql).as_str().to_owned();
    let prepared_delete = prepared_client
        .prep(&prepared_sql)
        .await
        .expect("prepare parameterized DELETE");
    assert!(prepared_client
        .exec_drop(&prepared_delete, (7u64,))
        .await
        .is_err());
    let direct_before: Option<String> = direct
        .query_first(format!("SELECT value FROM {PREPARED_TABLE} WHERE id = 7"))
        .await
        .expect("blocked prepared row remains");
    assert_eq!(direct_before.as_deref(), Some("prepared-once"));
    let prepared_once = daemon
        .client
        .list_approvals()
        .expect("prepared Once pending")
        .into_iter()
        .find(|approval| {
            approval.status == qk_control_plane::ApprovalStatus::Waiting
                && approval.fingerprint == prepared_fingerprint
        })
        .expect("approval for prepared placeholder SQL");
    daemon
        .client
        .decide_approval(
            &prepared_once.id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Once),
        )
        .expect("approve prepared Once");
    prepared_client
        .exec_drop(&prepared_delete, (7u64,))
        .await
        .expect("exact prepared Once retry");
    let once_deleted: Option<String> = direct
        .query_first(format!("SELECT value FROM {PREPARED_TABLE} WHERE id = 7"))
        .await
        .expect("verify prepared Once side effect");
    assert_eq!(once_deleted, None);

    assert!(prepared_client
        .exec_drop(&prepared_delete, (8u64,))
        .await
        .is_err());
    let changed_pending = daemon
        .client
        .list_approvals()
        .expect("changed prepared parameter pending")
        .into_iter()
        .find(|approval| {
            approval.status == qk_control_plane::ApprovalStatus::Waiting
                && approval.fingerprint == prepared_fingerprint
        })
        .expect("Once did not authorize changed prepared value");
    daemon
        .client
        .decide_approval(
            &changed_pending.id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Session),
        )
        .expect("approve prepared Session scope");
    prepared_client
        .exec_drop(&prepared_delete, (8u64,))
        .await
        .expect("prepared Session retry");
    prepared_client
        .exec_drop(&prepared_delete, (9u64,))
        .await
        .expect("prepared Session grants a fresh request-specific permit");
    for id in [8, 9] {
        let remaining: Option<String> = direct
            .query_first(format!(
                "SELECT value FROM {PREPARED_TABLE} WHERE id = {id}"
            ))
            .await
            .expect("verify prepared Session side effect");
        assert_eq!(remaining, None);
    }

    // A second live frontend receives an isolated backend session and approval scope.
    let mut other = connect_proxy(&proxy, &backend_url).await;
    let other_value: Option<Option<u64>> = other
        .query_first("SELECT @qk_proxy_session")
        .await
        .expect("other session variable");
    assert_eq!(other_value, Some(None));
    assert!(other
        .query_drop(format!("DELETE FROM {TABLE} WHERE id = 4"))
        .await
        .is_err());
    let other_prepared = other
        .prep(&prepared_sql)
        .await
        .expect("prepare in isolated frontend");
    assert!(other.exec_drop(&other_prepared, (10u64,)).await.is_err());
    let other_row: Option<String> = direct
        .query_first(format!("SELECT value FROM {PREPARED_TABLE} WHERE id = 10"))
        .await
        .expect("other frontend's prepared block has no side effect");
    assert_eq!(other_row.as_deref(), Some("other-session"));

    // LegacyShape rows are visible to the daemon but never produce a permit.
    let legacy_sql = format!("DELETE FROM {TABLE} WHERE id = 4");
    let store = qk_store::Store::open(&daemon.home.join("queryknight.db")).expect("daemon store");
    let known_sessions: std::collections::HashSet<String> = store
        .list_sessions()
        .expect("list existing sessions")
        .into_iter()
        .map(|session| session.id)
        .collect();
    let mut legacy_client = connect_proxy(&proxy, &backend_url).await;
    let legacy_session = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(session) = store
                .list_sessions()
                .expect("list sessions")
                .into_iter()
                .find(|session| !known_sessions.contains(&session.id))
            {
                break session;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("dedicated legacy-test session");
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64;
    store
        .insert_grant(
            &qk_approval::StoredGrant {
                id: qk_approval::ApprovalId::new("qka_live_legacy_mysql".to_owned()),
                shape: qk_core::sql_fingerprint(&legacy_sql),
                binding: qk_approval::ApprovalBinding::LegacyShape,
                scope: qk_approval::ApprovalScope {
                    session_id: Some(legacy_session.id),
                    integration: "proxy_mysql".to_owned(),
                    environment: "production".to_owned(),
                    database: "main".to_owned(),
                    agent_id: String::new(),
                    tool: "proxy_query".to_owned(),
                },
                status: qk_approval::GrantStatus::Approved,
                reuse: qk_approval::Scope::Session,
                expires_at_ms: now_ms + 60_000,
                reason_code: qk_core::ReasonCode::RequireApproval,
                message: "legacy test fixture".to_owned(),
                schema_ddl: None,
                schema_diff: None,
                risk: "high".to_owned(),
                operation_summary: "delete fixture row".to_owned(),
                matched_policy: None,
                decided_at_ms: Some(now_ms),
                decided_by: Some(qk_approval::DecisionSource::Ui),
            },
            now_ms,
        )
        .expect("insert legacy grant");
    assert!(legacy_client.query_drop(&legacy_sql).await.is_err());
    let legacy_prepared = legacy_client
        .prep(format!("DELETE FROM {TABLE} WHERE id = ?"))
        .await
        .expect("prepare LegacyShape SQL");
    assert!(legacy_client
        .exec_drop(&legacy_prepared, (4u64,))
        .await
        .is_err());
    let remaining: Option<String> = direct
        .query_first(format!("SELECT value FROM {TABLE} WHERE id = 4"))
        .await
        .expect("legacy row remains");
    assert_eq!(remaining.as_deref(), Some("legacy"));

    let mut raw = live_mysql_wire::RawMysqlClient::connect(&proxy, &backend_opts).await;
    let raw_statement = raw.prepare("SELECT ?").await;
    let secret = b"MYSQL_PREPARED_SECRET_8675309";
    raw.send_long_data(raw_statement, 0, &secret[..11]).await;
    raw.send_long_data(raw_statement, 0, &secret[11..]).await;
    assert_eq!(
        raw.execute_long_string(raw_statement).await,
        secret,
        "MySQL 8.4 receives the ordered accumulated long-data value"
    );
    let store = qk_store::Store::open(&daemon.home.join("queryknight.db")).expect("history store");
    let history = store.list_events(100).expect("query history");
    assert!(history
        .iter()
        .any(|event| event.sql.as_deref() == Some("SELECT ?")));
    assert!(!format!("{history:?}").contains("MYSQL_PREPARED_SECRET_8675309"));
    drop(raw);
    legacy_client
        .disconnect()
        .await
        .expect("disconnect legacy test client");
    other.disconnect().await.expect("disconnect second client");
    prepared_client
        .disconnect()
        .await
        .expect("disconnect prepared frontend");
    client.disconnect().await.expect("disconnect proxy client");
    proxy.stop().await;
    daemon.stop().await;
    direct
        .query_drop(format!("DROP TABLE {TABLE}"))
        .await
        .expect("cleanup fixture");
    direct
        .query_drop(format!("DROP TABLE {PREPARED_TABLE}"))
        .await
        .expect("cleanup prepared fixture");
    direct.disconnect().await.expect("disconnect direct client");
}

struct TestControlPlane {
    home: PathBuf,
    client: ControlPlaneClient,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), qk_daemon::runtime::RuntimeError>>,
}

impl TestControlPlane {
    async fn start() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let home = std::env::temp_dir().join(format!(
            "qk-proxy-mysql-live-daemon-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).expect("create isolated daemon home");
        let runtime = qk_daemon::runtime::DaemonRuntime::with_home(home.clone(), Some(0))
            .expect("daemon runtime");
        let (ready_tx, ready_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            qk_daemon::runtime::run_foreground(&runtime, Some(ready_tx), async move {
                let _ = shutdown_rx.await;
            })
            .await
        });
        tokio::time::timeout(Duration::from_secs(10), ready_rx)
            .await
            .expect("daemon ready timeout")
            .expect("daemon ready");
        let client = ControlPlaneClient::discover_with_url(Some(home.clone()), None)
            .expect("discover isolated daemon");
        Self {
            home,
            client,
            shutdown: Some(shutdown_tx),
            task,
        }
    }

    async fn stop(self) {
        if let Some(shutdown) = self.shutdown {
            let _ = shutdown.send(());
        }
        self.task
            .await
            .expect("daemon task")
            .expect("clean daemon stop");
        let _ = std::fs::remove_dir_all(self.home);
    }
}
