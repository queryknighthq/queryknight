use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use mysql_async::prelude::Queryable;
use mysql_async::{Conn, Opts};
use qk_control_plane::{ApprovalDecision, ControlPlaneClient};
use qk_db::DbConfig;
use qk_proxy_mysql::{ProxyConfig, ProxyServer};
use tokio::sync::oneshot;

const LIVE_URL_DEFAULT: &str = "mysql://root:root@127.0.0.1:3306/qk";
const TABLE: &str = "qk_proxy_mysql_live";

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
        .query_drop(format!(
            "CREATE TABLE {TABLE} (id INT PRIMARY KEY, value VARCHAR(64) NOT NULL)"
        ))
        .await
        .expect("create fixture");
    direct
        .exec_drop(
            format!("INSERT INTO {TABLE} (id, value) VALUES (?, ?), (?, ?), (?, ?), (?, ?)"),
            (1, "before", 2, "once", 3, "session", 4, "legacy"),
        )
        .await
        .expect("insert fixture");

    let daemon = TestControlPlane::start().await;
    let proxy = RunningProxy::start(&backend_url, daemon.client.clone()).await;
    let mut client = connect_proxy(&proxy, &backend_url).await;
    let one: Option<u64> = client.query_first("SELECT 1").await.expect("SELECT 1");
    assert_eq!(one, Some(1));

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
        client.prep("SELECT ?").await.is_err(),
        "prepared protocol remains unsupported"
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
    let remaining: Option<String> = direct
        .query_first(format!("SELECT value FROM {TABLE} WHERE id = 4"))
        .await
        .expect("legacy row remains");
    assert_eq!(remaining.as_deref(), Some("legacy"));

    legacy_client
        .disconnect()
        .await
        .expect("disconnect legacy test client");
    other.disconnect().await.expect("disconnect second client");
    client.disconnect().await.expect("disconnect proxy client");
    proxy.stop().await;
    daemon.stop().await;
    direct
        .query_drop(format!("DROP TABLE {TABLE}"))
        .await
        .expect("cleanup fixture");
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
