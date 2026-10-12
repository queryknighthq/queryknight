//! Live PostgreSQL verified-TLS matrix for the `qk-proxy-postgres` backend.
//!
//! Ignored by default. Run `scripts/test-postgres-tls.sh`, which provisions
//! an ephemeral PostgreSQL 17 TLS server and PKI and exports:
//!
//!   `QK_PG_TLS_URL`          trusted-CA URL (`…?sslmode=require`)
//!   `QK_PG_TLS_CA`           trusted CA bundle path
//!   `QK_PG_TLS_UNKNOWN_CA`   untrusted CA bundle path
//!
//! Proves TLS does not weaken authorization: an allowed SELECT reaches the
//! backend over verified TLS, a denied statement does not, and an
//! untrusted CA fails closed.

use std::path::PathBuf;
use std::time::Duration;

use qk_db::{DbConfig, PostgresTlsOptions};
use qk_proxy_postgres::{ProxyConfig, ProxyServer};
use tokio::sync::oneshot;
use tokio_postgres::{Client, Config as PgConfig, NoTls};

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
          - operations: [drop, update, delete, insert]
"#;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name} (run scripts/test-postgres-tls.sh)"))
}

struct RunningProxy {
    port: u16,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), qk_proxy_postgres::ProxyError>>,
}

impl RunningProxy {
    async fn start(backend_url: &str, ca: Option<PathBuf>) -> Self {
        let tls = PostgresTlsOptions { ca_path: ca };
        let db_config =
            DbConfig::from_url_with_tls(backend_url, tls).expect("typed PostgreSQL backend URL");
        let parsed: PgConfig = backend_url.parse().expect("backend URL");
        let user = parsed.get_user().expect("backend role");
        let database = parsed.get_dbname().expect("backend database");
        let host = match parsed.get_hosts().first().expect("backend host") {
            tokio_postgres::config::Host::Tcp(host) => host.clone(),
            other => panic!("live test requires a TCP backend host, got {other:?}"),
        };
        let port = parsed.get_ports().first().copied().unwrap_or(5432);
        let connection_key = format!("postgres://{user}@{host}:{port}/{database}");
        let policy = qk_core::parse_policy(POLICY).expect("test policy");
        let config = ProxyConfig::new(
            0,
            db_config,
            connection_key,
            "production".to_owned(),
            "main".to_owned(),
            policy,
            None,
        )
        .expect("proxy config");
        let proxy = ProxyServer::bind(config).await.expect("proxy bind");
        let port = proxy.local_addr().expect("proxy address").port();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            proxy
                .run_until(async move {
                    let _ = shutdown_rx.await;
                })
                .await
        });
        Self {
            port,
            shutdown: Some(shutdown_tx),
            task,
        }
    }

    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.task.await;
    }
}

/// Connect a plaintext frontend client through the proxy.
async fn frontend(backend_url: &str, port: u16) -> (Client, tokio::task::JoinHandle<()>) {
    let backend: PgConfig = backend_url.parse().expect("backend URL");
    let mut frontend = PgConfig::new();
    frontend.user(backend.get_user().expect("backend role"));
    if let Some(password) = backend.get_password() {
        frontend.password(password);
    }
    frontend.dbname(backend.get_dbname().expect("backend database"));
    frontend.host("127.0.0.1");
    frontend.port(port);
    frontend.ssl_mode(tokio_postgres::config::SslMode::Disable);
    let (client, connection) =
        tokio::time::timeout(Duration::from_secs(5), frontend.connect(NoTls))
            .await
            .expect("frontend connect timeout")
            .expect("frontend connects through the proxy");
    let handle = tokio::spawn(async move {
        let _ = connection.await;
    });
    (client, handle)
}

/// Connect a plaintext client to the TLS-enabled server (it also accepts
/// plaintext) for out-of-band verification.
async fn connect_plain(url: &str) -> Client {
    let config: PgConfig = url.parse().expect("admin URL");
    let (client, connection) = tokio::time::timeout(Duration::from_secs(5), config.connect(NoTls))
        .await
        .expect("admin connect timeout")
        .expect("admin connects");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}

#[tokio::test]
#[ignore = "needs the live PostgreSQL TLS server (scripts/test-postgres-tls.sh)"]
async fn trusted_ca_backend_allows_select() {
    let backend_url = env("QK_PG_TLS_URL");
    let proxy = RunningProxy::start(&backend_url, Some(PathBuf::from(env("QK_PG_TLS_CA")))).await;
    let (client, connection) = frontend(&backend_url, proxy.port).await;
    let row = client
        .query_one("SELECT 1", &[])
        .await
        .expect("allowed SELECT reaches the TLS backend");
    let value: i32 = row.get(0);
    assert_eq!(value, 1);
    drop(client);
    connection.abort();
    proxy.stop().await;
}

#[tokio::test]
#[ignore = "needs the live PostgreSQL TLS server (scripts/test-postgres-tls.sh)"]
async fn denied_sql_does_not_reach_backend() {
    let backend_url = env("QK_PG_TLS_URL");
    // Seed out of band so the proxy never sees the write.
    let admin = connect_plain(&env("QK_PG_TLS_ADMIN_URL")).await;
    admin
        .batch_execute(
            "DROP TABLE IF EXISTS qk_tls_probe;
             CREATE TABLE qk_tls_probe (id int primary key, note text);
             INSERT INTO qk_tls_probe VALUES (1, 'keep');",
        )
        .await
        .expect("seed probe table");

    let proxy = RunningProxy::start(&backend_url, Some(PathBuf::from(env("QK_PG_TLS_CA")))).await;
    let (client, connection) = frontend(&backend_url, proxy.port).await;
    let error = client
        .simple_query("DELETE FROM qk_tls_probe")
        .await
        .expect_err("denied SQL must be blocked by QueryKnight");
    let db_error = error
        .as_db_error()
        .expect("a policy block must be a PostgreSQL ErrorResponse");
    assert_eq!(
        db_error.code().code(),
        "42501",
        "policy block must use insufficient_privilege: {db_error:?}"
    );
    drop(client);
    connection.abort();
    proxy.stop().await;

    // Nothing reached the backend: the probe row must survive.
    let row = admin
        .query_one("SELECT note FROM qk_tls_probe WHERE id = 1", &[])
        .await
        .expect("probe row survives a blocked DELETE");
    assert_eq!(row.get::<_, String>(0), "keep");
    admin.batch_execute("DROP TABLE qk_tls_probe").await.ok();
}

#[tokio::test]
#[ignore = "needs the live PostgreSQL TLS server (scripts/test-postgres-tls.sh)"]
async fn unknown_ca_backend_fails_closed() {
    let backend_url = env("QK_PG_TLS_URL");
    let proxy = RunningProxy::start(
        &backend_url,
        Some(PathBuf::from(env("QK_PG_TLS_UNKNOWN_CA"))),
    )
    .await;
    // The proxy cannot complete the TLS handshake; the frontend connection
    // fails instead of silently downgrading to plaintext.
    let backend: PgConfig = backend_url.parse().expect("backend URL");
    let mut frontend = PgConfig::new();
    frontend.user(backend.get_user().expect("backend role"));
    if let Some(password) = backend.get_password() {
        frontend.password(password);
    }
    frontend.dbname(backend.get_dbname().expect("backend database"));
    frontend.host("127.0.0.1");
    frontend.port(proxy.port);
    frontend.ssl_mode(tokio_postgres::config::SslMode::Disable);
    let result = tokio::time::timeout(Duration::from_secs(5), frontend.connect(NoTls)).await;
    if let Ok(Ok((client, _connection))) = result {
        // The handshake may complete and the FATAL arrive on the first
        // statement; either way no plaintext backend session exists.
        let error = client
            .query_one("SELECT 1", &[])
            .await
            .expect_err("untrusted CA must not yield a working session");
        assert!(!format!("{error}").is_empty());
    }
    proxy.stop().await;
}
