//! Proxy backend TLS negotiation.
//!
//! Proves the exact SSLRequest framing, that a `N` or malformed backend
//! response fails closed without forwarding a StartupMessage, and that
//! explicit plaintext mode sends no SSLRequest.

use std::time::Duration;

use qk_db::DbConfig;
use qk_proxy_postgres::protocol::encode_startup;
use qk_proxy_postgres::{ProxyConfig, ProxyServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Exact PostgreSQL SSLRequest wire bytes: length 8, code 80877103.
const SSL_REQUEST: [u8; 8] = [0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F];

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
"#;

fn proxy_config(port: u16, sslmode: &str) -> ProxyConfig {
    let url =
        format!("postgres://qk:BACKEND_URL_SECRET@127.0.0.1:{port}/queryknight?sslmode={sslmode}");
    let db_config = DbConfig::from_url(&url).expect("typed postgres URL");
    let policy = qk_core::parse_policy(POLICY).expect("test policy");
    let config = ProxyConfig::new(
        0,
        db_config,
        format!("postgres://qk@127.0.0.1:{port}/queryknight"),
        "production".to_owned(),
        "main".to_owned(),
        policy,
        None,
    )
    .expect("proxy config");
    assert!(!format!("{config:?}").contains("BACKEND_URL_SECRET"));
    config
}

async fn start_proxy(
    config: ProxyConfig,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), qk_proxy_postgres::ProxyError>>,
) {
    let proxy = ProxyServer::bind(config).await.expect("proxy bind");
    let addr = proxy.local_addr().expect("proxy address");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        proxy
            .run_until(async move {
                let _ = shutdown_rx.await;
            })
            .await
    });
    (addr, shutdown_tx, task)
}

/// A raw backend that records the first 8 bytes and then answers once.
async fn spawn_raw_backend(response: &[u8]) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let response = response.to_vec();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut first = [0u8; 8];
        stream.read_exact(&mut first).await.expect("first 8 bytes");
        let _ = stream.write_all(&response).await;
        first.to_vec()
    });
    (port, task)
}

/// Connect a frontend client and complete a plaintext startup handshake so
/// the proxy proceeds to open the backend session.
async fn frontend_startup(addr: std::net::SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.expect("frontend connect");
    let startup = encode_startup(&[
        ("user".to_owned(), "qk".to_owned()),
        ("database".to_owned(), "queryknight".to_owned()),
    ])
    .expect("startup");
    stream.write_all(&startup).await.expect("frontend startup");
    stream
}

async fn read_frontend_error(stream: &mut TcpStream) -> Vec<u8> {
    let mut buffer = vec![0u8; 512];
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer))
        .await
        .expect("frontend response")
        .expect("read");
    buffer.truncate(read);
    buffer
}

#[tokio::test]
async fn tls_required_sends_exact_sslrequest() {
    let (backend_port, backend) = spawn_raw_backend(b"N").await;
    let (addr, shutdown, task) = start_proxy(proxy_config(backend_port, "require")).await;
    let mut frontend = frontend_startup(addr).await;
    // The backend refuses TLS; the frontend gets a bounded FATAL error.
    let response = read_frontend_error(&mut frontend).await;
    assert!(response.starts_with(b"E"), "expected an ErrorResponse");
    let _ = shutdown.send(());
    let _ = task.await;
    assert_eq!(
        backend.await.expect("backend join"),
        SSL_REQUEST.to_vec(),
        "backend must receive the exact SSLRequest"
    );
}

#[tokio::test]
async fn tls_refusal_fails_closed_without_startup_forwarding() {
    let (backend_port, backend) = spawn_raw_backend(b"N").await;
    let (addr, shutdown, task) = start_proxy(proxy_config(backend_port, "require")).await;
    let mut frontend = frontend_startup(addr).await;
    let response = read_frontend_error(&mut frontend).await;
    // Exactly one backend packet (the SSLRequest) is received; the proxy
    // never forwards the StartupMessage after a refusal.
    let bytes = backend.await.expect("backend join");
    assert_eq!(bytes.len(), 8, "only the SSLRequest is sent");
    assert!(response.starts_with(b"E"));
    let _ = shutdown.send(());
    let _ = task.await;
}

#[tokio::test]
async fn malformed_ssl_response_fails_closed() {
    let (backend_port, backend) = spawn_raw_backend(b"X").await;
    let (addr, shutdown, task) = start_proxy(proxy_config(backend_port, "require")).await;
    let mut frontend = frontend_startup(addr).await;
    let response = read_frontend_error(&mut frontend).await;
    assert!(response.starts_with(b"E"));
    assert_eq!(backend.await.expect("backend join"), SSL_REQUEST.to_vec());
    let _ = shutdown.send(());
    let _ = task.await;
}

#[tokio::test]
async fn explicit_plaintext_sends_no_sslrequest() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend_port = listener.local_addr().expect("addr").port();
    let backend = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut first = [0u8; 8];
        let read = stream.read(&mut first).await.expect("first bytes");
        first[..read].to_vec()
    });
    let (addr, shutdown, task) = start_proxy(proxy_config(backend_port, "disable")).await;
    let _frontend = frontend_startup(addr).await;
    let first_bytes = backend.await.expect("backend join");
    assert_ne!(
        first_bytes,
        SSL_REQUEST.to_vec(),
        "plaintext mode must not send SSLRequest"
    );
    let _ = shutdown.send(());
    let _ = task.await;
}
