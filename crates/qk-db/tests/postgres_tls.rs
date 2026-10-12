//! Direct qk-db PostgreSQL transport-mode tests.
//!
//! Covers the modes that do not need a live TLS server: non-verifying
//! modes are rejected before any network activity, explicit plaintext
//! stays plaintext, and a verified-TLS connection sends the exact
//! PostgreSQL SSLRequest and fails closed when the backend refuses TLS.
//!
//! The full trusted-CA / unknown-CA / hostname-mismatch matrix runs
//! against a live PostgreSQL 17 TLS server in `scripts/test-postgres-tls.sh`.

use std::io::ErrorKind;
use std::net::TcpListener as StdTcpListener;
use std::time::Duration;

use qk_db::adapters::postgres::PostgresAdapter;
use qk_db::{DatabaseAdapter, DbErrorKind, SecretUrl};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// PostgreSQL SSLRequest wire bytes: length 8, code 80877103.
const SSL_REQUEST: [u8; 8] = [0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F];

#[tokio::test]
async fn non_verifying_ssl_modes_fail_before_network() {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let port = listener.local_addr().expect("listener address").port();
    let adapter = PostgresAdapter;

    for suffix in ["", "?sslmode=prefer"] {
        let url = SecretUrl::new(format!(
            "postgres://user:PG_TLS_SECRET_12345@127.0.0.1:{port}/db{suffix}"
        ))
        .expect("URL");
        let error = adapter
            .test_connection(&url)
            .await
            .expect_err("non-verifying mode is unsupported");
        assert_eq!(error.kind(), &DbErrorKind::Unsupported, "{suffix}");
        assert!(error.message().contains("sslmode=prefer"));
        assert!(!error.to_string().contains("PG_TLS_SECRET_12345"));
        assert!(!format!("{error:?}").contains("PG_TLS_SECRET_12345"));
        assert!(matches!(
            &listener.accept(),
            Err(error) if error.kind() == ErrorKind::WouldBlock
        ));
    }

    // tokio-postgres rejects these modes at parse time; they never reach
    // the network either.
    let url = SecretUrl::new(format!(
        "postgres://user:PG_TLS_SECRET_12345@127.0.0.1:{port}/db?sslmode=verify-ca"
    ))
    .expect("URL");
    let error = adapter
        .test_connection(&url)
        .await
        .expect_err("verify-ca is not a tokio-postgres mode");
    assert_eq!(error.kind(), &DbErrorKind::Connection);
    assert!(!error.to_string().contains("PG_TLS_SECRET_12345"));
    assert!(matches!(
        &listener.accept(),
        Err(error) if error.kind() == ErrorKind::WouldBlock
    ));
}

#[tokio::test]
async fn verified_tls_sends_sslrequest_and_fails_closed_on_refusal() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let port = listener.local_addr().expect("listener address").port();
    let backend = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 8];
        stream.read_exact(&mut buf).await.expect("read SSLRequest");
        stream.write_all(b"N").await.expect("refuse TLS");
        buf
    });

    let adapter = PostgresAdapter;
    let url = SecretUrl::new(format!(
        "postgres://user:PG_TLS_SECRET_12345@127.0.0.1:{port}/db?sslmode=require"
    ))
    .expect("URL");
    let error = adapter
        .test_connection(&url)
        .await
        .expect_err("a TLS-refusing backend must fail closed");
    assert_eq!(error.kind(), &DbErrorKind::Transport);
    assert!(!error.to_string().contains("PG_TLS_SECRET_12345"));
    assert_eq!(backend.await.expect("backend join"), SSL_REQUEST);
}

#[tokio::test]
async fn explicit_plaintext_connects_without_sslrequest() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let port = listener.local_addr().expect("listener address").port();
    let backend = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 8];
        let read = stream.read(&mut buf).await.expect("read");
        // A plaintext StartupMessage begins with a length prefix, not the
        // fixed 8-byte SSLRequest.
        buf[..read].to_vec()
    });

    let adapter = PostgresAdapter;
    let url = SecretUrl::new(format!(
        "postgres://user:pass@127.0.0.1:{port}/db?sslmode=disable"
    ))
    .expect("URL");
    let result = tokio::time::timeout(Duration::from_secs(2), adapter.test_connection(&url)).await;
    // The fake backend never speaks PostgreSQL, so the call fails; what
    // matters is that no SSLRequest was sent.
    assert!(result.is_ok(), "plaintext connect must not hang");
    let first_bytes = backend.await.expect("backend join");
    assert_ne!(first_bytes, SSL_REQUEST.to_vec());
    assert!(first_bytes.len() >= 4, "startup length prefix is present");
}
