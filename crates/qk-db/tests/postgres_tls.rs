use std::io::ErrorKind;
use std::net::TcpListener as StdTcpListener;
use std::time::Duration;

use qk_db::adapters::postgres::PostgresAdapter;
use qk_db::{DatabaseAdapter, DbErrorKind, SecretUrl};
use tokio::net::TcpListener;

#[tokio::test]
async fn non_disable_ssl_modes_fail_before_network_and_disable_stays_plaintext() {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let port = listener.local_addr().expect("listener address").port();
    let adapter = PostgresAdapter;
    let urls = [
        format!("postgres://user:PG_TLS_SECRET_12345@127.0.0.1:{port}/db"),
        format!("postgres://user:PG_TLS_SECRET_12345@127.0.0.1:{port}/db?sslmode=prefer"),
        format!("postgres://user:PG_TLS_SECRET_12345@127.0.0.1:{port}/db?sslmode=require"),
    ];

    for raw_url in urls {
        let url = SecretUrl::new(raw_url).expect("URL");
        let error = adapter
            .test_connection(&url)
            .await
            .expect_err("non-disable sslmode is unsupported");
        assert_eq!(error.kind(), &DbErrorKind::Unsupported);
        assert!(error.message().contains("sslmode=disable"));
        assert!(!error.to_string().contains("PG_TLS_SECRET_12345"));
        assert!(!format!("{error:?}").contains("PG_TLS_SECRET_12345"));
        assert!(matches!(
            listener.accept(),
            Err(ref error) if error.kind() == ErrorKind::WouldBlock
        ));
    }

    let url = SecretUrl::new(format!(
        "postgres://user:PG_TLS_SECRET_12345@127.0.0.1:{port}/db?sslmode=require"
    ))
    .expect("URL");
    let error = adapter
        .execute(&url, "SELECT 1", &[])
        .await
        .expect_err("TLS is unsupported");
    assert_eq!(error.kind(), &DbErrorKind::Unsupported);
    assert!(matches!(
        listener.accept(),
        Err(ref error) if error.kind() == ErrorKind::WouldBlock
    ));

    let url = SecretUrl::new(format!(
        "postgres://user:PG_TLS_SECRET_12345@127.0.0.1:{port}/db?sslmode=verify-ca"
    ))
    .expect("URL");
    let error = adapter
        .test_connection(&url)
        .await
        .expect_err("tokio-postgres rejects verify-ca");
    assert_eq!(error.kind(), &DbErrorKind::Connection);
    assert!(!error.to_string().contains("PG_TLS_SECRET_12345"));
    assert!(matches!(
        listener.accept(),
        Err(ref error) if error.kind() == ErrorKind::WouldBlock
    ));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let port = listener.local_addr().expect("listener address").port();
    let accept = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("plaintext connection");
        drop(stream);
    });
    let url = SecretUrl::new(format!(
        "postgres://user:pass@127.0.0.1:{port}/db?sslmode=disable"
    ))
    .expect("URL");
    let result = tokio::time::timeout(Duration::from_secs(2), adapter.test_connection(&url))
        .await
        .expect("plaintext connection should complete against the closing fake server");
    assert_eq!(
        result.expect_err("fake server is not PostgreSQL").kind(),
        &DbErrorKind::Connection
    );
    accept.await.expect("accepted plaintext connection");
}
