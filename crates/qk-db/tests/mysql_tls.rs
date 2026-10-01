use std::io::ErrorKind;
use std::net::TcpListener;

use qk_db::adapters::mysql::MysqlAdapter;
use qk_db::{DatabaseAdapter, DbErrorKind, SecretUrl};

#[tokio::test]
async fn tls_config_fails_before_connection_or_sql_execution() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let port = listener.local_addr().expect("listener address").port();
    let url = SecretUrl::new(format!(
        "mysql://qk:MYSQL_TLS_SECRET_12345@127.0.0.1:{port}/db?require_ssl=true"
    ))
    .expect("URL");
    let adapter = MysqlAdapter;

    let error = adapter
        .test_connection(&url)
        .await
        .expect_err("TLS is unsupported");
    assert_eq!(error.kind(), &DbErrorKind::Unsupported);
    assert!(!error.to_string().contains("MYSQL_TLS_SECRET_12345"));
    assert!(!format!("{error:?}").contains("MYSQL_TLS_SECRET_12345"));
    assert!(matches!(
        listener.accept(),
        Err(ref error) if error.kind() == ErrorKind::WouldBlock
    ));

    let error = adapter
        .execute(&url, "SELECT 1", &[])
        .await
        .expect_err("TLS is unsupported");
    assert_eq!(error.kind(), &DbErrorKind::Unsupported);
    assert!(matches!(
        listener.accept(),
        Err(ref error) if error.kind() == ErrorKind::WouldBlock
    ));
}
