//! Live PostgreSQL verified-TLS matrix for the direct `qk-db` adapter.
//!
//! Ignored by default. Run `scripts/test-postgres-tls.sh`, which provisions
//! an ephemeral PostgreSQL 17 TLS server and PKI, exports the environment
//! below, and invokes this file with `--ignored`.
//!
//! Environment:
//!   `QK_PG_TLS_URL`            trusted-CA URL (`…?sslmode=require`)
//!   `QK_PG_TLS_CA`             trusted CA bundle path
//!   `QK_PG_TLS_UNKNOWN_CA`     untrusted CA bundle path
//!   `QK_PG_TLS_MISMATCH_URL`   same server, host not in the certificate SAN
//!   `QK_PG_PLAINTEXT_URL`      plaintext PostgreSQL URL (`sslmode=disable`)
//!   `QK_PG_TLS_REQUIRED_PLAINTEXT_URL`  same plaintext server, `sslmode=require`
//!
//! No implicit fallback: every TLS failure must be a typed transport error,
//! and explicit plaintext must keep working.

use std::path::PathBuf;

use qk_db::adapters::postgres::PostgresAdapter;
use qk_db::{DatabaseAdapter, DbErrorKind, PostgresTlsOptions, SecretUrl};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name} (run scripts/test-postgres-tls.sh)"))
}

fn url_with_ca(url: &str, ca: Option<PathBuf>) -> SecretUrl {
    SecretUrl::new_with_tls(url, PostgresTlsOptions { ca_path: ca }).expect("trusted URL")
}

#[tokio::test]
#[ignore = "needs the live PostgreSQL TLS server (scripts/test-postgres-tls.sh)"]
async fn trusted_ca_connects() {
    let adapter = PostgresAdapter;
    let url = url_with_ca(
        &env("QK_PG_TLS_URL"),
        Some(PathBuf::from(env("QK_PG_TLS_CA"))),
    );
    adapter
        .test_connection(&url)
        .await
        .expect("trusted CA + correct hostname must connect");
}

#[tokio::test]
#[ignore = "needs the live PostgreSQL TLS server (scripts/test-postgres-tls.sh)"]
async fn unknown_ca_fails_closed() {
    let adapter = PostgresAdapter;
    let url = url_with_ca(
        &env("QK_PG_TLS_URL"),
        Some(PathBuf::from(env("QK_PG_TLS_UNKNOWN_CA"))),
    );
    let error = adapter
        .test_connection(&url)
        .await
        .expect_err("an untrusted CA must fail");
    assert_eq!(error.kind(), &DbErrorKind::Transport, "{error:?}");
}

#[tokio::test]
#[ignore = "needs the live PostgreSQL TLS server (scripts/test-postgres-tls.sh)"]
async fn hostname_mismatch_fails_closed() {
    let adapter = PostgresAdapter;
    let url = url_with_ca(
        &env("QK_PG_TLS_MISMATCH_URL"),
        Some(PathBuf::from(env("QK_PG_TLS_CA"))),
    );
    let error = adapter
        .test_connection(&url)
        .await
        .expect_err("a hostname absent from the SAN must fail");
    assert_eq!(error.kind(), &DbErrorKind::Transport, "{error:?}");
}

#[tokio::test]
#[ignore = "needs the live PostgreSQL TLS server (scripts/test-postgres-tls.sh)"]
async fn tls_required_against_plaintext_fails_closed() {
    let adapter = PostgresAdapter;
    // The plaintext server answers `N` to SSLRequest; the URL demands TLS.
    let url = url_with_ca(
        &env("QK_PG_TLS_REQUIRED_PLAINTEXT_URL"),
        Some(PathBuf::from(env("QK_PG_TLS_CA"))),
    );
    let error = adapter
        .test_connection(&url)
        .await
        .expect_err("a TLS-refusing backend must fail closed");
    assert_eq!(error.kind(), &DbErrorKind::Transport, "{error:?}");
}

#[tokio::test]
#[ignore = "needs the live PostgreSQL TLS server (scripts/test-postgres-tls.sh)"]
async fn explicit_plaintext_still_connects() {
    let adapter = PostgresAdapter;
    let url = SecretUrl::new(env("QK_PG_PLAINTEXT_URL")).expect("plaintext URL");
    adapter
        .test_connection(&url)
        .await
        .expect("explicit plaintext must keep working");
}
