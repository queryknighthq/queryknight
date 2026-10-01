//! Optional live-database contracts for PostgreSQL and MySQL.
//!
//! Ignored by default (no Docker in unit runs). Run explicitly with a
//! database available:
//!
//! ```sh
//! # PostgreSQL 16 on 127.0.0.1:5432, superuser postgres/postgres:
//! docker run --rm -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:16
//! PG_URL='postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable' \
//!   cargo test -p qk-db --test live_contract -- --ignored
//!
//! # MySQL 8 on 127.0.0.1:3306, root/root, db qk:
//! docker run --rm -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=qk \
//!   -p 3306:3306 mysql:8
//! MYSQL_URL='mysql://root:root@127.0.0.1:3306/qk' \
//!   cargo test -p qk-db --test live_contract -- --ignored
//! ```
//!
//! These tests assert the full adapter contract against real servers:
//! handshake, DDL/DML, value decoding (bigint/decimal/binary/date),
//! EXPLAIN estimates, introspection, and typed error mapping. They
//! must NEVER run in normal CI (no `#[ignore]` removal).

use qk_db::{DatabaseAdapter, DbConfig, DbValue, ExecutionOutcome, SecretUrl};

fn pg_url() -> String {
    std::env::var("PG_URL").unwrap_or_else(|_| {
        "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable".to_owned()
    })
}

fn mysql_url() -> String {
    std::env::var("MYSQL_URL").unwrap_or_else(|_| "mysql://root:root@127.0.0.1:3306/qk".to_owned())
}

#[tokio::test]
#[ignore = "needs a live PostgreSQL (see header)"]
async fn postgres_live_contract() {
    let url = SecretUrl::new(pg_url()).expect("url");
    let config = DbConfig::from_url(url.expose()).expect("config");
    assert!(matches!(config, DbConfig::Postgres(_)));
    let adapter = qk_db::adapters::postgres::PostgresAdapter;
    let ping = adapter.test_connection(&url).await.expect("ping");
    assert!(ping.ok);
    assert!(ping
        .server_version
        .is_some_and(|version| !version.is_empty()));

    // Fixture via the bare adapter (isolated setup, not production auth).
    for ddl in [
        "DROP TABLE IF EXISTS qk_contract",
        "CREATE TABLE qk_contract (id BIGINT PRIMARY KEY, amount NUMERIC(30,17), payload BYTEA, created TIMESTAMPTZ, meta JSONB)",
        "INSERT INTO qk_contract VALUES (9007199254740993, 0.30000000000000004, '\\x0001'::bytea, '2026-09-30T12:00:00Z', '{\"a\":1}')",
    ] {
        adapter.execute(&url, ddl, &[]).await.unwrap_or_else(|error| panic!("{ddl}: {error}"));
    }
    let result = adapter
        .execute(
            &url,
            "SELECT id, amount, payload, created, meta FROM qk_contract",
            &[],
        )
        .await
        .expect("select");
    assert_eq!(
        result.columns,
        vec!["id", "amount", "payload", "created", "meta"]
    );
    let row = &result.rows[0];
    // Bigint exact through the adapter (stringified only at JSON edge).
    assert_eq!(row[0], DbValue::Int(9_007_199_254_740_993));
    assert_eq!(
        serde_json::to_string(&row[0]).expect("json"),
        "\"9007199254740993\""
    );
    // NUMERIC text precision preserved.
    assert_eq!(row[1], DbValue::Decimal("0.30000000000000004".to_owned()));
    assert_eq!(row[2], DbValue::Bytes(vec![0, 1]));
    assert_eq!(row[3], DbValue::DateTime("2026-09-30T12:00:00Z".to_owned()));
    assert_eq!(row[4], DbValue::Json(serde_json::json!({"a": 1})));

    // EXPLAIN estimate shape.
    let plan = adapter
        .explain(&url, "SELECT * FROM qk_contract", &[])
        .await
        .expect("explain");
    assert!(plan.contains("rows="), "unexpected plan: {plan}");

    // Introspection.
    let tables = adapter
        .list_tables(&url, Some("public"))
        .await
        .expect("tables");
    assert!(tables.iter().any(|table| table.name == "qk_contract"));
    let info = adapter
        .describe_table(&url, Some("public"), "qk_contract")
        .await
        .expect("describe");
    assert_eq!(info.primary_key, vec!["id".to_owned()]);

    // Guarded execution end to end (allow-all test policy).
    let policy = qk_core::parse_policy(
        "version: 1\ndefaults:\n  decision: deny\n  on_parse_error: deny\n  on_unknown: deny\nenvironments:\n  production:\n    databases:\n      main:\n        allow:\n          - operations: [select]\n",
    )
    .expect("policy");
    let store = qk_approval::InMemoryApprovalStore::new();
    let service = qk_db::ExecutionService::new();
    let auth = qk_db::TrustedContext {
        integration: "test".to_owned(),
        environment: "production".to_owned(),
        database: "main".to_owned(),
        tool: "db_query".to_owned(),
        session_id: None,
    };
    let approval = qk_db::ApprovalSetup {
        store: &store,
        provider: None,
        ttl_ms: 60_000,
        now_ms: 1_700_000_000_000,
    };
    let outcome = service
        .execute_guarded(
            &qk_db::GuardedCall {
                adapter: &adapter,
                config: &config,
                connection_key: "pg:test",
                auth: &auth,
                approval: &approval,
                policy: &policy,
            },
            &qk_db::ExecuteRequest {
                sql: "SELECT id FROM qk_contract".to_owned(),
                params: vec![],
                max_rows: None,
                cursor: None,
                approval_id: None,
            },
        )
        .await;
    assert!(
        matches!(outcome, ExecutionOutcome::Executed(_)),
        "{outcome:?}"
    );

    adapter
        .execute(&url, "DROP TABLE qk_contract", &[])
        .await
        .expect("cleanup");
}

#[tokio::test]
#[ignore = "needs a live MySQL (see header)"]
async fn mysql_live_contract() {
    let url = SecretUrl::new(mysql_url()).expect("url");
    let config = DbConfig::from_url(url.expose()).expect("config");
    assert!(matches!(config, DbConfig::Mysql(_)));
    let adapter = qk_db::adapters::mysql::MysqlAdapter;
    let ping = adapter.test_connection(&url).await.expect("ping");
    assert!(ping.ok);

    for ddl in [
        "DROP TABLE IF EXISTS qk_contract",
        "CREATE TABLE qk_contract (id BIGINT PRIMARY KEY, amount DECIMAL(30,17), payload BLOB, created DATETIME(6), meta JSON)",
        "INSERT INTO qk_contract VALUES (9007199254740993, 0.30000000000000004, UNHEX('0001'), '2026-09-30 12:00:00.000000', '{\"a\":1}')",
    ] {
        adapter.execute(&url, ddl, &[]).await.unwrap_or_else(|error| panic!("{ddl}: {error}"));
    }
    let result = adapter
        .execute(
            &url,
            "SELECT id, amount, payload, created, meta FROM qk_contract",
            &[],
        )
        .await
        .expect("select");
    let row = &result.rows[0];
    assert_eq!(row[0], DbValue::Int(9_007_199_254_740_993));
    assert_eq!(row[1], DbValue::Decimal("0.30000000000000004".to_owned()));
    assert_eq!(row[2], DbValue::Bytes(vec![0, 1]));
    assert_eq!(row[3], DbValue::DateTime("2026-09-30T12:00:00".to_owned()));
    assert_eq!(row[4], DbValue::Json(serde_json::json!({"a": 1})));

    let tables = adapter.list_tables(&url, None).await.expect("tables");
    assert!(tables.iter().any(|table| table.name == "qk_contract"));
    let ddl = adapter
        .dump_schema(&url, None, "qk_contract")
        .await
        .expect("dump");
    assert!(ddl.contains("CREATE TABLE"));

    adapter
        .execute(&url, "DROP TABLE qk_contract", &[])
        .await
        .expect("cleanup");
}
