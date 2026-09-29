//! Live SQLite integration: real temporary user databases through
//! the guarded service. Fixture DDL/DML bypasses authorization
//! deliberately (direct adapter calls, clearly isolated test setup);
//! every agent-visible read/write goes through `execute_guarded`.

use qk_approval::InMemoryApprovalStore;
use qk_db::{
    ApprovalSetup, DatabaseAdapter, DbConfig, DbErrorKind, DbValue, ExecuteRequest,
    ExecutionOutcome, ExecutionService, SecretUrl, TrustedContext,
};

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
          - operations: [select, insert, update, delete]
        row_safety:
          max_limit: 1000
"#;

const NOW: u64 = 1_700_000_000_000;

fn policy() -> qk_core::PolicyFile {
    qk_core::parse_policy(POLICY).expect("policy")
}

fn auth() -> TrustedContext {
    TrustedContext {
        integration: "test".to_owned(),
        environment: "production".to_owned(),
        database: "main".to_owned(),
        tool: "db_query".to_owned(),
        session_id: Some("session-1".to_owned()),
    }
}

struct Fixture {
    service: ExecutionService,
    adapter: qk_db::adapters::sqlite::SqliteAdapter,
    config: DbConfig,
    url: SecretUrl,
    _dir: std::path::PathBuf,
}

impl Fixture {
    /// Fresh temp database with a `users` table. Setup statements run
    /// on the bare adapter (isolated fixture setup, NOT production
    /// authorization).
    async fn setup() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "qk-db-live-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let url = SecretUrl::new(format!("sqlite:{}/app.db", dir.display())).expect("url");
        let adapter = qk_db::adapters::sqlite::SqliteAdapter;
        for ddl in [
            "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, score NUMERIC, data BLOB, meta TEXT, created TEXT)",
            "INSERT INTO users (id, name, score, data, meta, created) VALUES (1, 'ann', '19.99', X'0001', '{\"a\":1}', '2026-09-30T12:00:00Z')",
            "INSERT INTO users (id, name, score, data, meta, created) VALUES (9007199254740993, NULL, '0.30000000000000004', NULL, NULL, NULL)",
        ] {
            adapter
                .execute(&url, ddl, &[])
                .await
                .unwrap_or_else(|error| panic!("fixture {ddl}: {error}"));
        }
        Fixture {
            service: ExecutionService::new(),
            adapter,
            config: DbConfig::Sqlite(url.clone()),
            url,
            _dir: dir,
        }
    }

    async fn guarded(&self, sql: &str) -> ExecutionOutcome {
        let store = InMemoryApprovalStore::new();
        let auth = auth();
        let approval = ApprovalSetup {
            store: &store,
            provider: None,
            ttl_ms: 60_000,
            now_ms: NOW,
        };
        let policy = policy();
        self.service
            .execute_guarded(
                &qk_db::GuardedCall {
                    adapter: &self.adapter,
                    config: &self.config,
                    connection_key: "sqlite:test",
                    auth: &auth,
                    approval: &approval,
                    policy: &policy,
                },
                &ExecuteRequest {
                    sql: sql.to_owned(),
                    params: Vec::new(),
                    max_rows: None,
                    cursor: None,
                    approval_id: None,
                },
            )
            .await
    }
}

#[tokio::test]
async fn select_round_trip_with_value_shapes() {
    let db = Fixture::setup().await;
    let outcome = db
        .guarded("SELECT id, name, score, data, meta, created FROM users ORDER BY id")
        .await;
    let ExecutionOutcome::Executed(result) = outcome else {
        panic!("expected executed, got {outcome:?}");
    };
    assert_eq!(
        result.columns,
        vec!["id", "name", "score", "data", "meta", "created"]
    );
    assert_eq!(result.rows_shown, 2);
    assert!(!result.truncated);
    let first = &result.rows[0];
    assert_eq!(first[0], DbValue::Int(1));
    assert_eq!(first[1], DbValue::Text("ann".to_owned()));
    // SQLite NUMERIC affinity stores REAL: the engine (like Bun)
    // surfaces float64 here. Text precision preservation applies to
    // pg NUMERIC / mysql DECIMAL wire text (pinned in unit tests).
    assert_eq!(first[2], DbValue::Float(19.99));
    // Blob → bytes.
    assert_eq!(first[3], DbValue::Bytes(vec![0, 1]));
    // SQLite has no JSON type: TEXT passes through verbatim
    // (JSON parsing applies to pg JSON/JSONB and mysql JSON columns).
    assert_eq!(first[4], DbValue::Text("{\"a\":1}".to_owned()));
    // SQLite has no temporal types: stored text returns as text
    // (DateTime arises from pg/mysql native temporal decoding).
    assert_eq!(first[5], DbValue::Text("2026-09-30T12:00:00Z".to_owned()));
    let second = &result.rows[1];
    // Beyond JS-safe range → stringified on output, kept exact here.
    assert_eq!(second[0], DbValue::Int(9_007_199_254_740_993));
    assert_eq!(second[1], DbValue::Null);
    assert_eq!(
        serde_json::to_string(&second[0]).expect("json"),
        "\"9007199254740993\""
    );
}

#[tokio::test]
async fn bounded_mutations_report_affected_rows() {
    let db = Fixture::setup().await;
    let outcome = db
        .guarded("UPDATE users SET name = 'bob' WHERE id = 1")
        .await;
    let ExecutionOutcome::Executed(result) = outcome else {
        panic!("expected executed, got {outcome:?}");
    };
    assert_eq!(result.rows_affected, Some(1));
    assert!(result.rows.is_empty());
    let outcome = db.guarded("DELETE FROM users WHERE id = 1").await;
    let ExecutionOutcome::Executed(result) = outcome else {
        panic!("expected executed, got {outcome:?}");
    };
    assert_eq!(result.rows_affected, Some(1));
}

#[tokio::test]
async fn duplicate_columns_preserved_positionally() {
    let db = Fixture::setup().await;
    let outcome = db
        .guarded("SELECT id, id FROM users ORDER BY id LIMIT 1")
        .await;
    let ExecutionOutcome::Executed(result) = outcome else {
        panic!("expected executed, got {outcome:?}");
    };
    assert_eq!(result.columns, vec!["id", "id"]);
    assert_eq!(result.rows[0].len(), 2);
}

#[tokio::test]
async fn engine_error_is_typed_query_failure() {
    let db = Fixture::setup().await;
    let outcome = db.guarded("SELECT * FROM no_such_table").await;
    let ExecutionOutcome::Failed(error) = outcome else {
        panic!("expected failed, got {outcome:?}");
    };
    assert_eq!(error.kind(), &DbErrorKind::Query);
}

#[tokio::test]
async fn explain_reports_planner_text() {
    let db = Fixture::setup().await;
    let explained = db
        .adapter
        .explain(&db.url, "SELECT * FROM users", &[])
        .await
        .expect("explain");
    assert!(explained.contains("SCAN"), "unexpected plan: {explained}");
}

#[tokio::test]
async fn introspection_lists_and_describes() {
    let db = Fixture::setup().await;
    let tables = db.adapter.list_tables(&db.url, None).await.expect("tables");
    assert!(tables.iter().any(|table| table.name == "users"));
    let info = db
        .adapter
        .describe_table(&db.url, None, "users")
        .await
        .expect("describe");
    assert_eq!(info.columns.len(), 6);
    assert_eq!(info.primary_key, vec!["id".to_owned()]);
    assert!(info
        .columns
        .iter()
        .any(|col| col.name == "score" && col.data_type == "NUMERIC"));
    let ddl = db
        .adapter
        .dump_schema(&db.url, None, "users")
        .await
        .expect("dump");
    assert!(ddl.contains("CREATE TABLE users"));
    let ping = db.adapter.test_connection(&db.url).await.expect("ping");
    assert!(ping.ok);
}

#[tokio::test]
async fn truncation_flags_and_pages() {
    // 60+ rows through a 50-row budget: truncated + cursor.
    let setup = Fixture::setup().await;
    for i in 10..70 {
        setup
            .adapter
            .execute(
                &setup.url,
                &format!("INSERT INTO users (id, name) VALUES ({i}, 'bulk')"),
                &[],
            )
            .await
            .expect("bulk insert");
    }
    let outcome = setup.guarded("SELECT id FROM users ORDER BY id").await;
    let ExecutionOutcome::Executed(result) = outcome else {
        panic!("expected executed, got {outcome:?}");
    };
    assert!(result.truncated);
    assert_eq!(result.rows_shown, 50);
    assert!(result.cursor.is_some());
}
