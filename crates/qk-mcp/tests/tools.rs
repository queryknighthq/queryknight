//! MCP handler tests: schema snapshots, frozen formatting goldens,
//! choke-point proofs (adapter call counts), and history-failure
//! safety. Handlers are driven directly (no MCP framing here; the
//! stdio integration test covers the transport).

use qk_mcp::{
    DbDescribeArgs, DbExplainArgs, DbQueryArgs, DbSampleArgs, DbSchemaArgs, DbTablesArgs, McpState,
    QueryKnightServer,
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
          - operations: [select, insert]
        deny:
          - operations: [drop, truncate]
        approval_required:
          - operations: [update, delete]
        sensitive:
          columns:
            - users.password_hash
        mutations:
          deny_without_where: [update, delete]
        row_safety:
          max_limit: 1000
"#;

static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Live sqlite file with a small `users` table. Setup runs on the
/// bare adapter (isolated fixture, not production authorization).
/// Pins the policy environment (the MCP server reads it from the
/// process environment, like the reference).
async fn live_server() -> (QueryKnightServer, std::path::PathBuf) {
    std::env::set_var("QUERYKNIGHT_ENV", "production");
    std::env::set_var("QUERYKNIGHT_DATABASE", "main");
    let dir = std::env::temp_dir().join(format!(
        "qk-mcp-tools-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let url = format!("sqlite:{}/app.db", dir.display());
    let config = qk_db::DbConfig::from_url(&url).expect("config");
    let adapter = qk_db::ExecutionService::adapter_for(&config);
    for ddl in [
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, score NUMERIC, data BLOB)",
        "INSERT INTO users VALUES (1, 'ann', '19.99', X'0001')",
        "INSERT INTO users VALUES (9007199254740993, NULL, '0.3', NULL)",
    ] {
        adapter
            .execute(&qk_db::SecretUrl::new(&url).expect("secret"), ddl, &[])
            .await
            .unwrap_or_else(|error| panic!("fixture {ddl}: {error}"));
    }
    let policy = qk_core::parse_policy(POLICY).expect("policy");
    let state = McpState::without_daemon(&url, policy, None).expect("state");
    (QueryKnightServer::new(state), dir)
}

fn query(sql: &str) -> DbQueryArgs {
    DbQueryArgs {
        sql: sql.to_owned(),
        params: None,
        max_rows: None,
        cursor: None,
        approval_id: None,
    }
}

// ---------------------------------------------------------------------------
// Schema snapshots (frozen compatibility surface).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exact_tool_set_and_names() {
    let (server, _dir) = live_server().await;
    let names: Vec<String> = server
        .tools_snapshot()
        .iter()
        .map(|tool| tool.name.to_string())
        .collect();
    assert_eq!(
        names,
        vec![
            "approvals_decide",
            "approvals_list",
            "db_describe",
            "db_explain",
            "db_query",
            "db_sample",
            "db_schema",
            "db_tables",
        ]
    );
}

#[tokio::test]
async fn db_query_schema_shape() {
    let (server, _dir) = live_server().await;
    let tool = server
        .tools_snapshot()
        .into_iter()
        .find(|tool| tool.name == "db_query")
        .expect("db_query");
    let schema = serde_json::to_value(&tool.input_schema).expect("json");
    let props = schema.get("properties").expect("properties");
    for field in ["sql", "params", "maxRows", "cursor", "approvalId"] {
        assert!(props.get(field).is_some(), "missing {field}: {schema}");
    }
    assert_eq!(
        schema
            .get("required")
            .expect("required")
            .as_array()
            .expect("array")
            .iter()
            .filter_map(|value| value.as_str())
            .collect::<Vec<_>>(),
        vec!["sql"]
    );
    // Frozen bounds survive codegen.
    let sql = props.get("sql").expect("sql");
    assert_eq!(
        sql.get("minLength").and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(
        sql.get("maxLength").and_then(|value| value.as_u64()),
        Some(1_000_000)
    );
    assert_eq!(
        props
            .get("maxRows")
            .and_then(|value| value.get("maximum"))
            .and_then(|value| value.as_u64()),
        Some(200)
    );
}

// ---------------------------------------------------------------------------
// Formatting goldens.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn select_golden() {
    let (server, _dir) = live_server().await;
    let text = server
        .db_query_impl(query("SELECT id, name FROM users ORDER BY id LIMIT 1"))
        .await
        .expect("query");
    assert_eq!(
        text,
        "Showing 1 rows.\n\n| id | name |\n| --- | --- |\n| 1 | ann |\n\nReturned to agent: 9 bytes\nEstimated tokens returned: ~3"
    );
}

#[tokio::test]
async fn value_rendering_golden() {
    let (server, _dir) = live_server().await;
    let text = server
        .db_query_impl(query("SELECT id, name, score, data FROM users ORDER BY id"))
        .await
        .expect("query");
    // NULL renders empty; bigint survives exactly; blob is base64.
    // (SQLite NUMERIC affinity yields float64 like the reference
    // driver; DECIMAL text preservation is pinned in qk-db unit and
    // live pg/mysql tests.)
    assert!(
        text.contains("| 9007199254740993 |  | 0.3 |  |"),
        "got:\n{text}"
    );
    assert!(text.contains("| 1 | ann | 19.99 | AAE= |"), "got:\n{text}");
}

#[tokio::test]
async fn mutation_golden() {
    let (server, _dir) = live_server().await;
    let text = server
        .db_query_impl(query("INSERT INTO users (id, name) VALUES (7, 'zed')"))
        .await
        .expect("insert");
    assert!(text.contains("Rows affected: 1"), "got:\n{text}");
}

#[tokio::test]
async fn blocked_golden() {
    let (server, _dir) = live_server().await;
    let text = server
        .db_query_impl(query("DROP TABLE users"))
        .await
        .expect("blocked is a text result");
    assert!(text.starts_with("Blocked: "), "got:\n{text}");
    assert!(text.contains("[DENY_RULE]"), "got:\n{text}");
}

#[tokio::test]
async fn metadata_goldens() {
    let (server, _dir) = live_server().await;
    let tables = server
        .db_tables_impl(DbTablesArgs {
            schema: None,
            include_views: None,
            limit: None,
        })
        .await
        .expect("tables");
    assert!(tables.contains("users  table"), "got:\n{tables}");
    let describe = server
        .db_describe_impl(DbDescribeArgs {
            table: "users".to_owned(),
            schema: None,
        })
        .await
        .expect("describe");
    assert!(describe.contains("pk: id"), "got:\n{describe}");
    assert!(describe.contains("columns:"), "got:\n{describe}");
    let schema = server
        .db_schema_impl(DbSchemaArgs {
            schema: None,
            limit: None,
        })
        .await
        .expect("schema");
    assert!(schema.contains("users:"), "got:\n{schema}");
    let sample = server
        .db_sample_impl(DbSampleArgs {
            table: "users".to_owned(),
            schema: None,
            limit: Some(1),
        })
        .await
        .expect("sample");
    assert!(sample.contains("Showing 1 rows."), "got:\n{sample}");
    let explain = server
        .db_explain_impl(DbExplainArgs {
            sql: "SELECT * FROM users".to_owned(),
            params: None,
        })
        .await
        .expect("explain");
    assert!(
        explain.starts_with("Estimated plan (not measured runtime):\n"),
        "got:\n{explain}"
    );
}

#[tokio::test]
async fn approvals_list_without_daemon() {
    let (server, _dir) = live_server().await;
    assert_eq!(
        server.approvals_list_impl().await.expect("list"),
        "daemon unavailable; start queryknight"
    );
}

// ---------------------------------------------------------------------------
// Validation rejects before any service contact.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn malformed_arguments_are_protocol_errors() {
    let (server, _dir) = live_server().await;
    // Empty SQL would evaluate to a Blocked TEXT result if it reached
    // the service — a protocol Err proves validation-first.
    assert!(server.db_query_impl(query("")).await.is_err());
    assert!(server
        .db_query_impl(DbQueryArgs {
            max_rows: Some(0),
            ..query("SELECT 1")
        })
        .await
        .is_err());
    assert!(server
        .db_query_impl(DbQueryArgs {
            max_rows: Some(201),
            ..query("SELECT 1")
        })
        .await
        .is_err());
    assert!(server
        .db_describe_impl(DbDescribeArgs {
            table: "  ".to_owned(),
            schema: None
        })
        .await
        .is_err());
}

#[tokio::test]
async fn unknown_fields_ignored_like_zod_strip() {
    // Frozen: extra JSON keys are stripped, not rejected.
    let args: DbQueryArgs = serde_json::from_value(serde_json::json!({
        "sql": "SELECT 1",
        "dialect": "postgres",
        "extra": [1, 2, 3],
    }))
    .expect("unknown fields ignored");
    assert_eq!(args.sql, "SELECT 1");
}
