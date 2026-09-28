//! Adversarial SQL-layer battery: casing, comments, quoting per dialect,
//! string-embedded semicolons, nesting, aliases, unicode, malformed input,
//! bounded large input. Every case completes without panic; facts asserted.

use qk_sql::{analyze, AnalyzeOptions, ColumnName, LimitValue, Operation, SqlAnalysisError};

fn pg(sql: &str) -> qk_sql::QueryAnalysis {
    match analyze(sql, "postgres") {
        Ok(a) => a,
        Err(e) => panic!("postgres must parse {sql:?}: {e}"),
    }
}

#[test]
fn mixed_casing_and_comments() {
    let a = pg("SeLeCt /* inline */ id FrOm users -- trailing\nWhErE id = 1");
    assert_eq!(a.statements[0].operation, Operation::Select);
    assert!(a.read_only);
    let tables: Vec<String> = a.tables.iter().map(|t| t.to_string()).collect();
    assert_eq!(tables, vec!["users"]);
}

#[test]
fn semicolon_inside_string_literal() {
    let a = pg("SELECT ';'; SELECT 2");
    assert_eq!(a.statements.len(), 2);
    assert!(a
        .risk_signals
        .contains(&qk_sql::RiskSignal::MultipleStatements));
}

#[test]
fn dollar_quoted_string_with_semicolon() {
    let a = pg("SELECT $$a;b$$; SELECT 2");
    assert_eq!(a.statements.len(), 2);
}

#[test]
fn aliases_do_not_create_tables() {
    let a = pg("SELECT u.id FROM users u JOIN orders o ON o.user_id = u.id");
    let tables: Vec<String> = a.tables.iter().map(|t| t.to_string()).collect();
    assert_eq!(tables, vec!["orders", "users"]);
    // USING columns are extracted.
    let b = pg("SELECT id FROM users JOIN orders USING (id)");
    assert!(b
        .columns
        .iter()
        .any(|c| matches!(&c.name, ColumnName::Name(id) if id.value == "id")));
}

#[test]
fn schema_qualified_names() {
    let a = pg("SELECT id FROM public.users");
    assert_eq!(a.tables[0].to_string(), "public.users");
    let b = pg("SELECT id FROM db.public.users");
    assert_eq!(b.tables[0].to_string(), "db.public.users");
}

#[test]
fn quoting_per_dialect() {
    // PostgreSQL: quoted preserves case, unquoted preserved verbatim here.
    let a = pg("SELECT \"Email\" FROM \"Users\"");
    assert_eq!(a.tables[0].name.value, "Users");
    assert!(a.tables[0].name.quoted);
    // MySQL backticks.
    let b = match analyze("SELECT `weird col` FROM `my table`", "mysql") {
        Ok(a) => a,
        Err(e) => panic!("mysql backticks: {e}"),
    };
    assert_eq!(b.tables[0].to_string(), "my table");
    assert!(b.tables[0].name.quoted);
    // SQLite brackets.
    let c = match analyze("SELECT [weird col] FROM [my table]", "sqlite") {
        Ok(c) => c,
        Err(e) => panic!("sqlite brackets: {e}"),
    };
    assert_eq!(c.tables[0].to_string(), "my table");
}

#[test]
fn qualified_star_is_explicit() {
    let a = pg("SELECT u.* FROM users u");
    assert!(a.statements[0].select_star);
    assert!(a
        .columns
        .iter()
        .any(|c| matches!(&c.name, ColumnName::Star)));
}

#[test]
fn nested_subqueries_extracted() {
    let a = pg("SELECT name FROM users WHERE id IN (SELECT user_id FROM orders WHERE total > 100)");
    let tables: Vec<String> = a.tables.iter().map(|t| t.to_string()).collect();
    assert_eq!(tables, vec!["orders", "users"]);
    assert!(a.read_only);
}

#[test]
fn recursive_cte_parses() {
    let a = pg("WITH RECURSIVE sub AS (SELECT id FROM employees WHERE manager IS NULL UNION ALL SELECT e.id FROM employees e JOIN sub s ON e.manager = s.id) SELECT * FROM sub");
    assert_eq!(a.statements[0].operation, Operation::Select);
    assert!(a.read_only);
}

#[test]
fn exists_subquery_extracted() {
    let a = pg(
        "SELECT * FROM users WHERE EXISTS (SELECT 1 FROM orders WHERE orders.user_id = users.id)",
    );
    assert!(a.tables.iter().any(|t| t.to_string() == "orders"));
}

#[test]
fn unicode_identifiers_and_content() {
    let a = pg("SELECT \"üñï\" FROM \"tâble\" WHERE name = 'héllo 🎉'");
    assert_eq!(a.tables[0].to_string(), "tâble");
    assert!(a.read_only);
}

#[test]
fn malformed_variants_are_typed_errors() {
    // `SELECT FROM WHERE` is deliberately absent here: sqlparser-rs leniently
    // reads `WHERE` as a table name (documented in sqlparser-differences.md);
    // real databases reject it, so the leniency cannot authorize execution.
    for sql in [
        "(((((",
        "SELECT * FROM",
        "UPDATE SET",
        "'unclosed string",
        "SELECT 1; ;; garbage @@",
        "DELETE WHERE",
    ] {
        assert!(
            matches!(
                analyze(sql, "postgres"),
                Err(SqlAnalysisError::ParseError { .. })
            ),
            "{sql:?} must be a parse error"
        );
    }
}

#[test]
fn deep_nesting_fails_closed_without_panic() {
    // Parser nesting shapes trip the explicit recursion limit with a
    // machine-distinguishable error; no panic, no hang.
    let mut sql = String::from("SELECT 1");
    for i in 0..300 {
        sql = format!("SELECT * FROM ({sql}) t{i}");
    }
    assert!(matches!(
        analyze(&sql, "postgres"),
        Err(SqlAnalysisError::ComplexityLimitExceeded { .. })
    ));
}

#[test]
fn large_but_bounded_input_parses() {
    // Operator chains bypass the parser counter; the capped walk truncates
    // explicitly instead of claiming a complete inspection.
    let padding = "SELECT 1".to_owned() + &" + 1".repeat(20_000);
    assert!(padding.len() < qk_sql::MAX_SQL_BYTES);
    let a = match analyze(&padding, "postgres") {
        Ok(a) => a,
        Err(e) => panic!("bounded input must parse: {e}"),
    };
    assert_eq!(a.statements[0].operation, Operation::Select);
    assert_eq!(a.completeness, qk_sql::AnalysisCompleteness::DepthTruncated);
    assert!(!a.read_only);
}

#[test]
fn input_at_exact_limit_boundary() {
    let mut sql = String::from("SELECT 1");
    while sql.len() + 20 < qk_sql::MAX_SQL_BYTES {
        sql.push_str(" /* pad */");
    }
    assert!(sql.len() < qk_sql::MAX_SQL_BYTES);
    assert!(analyze(&sql, "postgres").is_ok());
    sql.push_str(&"x".repeat(64));
    assert!(matches!(
        analyze(&sql, "postgres"),
        Err(SqlAnalysisError::InputTooLarge { .. })
    ));
    // The limit is overridable per call without changing the frozen default.
    assert!(qk_sql::analyze_with_options(
        &sql,
        "postgres".parse().expect("dialect"),
        AnalyzeOptions {
            max_bytes: sql.len() + 1
        }
    )
    .is_ok());
}

#[test]
fn keyword_as_table_leniency_documented() {
    // sqlparser-rs accepts reserved words as table names where the reference
    // rejects them. Pinned as a known leniency: real databases refuse to
    // execute these shapes, so no execution can be authorized from them.
    let a = pg("SELECT FROM WHERE");
    assert_eq!(a.statements[0].operation, Operation::Select);
    assert_eq!(
        a.tables.iter().map(|t| t.to_string()).collect::<Vec<_>>(),
        vec!["WHERE"]
    );
}

#[test]
fn unknown_dialect_is_typed_error() {
    assert!(matches!(
        analyze("SELECT 1", "mssql"),
        Err(SqlAnalysisError::UnsupportedDialect(_))
    ));
    assert!(matches!(
        analyze("SELECT 1", ""),
        Err(SqlAnalysisError::UnsupportedDialect(_))
    ));
}

#[test]
fn mysql_update_delete_limit_and_returning_shapes() {
    let a = match analyze("DELETE FROM t WHERE a = 1 LIMIT 5", "mysql") {
        Ok(a) => a,
        Err(e) => panic!("mysql delete limit: {e}"),
    };
    assert_eq!(a.statements[0].has_where, Some(true));
    assert!(matches!(
        a.statements[0].limit,
        Some(LimitValue::Literal(5))
    ));

    let b = pg("UPDATE t SET a = 1 WHERE b = 2 RETURNING a");
    assert!(b.statements[0].has_returning);
}
