use qk_sql::analyze::{has_parameter_markers, AnalyzeOptions};
use qk_sql::SqlDialect;

#[test]
fn marker_detection_uses_the_dialect_ast_not_string_contents() {
    let options = AnalyzeOptions { max_bytes: 1024 };
    assert!(has_parameter_markers(
        "SELECT * FROM t WHERE id = $1",
        SqlDialect::PostgreSql,
        options
    )
    .unwrap());
    assert!(!has_parameter_markers("SELECT '$1'", SqlDialect::PostgreSql, options).unwrap());
    assert!(
        has_parameter_markers("SELECT * FROM t WHERE id = ?", SqlDialect::MySql, options).unwrap()
    );
    assert!(!has_parameter_markers("SELECT '?'", SqlDialect::MySql, options).unwrap());
    assert!(!has_parameter_markers(
        "SELECT payload ? 'key' FROM t",
        SqlDialect::PostgreSql,
        options
    )
    .unwrap());
}

#[test]
fn marker_detection_keeps_the_existing_input_budget() {
    let error = has_parameter_markers(
        "SELECT 12345",
        SqlDialect::PostgreSql,
        AnalyzeOptions { max_bytes: 4 },
    )
    .expect_err("oversized SQL must be rejected before parsing");
    assert!(matches!(
        error,
        qk_sql::SqlAnalysisError::InputTooLarge { .. }
    ));
}
