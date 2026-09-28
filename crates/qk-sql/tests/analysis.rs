//! Analysis compatibility: shared corpus structural facts plus
//! Rust-capability fixtures (`sql-analysis-rust.cases.json`). No verdicts.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use qk_sql::{analyze, ColumnName, LimitValue, Operation, QueryAnalysis};

fn compat_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/compatibility")
}

fn read_json(file: &str) -> Vec<serde_json::Value> {
    let text =
        fs::read_to_string(compat_dir().join(file)).unwrap_or_else(|e| panic!("read {file}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {file}: {e}"))
}

fn field(case: &serde_json::Value, key: &str) -> String {
    case.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("missing {key} in {case}"))
        .to_owned()
}

fn shared_case(file: &str, name: &str) -> (String, String) {
    for case in read_json(file) {
        if case.get("name").and_then(|v| v.as_str()) == Some(name) {
            return (field(&case, "sql"), field(&case, "dialect"));
        }
    }
    panic!("case {name} not found in {file}");
}

fn tables_of(a: &QueryAnalysis) -> Vec<String> {
    a.tables.iter().map(|t| t.to_string()).collect()
}

fn mutated_of(a: &QueryAnalysis) -> Vec<String> {
    a.mutated_tables.iter().map(|t| t.to_string()).collect()
}

fn columns_of(a: &QueryAnalysis) -> Vec<String> {
    a.columns
        .iter()
        .map(|c| {
            let mut s = c
                .qualifier
                .iter()
                .map(|i| i.value.clone())
                .collect::<Vec<_>>();
            match &c.name {
                ColumnName::Star => s.push("*".to_owned()),
                ColumnName::Name(id) => s.push(id.value.clone()),
            }
            s.join(".")
        })
        .collect()
}

fn ops_of(a: &QueryAnalysis) -> Vec<&str> {
    a.operations.iter().map(|o| o.name()).collect()
}

fn nested_of_first(a: &QueryAnalysis) -> Vec<&str> {
    a.statements
        .first()
        .map(|s| s.nested_operations.iter().map(|o| o.name()).collect())
        .unwrap_or_default()
}

fn analyze_shared(file: &str, name: &str) -> QueryAnalysis {
    let (sql, dialect) = shared_case(file, name);
    match analyze(&sql, &dialect) {
        Ok(a) => a,
        Err(e) => panic!("shared case {name} must parse: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Shared corpus: multi-statement + nested DML (analysis fields only)
// ---------------------------------------------------------------------------

#[test]
fn multi_statement_attack_fully_visible() {
    let a = analyze_shared(
        "multistatement-nested.cases.json",
        "multi-statement attack denied via strictest",
    );
    assert_eq!(a.statements.len(), 2);
    assert_eq!(ops_of(&a), vec!["select", "drop"]);
    assert_eq!(tables_of(&a), vec!["users"]);
    assert_eq!(mutated_of(&a), vec!["users"]);
    assert!(!a.read_only);
    assert!(a
        .risk_signals
        .contains(&qk_sql::RiskSignal::MultipleStatements));
}

#[test]
fn stacked_statements_each_classified() {
    let a = analyze_shared(
        "multistatement-nested.cases.json",
        "stacked unbounded delete denied",
    );
    assert_eq!(a.statements.len(), 2);
    let second = &a.statements[1];
    assert_eq!(second.operation, Operation::Delete);
    assert_eq!(second.has_where, Some(false));
}

#[test]
fn data_modifying_cte_exposes_inner_delete() {
    // Oracle rejects this shape; sqlparser-rs parses it. The inner DELETE
    // must be visible as a nested operation either way.
    let a = analyze_shared(
        "multistatement-nested.cases.json",
        "data-modifying CTE fails closed on parse",
    );
    assert_eq!(a.statements.len(), 1);
    assert_eq!(a.statements[0].operation, Operation::Select);
    assert_eq!(nested_of_first(&a), vec!["delete"]);
    assert!(tables_of(&a).contains(&"customers".to_owned()));
    assert!(!a.read_only);
}

#[test]
fn insert_select_tables_and_star() {
    let a = analyze_shared(
        "multistatement-nested.cases.json",
        "insert-select carries write operation",
    );
    assert_eq!(a.statements[0].operation, Operation::Insert);
    assert_eq!(tables_of(&a), vec!["archive", "public.customers"]);
    assert_eq!(mutated_of(&a), vec!["archive"]);
    assert!(columns_of(&a).contains(&"*".to_owned()));
}

#[test]
fn delete_with_subquery_bounded() {
    let a = analyze_shared(
        "multistatement-nested.cases.json",
        "delete with subquery still bounded",
    );
    assert_eq!(a.statements[0].operation, Operation::Delete);
    assert_eq!(a.statements[0].has_where, Some(true));
}

// ---------------------------------------------------------------------------
// Shared corpus: malformed / unsupported (analysis layer only)
// ---------------------------------------------------------------------------

#[test]
fn empty_input_is_typed_error() {
    let (sql, dialect) = shared_case(
        "malformed-unsupported.cases.json",
        "empty query denied without parsing",
    );
    assert!(matches!(
        analyze(&sql, &dialect),
        Err(qk_sql::SqlAnalysisError::EmptyQuery)
    ));
}

#[test]
fn oversized_input_is_typed_error() {
    let (sql, dialect) = shared_case(
        "malformed-unsupported.cases.json",
        "oversized sql denied without parsing",
    );
    let err = qk_sql::analyze_with_options(
        &sql,
        dialect.parse().expect("test dialect"),
        qk_sql::AnalyzeOptions { max_bytes: 4 },
    )
    .expect_err("must exceed budget");
    assert!(matches!(
        err,
        qk_sql::SqlAnalysisError::InputTooLarge { .. }
    ));
}

#[test]
fn garbage_input_is_parse_error() {
    let (sql, dialect) = shared_case(
        "malformed-unsupported.cases.json",
        "garbage sql fails closed",
    );
    assert!(matches!(
        analyze(&sql, &dialect),
        Err(qk_sql::SqlAnalysisError::ParseError { .. })
    ));
}

#[test]
fn call_parses_but_never_read_only() {
    let a = analyze_shared(
        "malformed-unsupported.cases.json",
        "call statement unknown fails closed",
    );
    assert_eq!(a.statements[0].operation, Operation::Call);
    assert!(!a.read_only);
}

#[test]
fn merge_parses_with_visible_tables() {
    // Oracle rejects MERGE; sqlparser-rs parses it. Facts, not verdicts.
    let a = analyze_shared(
        "malformed-unsupported.cases.json",
        "merge into fails closed",
    );
    assert_eq!(a.statements[0].operation, Operation::Merge);
    assert!(tables_of(&a).contains(&"customers".to_owned()));
    assert!(!a.read_only);
}

#[test]
fn grant_and_truncate_classified() {
    let g = analyze_shared(
        "malformed-unsupported.cases.json",
        "grant without explicit rule still denied by default",
    );
    assert_eq!(g.statements[0].operation, Operation::Grant);
    assert!(!g.read_only);
    let t = analyze_shared(
        "malformed-unsupported.cases.json",
        "truncate denied by rule",
    );
    assert_eq!(t.statements[0].operation, Operation::Truncate);
    assert_eq!(mutated_of(&t), vec!["customers"]);
}

// ---------------------------------------------------------------------------
// Shared corpus: unbounded mutations (structure only) + sensitive extraction
// ---------------------------------------------------------------------------

#[test]
fn unbounded_structures_record_where_absence() {
    for (name, want) in [
        ("deny unbounded update", Some(false)),
        ("deny unbounded delete", Some(false)),
        ("unbounded mysql update denied", Some(false)),
        ("unbounded sqlite delete denied", Some(false)),
        ("bounded update escapes unbounded gate", Some(true)),
    ] {
        let a = analyze_shared("unbounded-mutations.cases.json", name);
        assert_eq!(a.statements[0].has_where, want, "{name}");
    }
}

#[test]
fn sensitive_examples_extract_tables_and_columns() {
    let a = analyze_shared("sensitive-columns.cases.json", "sensitive column denied");
    assert_eq!(tables_of(&a), vec!["users"]);
    assert_eq!(columns_of(&a), vec!["password_hash"]);
    let a = analyze_shared(
        "sensitive-columns.cases.json",
        "qualified sensitive column denied",
    );
    assert!(columns_of(&a).contains(&"users.password_hash".to_owned()));
    let a = analyze_shared(
        "sensitive-columns.cases.json",
        "schema qualified wildcard denied",
    );
    assert_eq!(tables_of(&a), vec!["public.integrations"]);
}

// ---------------------------------------------------------------------------
// Rust-capability fixtures (data-driven)
// ---------------------------------------------------------------------------

fn table_set(a: &QueryAnalysis) -> Vec<String> {
    tables_of(a)
}

#[test]
fn rust_capability_fixtures() {
    let cases = read_json("sql-analysis-rust.cases.json");
    let mut seen = HashMap::new();
    for case in &cases {
        let name = field(case, "name");
        *seen.entry(name.clone()).or_insert(0) += 1;
        let dialect = field(case, "dialect");
        let sql = field(case, "sql");
        let exp = case
            .get("expected")
            .unwrap_or_else(|| panic!("{name}: no expected"));
        let err_kind = exp.get("error").and_then(|v| v.as_str());
        let result = analyze(&sql, &dialect);
        match err_kind {
            Some("empty") => assert!(
                matches!(result, Err(qk_sql::SqlAnalysisError::EmptyQuery)),
                "{name}: expected EmptyQuery, got {result:?}"
            ),
            Some("parse") => assert!(
                matches!(result, Err(qk_sql::SqlAnalysisError::ParseError { .. })),
                "{name}: expected ParseError, got {result:?}"
            ),
            Some("dialect") => assert!(
                matches!(result, Err(qk_sql::SqlAnalysisError::UnsupportedDialect(_))),
                "{name}: expected UnsupportedDialect, got {result:?}"
            ),
            Some(other) => panic!("{name}: unknown error expectation {other}"),
            None => {
                let a = match result {
                    Ok(a) => a,
                    Err(e) => panic!("{name}: expected analysis, got {e}"),
                };
                if let Some(n) = exp.get("statements").and_then(|v| v.as_u64()) {
                    assert_eq!(a.statements.len(), n as usize, "{name}: statements");
                }
                if let Some(ops) = exp.get("operations") {
                    let want: Vec<String> = serde_json::from_value(ops.clone())
                        .unwrap_or_else(|e| panic!("{name}: bad operations: {e}"));
                    let mut got = ops_of(&a)
                        .into_iter()
                        .map(str::to_owned)
                        .collect::<Vec<_>>();
                    got.sort();
                    let mut want = want;
                    want.sort();
                    assert_eq!(got, want, "{name}: operations");
                }
                if let Some(nested) = exp.get("nested") {
                    let want: Vec<String> = serde_json::from_value(nested.clone())
                        .unwrap_or_else(|e| panic!("{name}: bad nested: {e}"));
                    assert_eq!(nested_of_first(&a), want, "{name}: nested");
                }
                if let Some(tables) = exp.get("tables") {
                    let mut want: Vec<String> = serde_json::from_value(tables.clone())
                        .unwrap_or_else(|e| panic!("{name}: bad tables: {e}"));
                    want.sort();
                    assert_eq!(table_set(&a), want, "{name}: tables");
                }
                if let Some(mutated) = exp.get("mutated") {
                    let mut want: Vec<String> = serde_json::from_value(mutated.clone())
                        .unwrap_or_else(|e| panic!("{name}: bad mutated: {e}"));
                    want.sort();
                    let mut got = mutated_of(&a);
                    got.sort();
                    assert_eq!(got, want, "{name}: mutated");
                }
                if let Some(columns) = exp.get("columns") {
                    let mut want: Vec<String> = serde_json::from_value(columns.clone())
                        .unwrap_or_else(|e| panic!("{name}: bad columns: {e}"));
                    want.sort();
                    let mut got = columns_of(&a);
                    got.sort();
                    assert_eq!(got, want, "{name}: columns");
                }
                if let Some(w) = exp.get("has_where") {
                    if w.is_null() {
                        assert_eq!(a.statements[0].has_where, None, "{name}: has_where");
                    } else {
                        assert_eq!(
                            a.statements[0].has_where,
                            Some(
                                w.as_bool()
                                    .unwrap_or_else(|| panic!("{name}: bad has_where"))
                            ),
                            "{name}: has_where"
                        );
                    }
                }
                if let Some(l) = exp.get("limit").and_then(|v| v.as_str()) {
                    let got = match &a.statements[0].limit {
                        Some(LimitValue::Literal(n)) => format!("literal:{n}"),
                        Some(LimitValue::Parameterized) => "parameterized".to_owned(),
                        Some(LimitValue::Expression) => "expression".to_owned(),
                        None => "none".to_owned(),
                    };
                    assert_eq!(got, l, "{name}: limit");
                }
                if let Some(w) = exp.get("read_only").and_then(|v| v.as_bool()) {
                    assert_eq!(a.read_only, w, "{name}: read_only");
                }
                if let Some(w) = exp.get("select_star").and_then(|v| v.as_bool()) {
                    assert_eq!(a.statements[0].select_star, w, "{name}: select_star");
                }
                if let Some(signals) = exp.get("signals") {
                    let want: Vec<String> = serde_json::from_value(signals.clone())
                        .unwrap_or_else(|e| panic!("{name}: bad signals: {e}"));
                    for s in &want {
                        assert!(
                            a.risk_signals.iter().any(|r| format!("{r:?}") == *s),
                            "{name}: missing signal {s} in {:?}",
                            a.risk_signals
                        );
                    }
                }
            }
        }
    }
    assert_eq!(seen.len(), cases.len(), "fixture names must be unique");
    assert!(!cases.is_empty(), "capability fixtures must exist");
}
