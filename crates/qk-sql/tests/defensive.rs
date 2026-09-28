//! Defensive-scan fixtures, strictness/monotonicity proofs, AST-vs-scan
//! differentials, and adversarial cases. No verdicts anywhere.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use qk_sql::{
    analyze, defensive_scan, AnalysisCompleteness, DefensiveSignal, OpCategory, PossibleOperation,
    ScanCompleteness, SqlDialect, SqlInspection,
};

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

fn dialect_of(case: &serde_json::Value) -> SqlDialect {
    field(case, "dialect")
        .parse()
        .unwrap_or_else(|e| panic!("bad dialect: {e}"))
}

fn possible_names(scan: &qk_sql::DefensiveScan) -> Vec<&str> {
    scan.possible_operations.iter().map(|o| o.name()).collect()
}

// ---------------------------------------------------------------------------
// Fixture runner.
// ---------------------------------------------------------------------------

#[test]
fn defensive_scan_fixtures() {
    let cases = read_json("defensive-scan.cases.json");
    let mut seen = HashMap::new();
    for case in &cases {
        let name = field(case, "name");
        *seen.entry(name.clone()).or_insert(0) += 1;
        let scan = defensive_scan(&field(case, "sql"), dialect_of(case));
        let exp = case
            .get("expected")
            .unwrap_or_else(|| panic!("{name}: no expected"));
        let mut want_possible: Vec<String> =
            serde_json::from_value(exp.get("possible").cloned().unwrap_or_default())
                .unwrap_or_else(|e| panic!("{name}: bad possible: {e}"));
        want_possible.sort();
        let mut got_possible: Vec<String> = possible_names(&scan)
            .into_iter()
            .map(str::to_owned)
            .collect();
        got_possible.sort();
        assert_eq!(got_possible, want_possible, "{name}: possible");
        let want_signals: Vec<String> =
            serde_json::from_value(exp.get("signals").cloned().unwrap_or_default())
                .unwrap_or_else(|e| panic!("{name}: bad signals: {e}"));
        for s in &want_signals {
            assert!(
                scan.signals.iter().any(|sig| format!("{sig:?}") == *s),
                "{name}: missing signal {s} in {:?}",
                scan.signals
            );
        }
        assert_eq!(
            scan.signals.len(),
            want_signals.len(),
            "{name}: signal count"
        );
        assert_eq!(
            scan.statement_boundaries,
            exp.get("boundaries").and_then(|v| v.as_u64()).unwrap_or(0) as usize,
            "{name}: boundaries"
        );
        let want_complete = field(exp, "completeness") == "Complete";
        assert_eq!(
            scan.completeness == ScanCompleteness::Complete,
            want_complete,
            "{name}: completeness"
        );
    }
    assert_eq!(seen.len(), cases.len(), "fixture names must be unique");
    assert!(!cases.is_empty());
}

// ---------------------------------------------------------------------------
// Strictness / monotonicity: separate types, no unsafe transformation.
// ---------------------------------------------------------------------------

/// AST operation names that must have a defensive counterpart when the scan
/// is complete. Reads need none (missing a read never reduces risk).
fn required_counterpart(op: &str) -> Option<&'static str> {
    match op {
        "insert" => Some("insert"),
        "update" => Some("update"),
        "delete" => Some("delete"),
        "merge" => Some("merge"),
        "create" => Some("create"),
        "alter" => Some("alter"),
        "drop" => Some("drop"),
        "truncate" => Some("truncate"),
        "grant" => Some("grant"),
        "revoke" => Some("revoke"),
        "copy" => Some("copy"),
        "call" => Some("call"),
        "vacuum" => Some("vacuum"),
        "transaction" => Some("transaction"),
        _ => None,
    }
}

#[test]
fn defensive_never_weakens_ast_risk() {
    // Every non-read AST operation must be visible to the defensive scan
    // (or the scan must flag itself incomplete). Corpus: all shared SQL
    // fixtures plus adversarial shapes.
    let mut files = vec![
        "policy-evaluation.cases.json",
        "sensitive-columns.cases.json",
        "unbounded-mutations.cases.json",
        "multistatement-nested.cases.json",
        "malformed-unsupported.cases.json",
        "approvals-rowlimits.cases.json",
        "sql-analysis-rust.cases.json",
    ];
    files.sort();
    let mut checked = 0u32;
    for file in files {
        for case in read_json(file) {
            let (Some(sql), Some(dialect_str)) = (
                case.get("sql").and_then(|v| v.as_str()),
                case.get("dialect").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            let Ok(dialect) = dialect_str.parse::<SqlDialect>() else {
                continue;
            };
            let Ok(analysis) = analyze(sql, dialect_str) else {
                continue;
            };
            let scan = defensive_scan(sql, dialect);
            checked += 1;
            for op in &analysis.operations {
                if op.category() == OpCategory::Read {
                    continue;
                }
                let Some(need) = required_counterpart(op.name()) else {
                    continue;
                };
                assert!(
                    possible_names(&scan).contains(&need)
                        || scan.completeness == ScanCompleteness::LexicallyIncomplete,
                    "{file}: AST op {} invisible to defensive scan of {sql:?}",
                    op.name()
                );
            }
        }
    }
    assert!(checked > 40, "must cover the corpus, saw {checked}");
}

#[test]
fn scanner_cannot_alter_ast_facts() {
    // The scanner borrows `&str` and returns owned evidence; analyzing
    // before and after must be identical, and `read_only == false` can
    // never flip back regardless of defensive output.
    for sql in [
        "DELETE FROM customers",
        "SELECT 1; DROP TABLE users",
        "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d",
        "SELECT password_hash FROM users",
    ] {
        let before = analyze(sql, "postgres").expect("parse");
        let scan = defensive_scan(sql, SqlDialect::PostgreSql);
        let after = analyze(sql, "postgres").expect("parse");
        assert_eq!(before, after, "scan must not alter analysis of {sql:?}");
        if !before.read_only {
            assert!(!after.read_only, "{sql:?} stays non-read");
            let _ = scan;
        }
    }
}

#[test]
fn ast_failure_plus_select_only_stays_failure() {
    // The forbidden transformation (error + possible Select = safe) is
    // unrepresentable: `analysis` remains `Err` no matter what the scan saw.
    // Garbage with no keywords: empty defensive evidence still cannot heal
    // the AST failure.
    let inspection = SqlInspection::inspect("FROBNICATE THE customers !!", SqlDialect::PostgreSql);
    assert!(inspection.ast_failed());
    assert!(inspection.defensive.possible_operations.is_empty());
    // Failures that do mention SELECT: still failed, still not safe.
    for sql in ["SELECT 'unterminated", "WITH x AS (DELETE FROM t) SELECT"] {
        let inspection = SqlInspection::inspect(sql, SqlDialect::PostgreSql);
        assert!(inspection.ast_failed(), "{sql:?} must stay failed");
        assert!(
            inspection
                .defensive
                .possible_operations
                .contains(&PossibleOperation::Select)
                || inspection.defensive.completeness == ScanCompleteness::LexicallyIncomplete,
            "{sql:?}"
        );
        // No API exists to recover safety from this state: assert the only
        // safety-bearing field still denies confidence.
        if let Ok(analysis) = &inspection.analysis {
            assert!(
                !analysis.read_only || analysis.completeness == AnalysisCompleteness::Complete,
                "{sql:?}"
            );
        }
    }
}

#[test]
fn inspection_bundle_runs_both_layers() {
    let inspection = SqlInspection::inspect("SELECT 1; DROP TABLE users", SqlDialect::PostgreSql);
    assert!(!inspection.ast_failed());
    let mut ops: Vec<&str> = inspection
        .analysis
        .expect("parse")
        .operations
        .iter()
        .map(|o| o.name())
        .collect();
    ops.sort_unstable();
    assert_eq!(ops, vec!["drop", "select"]);
    assert!(inspection
        .defensive
        .possible_operations
        .contains(&PossibleOperation::Drop));
    assert!(inspection
        .defensive
        .signals
        .contains(&DefensiveSignal::MultipleStatements));
}

// ---------------------------------------------------------------------------
// Differential: AST vs defensive on valid SQL.
// ---------------------------------------------------------------------------

#[test]
fn differential_valid_sql() {
    // (sql, dialect, AST ops, defensive must-contain). Disagreements below
    // are documented, never "fixed" by weakening the AST.
    const PG: SqlDialect = SqlDialect::PostgreSql;
    let cases = [
        (
            "SELECT id FROM users WHERE id = 1",
            PG,
            vec!["select"],
            vec!["select"],
        ),
        (
            "INSERT INTO t (a) VALUES (1)",
            PG,
            vec!["insert"],
            vec!["insert"],
        ),
        (
            "UPDATE t SET a = 1 WHERE b = 2",
            PG,
            vec!["update"],
            vec!["update"],
        ),
        (
            "DELETE FROM t WHERE b = 2",
            PG,
            vec!["delete"],
            vec!["delete"],
        ),
        (
            "MERGE INTO a USING b ON a.id = b.id WHEN MATCHED THEN UPDATE SET x = 1",
            PG,
            vec!["merge", "update"],
            vec!["merge", "update"],
        ),
        ("DROP TABLE t", PG, vec!["drop"], vec!["drop"]),
        ("COPY t FROM '/x'", PG, vec!["copy"], vec!["copy"]),
        ("VACUUM t", PG, vec!["vacuum"], vec!["vacuum"]),
        ("CALL p()", PG, vec!["call"], vec!["call"]),
        (
            "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d",
            PG,
            vec!["delete", "select"],
            vec!["delete", "select"],
        ),
        (
            "SELECT 1; DROP TABLE t",
            PG,
            vec!["drop", "select"],
            vec!["drop", "select"],
        ),
        // EXPLAIN: AST op is Explain; defensive sees the inner statement.
        (
            "EXPLAIN UPDATE t SET a = 1",
            PG,
            vec!["explain", "update"],
            vec!["update"],
        ),
        // VALUES list: AST sees a read; the scanner sees no SELECT
        // keyword. Missing a read is safe (reads carry no risk).
        ("VALUES (1, 2), (3, 4)", PG, vec!["select"], vec![]),
    ];
    for (sql, dialect, want_ops, want_possible) in cases {
        let inspection = SqlInspection::inspect(sql, dialect);
        assert!(!inspection.ast_failed(), "{sql:?} must parse");
        let analysis = inspection.analysis.expect("parse");
        let mut ops: Vec<&str> = analysis.operations.iter().map(|o| o.name()).collect();
        ops.sort_unstable();
        let mut want = want_ops.clone();
        want.sort_unstable();
        assert_eq!(ops, want, "{sql:?} AST ops");
        for p in want_possible {
            assert!(
                possible_names(&inspection.defensive).contains(&p),
                "{sql:?} defensive misses {p}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Adversarial extras beyond fixtures.
// ---------------------------------------------------------------------------

#[test]
fn adversarial_scanner_cases() {
    let pg = SqlDialect::PostgreSql;
    // Escaped quote stays inside the string.
    let s = defensive_scan("SELECT 'it''s DROP'", pg);
    assert!(!possible_names(&s).contains(&"drop"));
    // Unterminated backtick identifier: incomplete, never confident.
    let s = defensive_scan("SELECT `abc", SqlDialect::MySql);
    assert_eq!(s.completeness, ScanCompleteness::LexicallyIncomplete);
    assert!(s
        .possible_operations
        .contains(&PossibleOperation::UnknownWrite));
    // `$` alone is not a word and not a quote.
    let s = defensive_scan("SELECT $", pg);
    assert_eq!(s.completeness, ScanCompleteness::Complete);
    assert!(s
        .possible_operations
        .iter()
        .all(|o| *o == PossibleOperation::Select));
    // Huge bounded input stays linear and panic-free.
    let big = format!("SELECT {} FROM t WHERE {}", "a, ".repeat(20_000), "1 = 1");
    let s = defensive_scan(&big, pg);
    assert!(possible_names(&s).contains(&"select"));
    assert_eq!(s.completeness, ScanCompleteness::Complete);
    // 64 KiB of hostile keywords: still just evidence.
    let hostile = "DROP TABLE t; ".repeat(4_000);
    assert!(hostile.len() < 64 * 1024);
    let s = defensive_scan(&hostile, pg);
    assert!(s.possible_operations.contains(&PossibleOperation::Drop));
    assert!(s.signals.contains(&DefensiveSignal::MultipleStatements));
    assert!(s.statement_boundaries >= 4_000);
}
