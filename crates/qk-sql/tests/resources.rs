//! Resource hardening: explicit parser recursion limit, guarded AST
//! destruction, completeness semantics, <=64 KiB hostile battery, and
//! concurrent hostile analyses. std threads only; no Tokio.

use std::path::PathBuf;

use qk_sql::{
    analyze, AnalysisCompleteness, Operation, RiskSignal, SqlAnalysisError, MAX_SQL_BYTES,
    SQL_PARSER_RECURSION_LIMIT,
};

/// 2 MiB worker: proves no giant per-request stack is needed. Tokio workers
/// and libtest threads share this order of magnitude.
const SMALL_STACK: usize = 2 * 1024 * 1024;

/// Production SQL input boundary under test: 64 KiB.
const PRODUCTION_BYTES: usize = 64 * 1024;

fn on_small_stack<F, R>(f: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    std::thread::Builder::new()
        .stack_size(SMALL_STACK)
        .spawn(f)
        .expect("spawn small-stack worker")
        .join()
        .expect("worker must not panic")
}

fn chain(n: usize) -> String {
    "SELECT 1".to_owned() + &" + 1".repeat(n)
}

fn parens(n: usize) -> String {
    format!("SELECT {}1{}", "(".repeat(n), ")".repeat(n))
}

fn subqueries(n: usize) -> String {
    let mut sql = String::from("SELECT 1");
    for i in 0..n {
        sql = format!("SELECT * FROM ({sql}) t{i}");
    }
    sql
}

fn nested_functions(n: usize) -> String {
    format!("SELECT {}1{}", "abs(".repeat(n), ")".repeat(n))
}

fn nested_case(n: usize) -> String {
    let mut sql = String::from("0");
    for _ in 0..n {
        sql = format!("CASE WHEN 1 > 0 THEN {sql} ELSE -1 END");
    }
    format!("SELECT {sql} FROM t")
}

// ---------------------------------------------------------------------------
// 1+5. Recursion limit active; protection crates in the build.
// ---------------------------------------------------------------------------

#[test]
fn recursion_limit_rejects_nesting_with_typed_error() {
    assert_eq!(SQL_PARSER_RECURSION_LIMIT, 50);
    let err = analyze(&subqueries(300), "postgres").expect_err("must be bounded");
    assert_eq!(err, SqlAnalysisError::ComplexityLimitExceeded { limit: 50 });
    assert_eq!(
        err.to_string(),
        "SQL complexity exceeds the analysis limit (50)"
    );
}

#[test]
fn recursion_protection_in_build() {
    // Dependency inspection: `recursive-protection` (default-on) resolves to
    // the `recursive` + `stacker` crates in the compiled graph, and the
    // parser dependency stays pinned.
    let lock = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock");
    let text = std::fs::read_to_string(&lock).expect("read Cargo.lock");
    for probe in [
        "name = \"sqlparser\"\nversion = \"0.63.0\"",
        "name = \"recursive\"",
        "name = \"stacker\"",
        "name = \"recursive-proc-macro-impl\"",
    ] {
        assert!(text.contains(probe), "Cargo.lock must contain {probe}");
    }
    // Behavioral proof the counter is live: shallow nesting passes.
    let ok = analyze(&subqueries(5), "postgres").expect("shallow must parse");
    assert_eq!(ok.completeness, AnalysisCompleteness::Complete);
}

// ---------------------------------------------------------------------------
// 4+6. Walk/drop bounded; truncation explicit and never read-only.
// ---------------------------------------------------------------------------

#[test]
fn deep_chain_truncates_explicitly_on_small_stack() {
    // 200 operator levels: parser counter is blind to chains, the capped
    // walk must surface DepthTruncated and withhold any read-only claim.
    let a = on_small_stack(|| analyze(&chain(200), "postgres").expect("must analyze"));
    assert_eq!(a.completeness, AnalysisCompleteness::DepthTruncated);
    assert!(!a.read_only);
    assert!(a.risk_signals.contains(&RiskSignal::DepthTruncated));
}

#[test]
fn complete_read_stays_confident() {
    let a = analyze("SELECT id, name FROM users WHERE id = 1", "postgres").expect("parse");
    assert_eq!(a.completeness, AnalysisCompleteness::Complete);
    assert!(a.read_only);
}

#[test]
fn drop_of_deep_tree_safe_on_small_stack() {
    // 25k levels aborted a bare 2 MiB thread pre-fix (measured). The guarded
    // destruction must survive it.
    let sql = chain(25_000);
    let a = on_small_stack(move || analyze(&sql, "postgres").expect("must analyze"));
    assert_eq!(a.statements[0].operation, Operation::Select);
    assert_eq!(a.completeness, AnalysisCompleteness::DepthTruncated);
}

// ---------------------------------------------------------------------------
// 7. Hostile battery within the 64 KiB production boundary.
// ---------------------------------------------------------------------------

fn assert_bounded(label: &str, sql: String) {
    assert!(sql.len() <= PRODUCTION_BYTES, "{label} exceeds 64 KiB");
    let outcome = on_small_stack(move || match analyze(&sql, "postgres") {
        Ok(a) => format!(
            "ok complete={:?} ops={}",
            a.completeness,
            a.operations.len()
        ),
        Err(e) => format!("err {e}"),
    });
    assert!(
        outcome.starts_with("ok") || outcome.starts_with("err"),
        "{label}: unexpected outcome {outcome}"
    );
    println!("{label}: {outcome}");
}

#[test]
fn hostile_battery_within_production_budget() {
    assert_bounded("chain-16k", chain(16_000));
    assert_bounded("parens-20k", parens(20_000));
    assert_bounded("subqueries-1500", subqueries(1_500));
    assert_bounded("functions-8k", nested_functions(8_000));
    assert_bounded("case-1200", nested_case(1_200));
    assert_bounded(
        "combo",
        format!(
            "WITH a AS ({}) SELECT {} FROM a WHERE {}",
            subqueries(200),
            "abs(".repeat(500) + "1" + &")".repeat(500),
            (0..300)
                .map(|i| format!("x{i} = {i}"))
                .collect::<Vec<_>>()
                .join(" AND ")
        ),
    );
}

#[test]
fn production_budget_holds_max_sql_bytes_contract() {
    const { assert!(PRODUCTION_BYTES < MAX_SQL_BYTES) }
    assert_eq!(MAX_SQL_BYTES, 1_000_000);
}

// ---------------------------------------------------------------------------
// 9. Concurrent hostile analyses.
// ---------------------------------------------------------------------------

#[test]
fn concurrent_hostile_analyses() {
    let inputs = [
        chain(16_000),
        parens(20_000),
        subqueries(1_500),
        nested_case(1_200),
        "SELECT id FROM users WHERE id = 1".to_owned(),
        "UPDATE t SET a = 1 WHERE b = 2; DROP TABLE t".to_owned(),
    ];
    let mut handles = Vec::new();
    for round in 0..4 {
        for (i, sql) in inputs.iter().enumerate() {
            let sql = sql.clone();
            handles.push(
                std::thread::Builder::new()
                    .name(format!("hostile-{round}-{i}"))
                    .stack_size(SMALL_STACK)
                    .spawn(move || match analyze(&sql, "postgres") {
                        Ok(a) => format!("ok {:?}", a.completeness),
                        Err(e) => format!("err {e}"),
                    })
                    .expect("spawn"),
            );
        }
    }
    let mut ok = 0u32;
    let mut err = 0u32;
    for h in handles {
        match h.join() {
            Ok(o) if o.starts_with("ok") => ok += 1,
            Ok(o) if o.starts_with("err") => err += 1,
            other => panic!("unexpected worker outcome: {other:?}"),
        }
    }
    assert_eq!(ok + err, 24, "all 24 workers must report deterministically");
    assert!(
        ok > 0 && err > 0,
        "battery must mix analyses and typed errors"
    );
}
