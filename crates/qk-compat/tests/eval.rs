//! Evaluator parity: frozen evaluation fixtures vs `qk_core::evaluate`
//! (parity test, no external processes) plus a differential comparison
//! against the TypeScript oracle via the reference runner dump (needs `bun`;
//! skipped gracefully without it).
//!
//! Applicability: approval *resolution* cases (approved/denied/throws/
//! missing-provider) and the observe-mode case belong to later layers
//! (provider protocol, omitted observe mode) and are pinned as deferred.
//! Two shared fixtures diverge deliberately and are pinned with their
//! documented Rust outcomes:
//! - "data-modifying CTE fails closed on parse": oracle cannot parse
//!   (DENY_PARSE_ERROR); Rust sees the nested DELETE and holds it for
//!   approval like a directly visible bounded DELETE (REQUIRE_APPROVAL).
//! - "merge into fails closed": oracle cannot parse (DENY_PARSE_ERROR);
//!   Rust parses MERGE and falls through to default deny (DEFAULT_DENY).

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use qk_core::{
    evaluate, parse_policy, Decision, EvaluateOptions, EvaluationRequest, ExecutionContext,
    PolicyDecision, PolicyFile,
};

const EVAL_FILES: &[&str] = &[
    "policy-evaluation.cases.json",
    "sensitive-columns.cases.json",
    "unbounded-mutations.cases.json",
    "multistatement-nested.cases.json",
    "malformed-unsupported.cases.json",
    "approvals-rowlimits.cases.json",
    "evaluation-rust.cases.json",
];

/// Shared files where the oracle is expected to agree with Rust (modulo
/// pinned divergences). Rust-only files assert Rust behavior alone.
const SHARED_EVAL_FILES: &[&str] = &[
    "policy-evaluation.cases.json",
    "sensitive-columns.cases.json",
    "unbounded-mutations.cases.json",
    "multistatement-nested.cases.json",
    "malformed-unsupported.cases.json",
    "approvals-rowlimits.cases.json",
];

/// Approval-resolution cases unlocked by the approval layer: the harness
/// maps each fixture `approval` value onto a provider (approved, denied,
/// waiting, throws, missing) and resolves through `qk_approval::resolve`.
fn resolve_approval(
    file: &str,
    name: &str,
    approval: &str,
    evaluation: &qk_core::EvaluationResult,
    context: &qk_core::ExecutionContext,
    dialect: qk_sql::SqlDialect,
    sql: &str,
) -> (String, String) {
    use qk_approval::{
        ErrorProvider, InMemoryApprovalStore, ProviderDecision, TestProvider, UnavailableProvider,
        DEFAULT_APPROVAL_TTL_MS,
    };
    let store = InMemoryApprovalStore::new();
    let approved = TestProvider::new(vec![ProviderDecision::Approved]);
    let denied = TestProvider::new(vec![ProviderDecision::Denied]);
    let waiting = TestProvider::new(vec![ProviderDecision::Waiting]);
    let erroring = ErrorProvider::new("paged human, got voicemail");
    let unavailable = UnavailableProvider;
    let provider: Option<&dyn qk_approval::ApprovalProvider> = match approval {
        "approved" => Some(&approved),
        "denied" => Some(&denied),
        "waiting" | "none" => Some(&waiting),
        "throws" => Some(&erroring),
        "unavailable" => Some(&unavailable),
        "missing-provider" => None,
        other => panic!("{file}::{name}: unknown approval mode {other}"),
    };
    let resolved = qk_approval::resolve(
        &qk_approval::ResolveRequest {
            evaluation,
            context,
            dialect,
            sql,
            params: &[],
            approval_id: None,
            ttl_ms: DEFAULT_APPROVAL_TTL_MS,
            now_ms: 1_000,
        },
        &store,
        provider,
    );
    (
        resolved.decision.as_str().to_owned(),
        resolved.reason_code.as_str().to_owned(),
    )
}

/// Observe mode is omitted (no product caller in the reference); the
/// corpus fixture documents evaluate() API behavior only.
const DEFERRED_OBSERVE: &[&str] = &["observe mode downgrades denial to allow"];

/// Deliberate divergences: name -> (decision, reason_code).
fn divergent(name: &str) -> Option<(&'static str, &'static str)> {
    match name {
        // The fixture's DELETE has no WHERE: nested unbounded protection
        // denies exactly like a directly visible unbounded DELETE.
        "data-modifying CTE fails closed on parse" => Some(("deny", "UNBOUNDED_DELETE")),
        // The MERGE carries an UPDATE branch: nested operations
        // participate in rules, so the approval rule for updates holds it
        // (never Allow; never a plain read).
        "merge into fails closed" => Some(("require_approval", "REQUIRE_APPROVAL")),
        _ => None,
    }
}

fn compat_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/compatibility")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The historical TypeScript implementation, when it is checked out.
///
/// The differential comparison is an owner/developer check: it needs the
/// separately maintained reference implementation, which is not part of this
/// repository. It is skipped, not failed, when that checkout is unavailable, so
/// `cargo test` works from a standalone public checkout.
fn typescript_reference_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("QUERYKNIGHT_TS_DIR")
        .map_or_else(|| workspace_root().join("../queryknight-ts"), PathBuf::from);
    let entry = dir
        .join("packages")
        .join("core")
        .join("src")
        .join("index.ts");
    entry.is_file().then_some(dir)
}

fn read_json(file: &str) -> Vec<serde_json::Value> {
    let text =
        fs::read_to_string(compat_dir().join(file)).unwrap_or_else(|e| panic!("read {file}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {file}: {e}"))
}

fn str_field(case: &serde_json::Value, key: &str) -> Option<String> {
    case.get(key).and_then(|v| v.as_str()).map(str::to_owned)
}

fn expand_generated(sql: &str) -> String {
    match sql {
        "CHAIN_200" => "SELECT 1".to_owned() + &" + 1".repeat(200),
        "NEST_2000" => {
            let mut sql = String::from("SELECT 1");
            for i in 0..2000 {
                sql = format!("SELECT * FROM ({sql}) t{i}");
            }
            sql
        }
        _ => sql.to_owned(),
    }
}

fn default_policy() -> PolicyFile {
    parse_policy("version: 1\ndefaults:\n  decision: deny\n").expect("default policy")
}

fn load_policy(case: &serde_json::Value, file: &str) -> PolicyFile {
    if let Some(yaml) = case.get("policy_yaml") {
        if yaml.is_null() {
            return default_policy();
        }
        let text = yaml
            .as_str()
            .unwrap_or_else(|| panic!("{file}: bad policy_yaml"));
        return parse_policy(text).unwrap_or_else(|e| panic!("{file}: invalid policy: {e}"));
    }
    let rel = str_field(case, "policy").unwrap_or_else(|| panic!("{file}: case has no policy"));
    let text =
        fs::read_to_string(compat_dir().join(&rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"));
    parse_policy(&text).unwrap_or_else(|e| panic!("{file}: invalid policy: {e}"))
}

struct Evaluated {
    evaluation: qk_core::EvaluationResult,
    context: qk_core::ExecutionContext,
    dialect: qk_sql::SqlDialect,
    sql: String,
    approval: String,
}

fn rust_evaluate(file: &str, case: &serde_json::Value) -> Evaluated {
    let name = str_field(case, "name").unwrap_or_else(|| panic!("{file}: nameless case"));
    let policy = load_policy(case, file);
    let ctx_value = case.get("context").cloned().unwrap_or_default();
    let context = ExecutionContext {
        integration: ctx_value
            .get("integration")
            .and_then(|v| v.as_str())
            .unwrap_or("cli")
            .to_owned(),
        environment: ctx_value
            .get("environment")
            .and_then(|v| v.as_str())
            .unwrap_or("production")
            .to_owned(),
        database: ctx_value
            .get("database")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        agent_id: ctx_value
            .get("agent_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        tool: ctx_value
            .get("tool")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        session_id: ctx_value
            .get("session_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
    };
    let dialect: qk_sql::SqlDialect = str_field(case, "dialect")
        .unwrap_or_else(|| "postgres".to_owned())
        .parse()
        .unwrap_or_else(|e| panic!("{file} {name}: bad dialect: {e}"));
    let sql = expand_generated(
        &str_field(case, "sql").unwrap_or_else(|| panic!("{file} {name}: no sql")),
    );
    let options = EvaluateOptions {
        max_bytes: case
            .get("max_sql_bytes")
            .and_then(|v| v.as_u64())
            .map_or(qk_sql::MAX_SQL_BYTES, |n| n as usize),
    };
    let approval = case
        .get("approval")
        .and_then(|v| v.as_str())
        .unwrap_or("none")
        .to_owned();
    let result = evaluate(
        &EvaluationRequest {
            context: &context,
            dialect,
            sql: &sql,
            policy: &policy,
        },
        &options,
    );
    Evaluated {
        evaluation: result,
        dialect,
        context,
        sql,
        approval,
    }
}

fn is_eval_case(case: &serde_json::Value) -> bool {
    case.get("expected")
        .and_then(|e| e.get("decision"))
        .and_then(|v| v.as_str())
        .is_some()
        && case.get("sql").and_then(|v| v.as_str()).is_some()
}

#[test]
fn evaluator_parity_with_frozen_fixtures() {
    let mut applied = 0u32;
    let mut deferred = Vec::new();
    let mut diverged = Vec::new();
    for file in EVAL_FILES {
        for case in read_json(file) {
            if !is_eval_case(&case) {
                continue;
            }
            let name = str_field(&case, "name").unwrap_or_else(|| panic!("{file}: nameless"));
            if DEFERRED_OBSERVE.contains(&name.as_str()) {
                deferred.push(format!("{file}::{name}"));
                continue;
            }
            let got = rust_evaluate(file, &case);
            let (decision, reason) = resolve_approval(
                file,
                &name,
                &got.approval,
                &got.evaluation,
                &got.context,
                got.dialect,
                &got.sql,
            );
            if let Some((want_decision, want_reason)) = divergent(&name) {
                assert_eq!(decision, want_decision, "{file}::{name} divergent decision");
                assert_eq!(reason, want_reason, "{file}::{name} divergent reason");
                diverged.push(format!("{file}::{name}"));
                continue;
            }
            let exp = case.get("expected").expect("expected");
            let want_decision = exp
                .get("decision")
                .and_then(|v| v.as_str())
                .expect("decision");
            let want_reason = exp
                .get("reason_code")
                .and_then(|v| v.as_str())
                .expect("reason");
            assert_eq!(decision, want_decision, "{file}::{name} decision");
            assert_eq!(reason, want_reason, "{file}::{name} reason");
            applied += 1;
        }
    }
    assert_eq!(
        deferred,
        DEFERRED_OBSERVE
            .iter()
            .map(|n| format!("policy-evaluation.cases.json::{n}"))
            .collect::<Vec<_>>(),
        "deferred set must stay pinned"
    );
    assert_eq!(
        diverged.len(),
        2,
        "divergent set must stay pinned: {diverged:?}"
    );
    assert_eq!(
        applied, 52,
        "applied count must stay pinned, applied={applied}"
    );
    println!(
        "parity: {applied} applied, {} deferred, {} divergent",
        deferred.len(),
        diverged.len()
    );
}

#[test]
fn differential_against_typescript_oracle() {
    // Owner/developer check: needs the separately maintained reference
    // implementation, which is not part of this repository.
    let Some(reference) = typescript_reference_dir() else {
        println!(
            "queryknight-ts checkout unavailable; differential skipped \
             (set QUERYKNIGHT_TS_DIR to run it; the parity test still guards the fixtures)"
        );
        return;
    };
    if Command::new("bun").arg("--version").output().is_err() {
        println!("bun unavailable; differential skipped (parity test still guards fixtures)");
        return;
    }
    let output = Command::new("bun")
        .arg("tools/reference-runner/run.ts")
        .arg("--dump")
        .current_dir(workspace_root())
        .env("QUERYKNIGHT_TS_DIR", &reference)
        .output()
        .expect("run reference dump");
    assert!(output.status.success(), "reference dump failed");
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).expect("parse dump");
    let mut compared = 0u32;
    let mut oracle_sanity = 0u32;
    for row in &rows {
        let file = row.get("file").and_then(|v| v.as_str()).unwrap_or("");
        let name = row.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if !SHARED_EVAL_FILES.contains(&file) {
            continue;
        }
        if DEFERRED_OBSERVE.contains(&name) {
            continue;
        }
        let ts_decision = row.get("decision").and_then(|v| v.as_str()).unwrap_or("?");
        let ts_reason = row
            .get("reason_code")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        if divergent(name).is_some() {
            // Oracle must still match the frozen expectation (no drift);
            // Rust follows the documented divergence (proven in parity test).
            let case = read_json(file)
                .into_iter()
                .find(|c| c.get("name").and_then(|v| v.as_str()) == Some(name))
                .expect("fixture");
            let exp = case.get("expected").expect("expected");
            assert_eq!(
                ts_decision,
                exp.get("decision").and_then(|v| v.as_str()).unwrap_or("?")
            );
            assert_eq!(
                ts_reason,
                exp.get("reason_code")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
            );
            oracle_sanity += 1;
            continue;
        }
        let case = read_json(file)
            .into_iter()
            .find(|c| c.get("name").and_then(|v| v.as_str()) == Some(name))
            .expect("fixture");
        let got = rust_evaluate(file, &case);
        let (decision, reason) = resolve_approval(
            file,
            name,
            &got.approval,
            &got.evaluation,
            &got.context,
            got.dialect,
            &got.sql,
        );
        assert_eq!(decision, ts_decision, "{file}::{name} decision vs oracle");
        assert_eq!(reason, ts_reason, "{file}::{name} reason vs oracle");
        compared += 1;
    }
    assert_eq!(
        compared, 40,
        "compared count must stay pinned, compared={compared}"
    );
    println!("differential: {compared} Rust==TS, {oracle_sanity} oracle-sanity on divergences");
}

#[test]
fn reason_code_decision_serialization() {
    assert_eq!(Decision::Allow.as_str(), "allow");
    assert_eq!(Decision::Deny.as_str(), "deny");
    assert_eq!(Decision::RequireApproval.as_str(), "require_approval");
    // The 20-code frozen set is pinned in qk-core's decision unit test;
    // here we pin the harness surface re-exports resolve.
    let _: PolicyDecision = PolicyDecision::Deny;
    assert_eq!(qk_core::ReasonCode::DefaultDeny.as_str(), "DEFAULT_DENY");
}
