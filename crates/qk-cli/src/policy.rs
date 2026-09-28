//! `queryknight policy validate` and `queryknight policy test`, wired to
//! the real loader and evaluator. No second policy engine lives here.

use std::path::PathBuf;

use qk_core::{
    evaluate, parse_policy, parse_test_cases, EvaluateOptions, EvaluationRequest, ExecutionContext,
    PolicyFile, PolicyTestCase,
};

fn load_policy_file(path: &PathBuf) -> Result<PolicyFile, i32> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        eprintln!("cannot read policy {}: {e}", path.display());
        2
    })?;
    parse_policy(&text).map_err(|e| {
        eprintln!("invalid policy {}: {e}", path.display());
        2
    })
}

/// Validate a policy file: exit 0 with a summary, or exit 2 with usage or
/// validation errors on stderr.
pub fn validate(file: Option<PathBuf>) -> i32 {
    let Some(path) = file else {
        eprintln!("usage: queryknight policy validate <policy.yaml>");
        return 2;
    };
    let policy = match load_policy_file(&path) {
        Ok(policy) => policy,
        Err(code) => return code,
    };
    let databases = policy
        .environments
        .values()
        .flat_map(|env| env.databases.keys())
        .count();
    let tests = policy.tests.len();
    println!(
        "policy {}: valid (version 1, {databases} database scope(s), {tests} embedded test(s))",
        path.display()
    );
    0
}

/// Run policy test cases through the real evaluator. Exit 0 when all pass,
/// 1 when any fail, 2 on usage or invalid inputs.
pub fn test(
    policy_path: Option<PathBuf>,
    cases_path: Option<PathBuf>,
    dialect: Option<String>,
    env: Option<String>,
    db: Option<String>,
) -> i32 {
    let Some(policy_arg) = policy_path else {
        eprintln!("usage: queryknight policy test <policy.yaml> [cases.yaml]");
        return 2;
    };
    let policy = match load_policy_file(&policy_arg) {
        Ok(policy) => policy,
        Err(code) => return code,
    };
    let mut cases: Vec<PolicyTestCase> = policy.tests.clone();
    if let Some(path) = cases_path {
        let text = std::fs::read_to_string(&path).map_err(|e| {
            eprintln!("invalid cases file: cannot read {}: {e}", path.display());
            2
        });
        let text = match text {
            Ok(text) => text,
            Err(code) => return code,
        };
        match parse_test_cases(&text) {
            Ok(parsed) => cases = parsed,
            Err(e) => {
                eprintln!("invalid cases file: {e}");
                return 2;
            }
        }
    }
    if cases.is_empty() {
        eprintln!("no test cases: embed `tests:` in the policy or pass a cases file");
        return 2;
    }
    let default_dialect = dialect.unwrap_or_else(|| "postgres".to_owned());
    let default_env = env.unwrap_or_else(|| "production".to_owned());
    let default_db = db.unwrap_or_else(|| "main".to_owned());
    let mut failed = 0u32;
    for case in &cases {
        let dialect: qk_sql::SqlDialect = match case
            .dialect
            .clone()
            .unwrap_or_else(|| default_dialect.clone())
            .parse()
        {
            Ok(dialect) => dialect,
            Err(e) => {
                eprintln!("invalid test case {}: {e}", case.name);
                return 2;
            }
        };
        let context = ExecutionContext {
            integration: case.integration.clone().unwrap_or_else(|| "cli".to_owned()),
            environment: case.environment.clone().unwrap_or(default_env.clone()),
            database: Some(case.database.clone().unwrap_or_else(|| default_db.clone())),
            agent_id: case.agent_id.clone(),
            tool: None,
            session_id: None,
        };
        // No approval provider: approval-gated cases surface as
        // RequireApproval, exactly what the fixtures assert.
        let result = evaluate(
            &EvaluationRequest {
                context: &context,
                dialect,
                sql: &case.sql,
                policy: &policy,
            },
            &EvaluateOptions::default(),
        );
        let decision_ok = result.decision.as_str() == case.expect.as_str();
        let reason_ok = case
            .reason
            .as_ref()
            .is_none_or(|reason| result.reason_code.as_str() == reason);
        if decision_ok && reason_ok {
            println!("PASS {} ({})", case.name, result.reason_code.as_str());
        } else {
            failed += 1;
            let want_reason = case
                .reason
                .as_ref()
                .map(|r| format!("/{r}"))
                .unwrap_or_default();
            println!(
                "FAIL {}: expected {}{}, got {}/{} ({})",
                case.name,
                case.expect.as_str(),
                want_reason,
                result.decision.as_str(),
                result.reason_code.as_str(),
                result.message,
            );
        }
    }
    println!("{}/{} passed", cases.len() - failed as usize, cases.len());
    if failed > 0 {
        1
    } else {
        0
    }
}
