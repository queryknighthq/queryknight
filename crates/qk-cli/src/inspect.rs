//! `queryknight inspect`: evaluate SQL against a policy through the real
//! Rust evaluator. Evaluation-only: approvals surface as
//! `REQUIRE_APPROVAL`, never resolved here.

use std::io::IsTerminal as _;
use std::path::PathBuf;

use qk_core::{
    evaluate, parse_policy, Decision, EvaluateOptions, EvaluationRequest, ExecutionContext,
    PolicyFile,
};

/// Demo policy used when `--policy` is absent. Mirrors the reference demo
/// posture (production `main` with read allows, destructive denies, write
/// approvals, sensitive columns, unbounded-mutation and row guards) so the
/// CLI is useful without a policy file. Real deployments pass `--policy`.
const DEMO_POLICY: &str = "version: 1
defaults:
  decision: deny
environments:
  production:
    databases:
      main:
        allow:
          - operations: [select, show, describe, explain]
        deny:
          - operations: [drop, truncate, grant, revoke]
        approval_required:
          - operations: [insert, update, delete, create, alter]
        sensitive:
          columns:
            - users.password_hash
            - users.mfa_secret
            - payments.card_token
            - customers.ssn
            - \"*.api_key\"
            - \"*.secret\"
            - \"*.access_token\"
        mutations:
          deny_without_where: [update, delete]
        row_safety:
          max_limit: 1000
";

/// Parsed inspect arguments (adapted from CLI syntax into core APIs).
pub struct InspectArgs {
    /// SQL dialect name.
    pub dialect: String,
    /// Policy file, or demo policy when absent.
    pub policy: Option<PathBuf>,
    /// JSON output.
    pub json: bool,
    /// Environment scope.
    pub env: Option<String>,
    /// Database scope.
    pub db: Option<String>,
    /// Agent identity.
    pub agent: Option<String>,
    /// Integration name.
    pub integration: Option<String>,
    /// Tool name.
    pub tool: Option<String>,
    /// Positional SQL fragments.
    pub sql: Vec<String>,
}

fn demo_policy() -> Result<PolicyFile, String> {
    parse_policy(DEMO_POLICY).map_err(|e| format!("internal demo policy invalid: {e}"))
}

fn load_policy(path: &PathBuf) -> Result<PolicyFile, i32> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        eprintln!("cannot read policy {}: {e}", path.display());
        2
    })?;
    parse_policy(&text).map_err(|e| {
        eprintln!("invalid policy {}: {e}", path.display());
        2
    })
}

fn read_stdin_if_piped() -> String {
    if std::io::stdin().is_terminal() {
        return String::new();
    }
    let mut input = String::new();
    match std::io::Read::read_to_string(&mut std::io::stdin(), &mut input) {
        Ok(_) => input.trim().to_owned(),
        Err(_) => String::new(),
    }
}

/// Run inspect; returns the process exit code.
pub fn run(args: InspectArgs) -> i32 {
    let dialect: qk_sql::SqlDialect = match args.dialect.parse() {
        Ok(dialect) => dialect,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let policy = match args.policy {
        Some(ref path) => match load_policy(path) {
            Ok(policy) => policy,
            Err(code) => return code,
        },
        None => match demo_policy() {
            Ok(policy) => policy,
            Err(message) => {
                eprintln!("{message}");
                return 1;
            }
        },
    };
    let sql = {
        let positional = args.sql.join(" ").trim().to_owned();
        if positional.is_empty() {
            read_stdin_if_piped()
        } else {
            positional
        }
    };
    if sql.is_empty() {
        eprintln!(
            "usage: queryknight inspect [--dialect postgres] [--policy policy.yaml] [--env production] [--db main] [--json] \"<SQL>\""
        );
        return 2;
    }
    let context = ExecutionContext {
        integration: args.integration.unwrap_or_else(|| "cli".to_owned()),
        environment: args.env.unwrap_or_else(|| "production".to_owned()),
        database: Some(args.db.unwrap_or_else(|| "main".to_owned())),
        agent_id: args.agent,
        tool: args.tool,
        session_id: None,
    };
    let result = evaluate(
        &EvaluationRequest {
            context: &context,
            dialect,
            sql: &sql,
            policy: &policy,
        },
        &EvaluateOptions::default(),
    );
    if args.json {
        print_json(&result, &sql, dialect);
    } else {
        println!("Decision: {}", result.decision.as_str().to_uppercase());
        println!("Reason: {}", result.reason_code.as_str());
        println!("Message: {}", result.message);
        if let Some(table) = &result.table {
            println!("Table: {table}");
        }
        if let Some(column) = &result.column {
            println!("Column: {column}");
        }
        if let Some(matched) = &result.matched_policy {
            println!("Matched policy: {matched}");
        }
        let signals = risk_signals(&sql, dialect);
        if !signals.is_empty() {
            println!("Risk signals: {}", signals.join(", "));
        }
    }
    if result.decision != Decision::Allow {
        3
    } else {
        0
    }
}

/// Display-only analysis for risk signals and JSON output. The verdict
/// above comes solely from `evaluate()`; this second parse never decides.
fn risk_signals(sql: &str, dialect: qk_sql::SqlDialect) -> Vec<String> {
    match qk_sql::analyze_with_options(
        sql,
        dialect,
        qk_sql::AnalyzeOptions {
            max_bytes: qk_sql::MAX_SQL_BYTES,
        },
    ) {
        Ok(analysis) => {
            let mut signals: Vec<String> = analysis
                .risk_signals
                .iter()
                .map(|s| s.name().to_owned())
                .collect();
            signals.sort();
            signals
        }
        Err(_) => Vec::new(),
    }
}

/// Stable machine-readable inspect output. Key order and 2-space pretty
/// printing mirror the reference shape; absent fields are omitted (never
/// `null`, never Debug representations).
#[derive(serde::Serialize)]
struct InspectJson<'a> {
    decision: String,
    reason_code: &'a str,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    matched_policy: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    table: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    column: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: &'a Option<String>,
    risk_signals: Vec<String>,
    fingerprint: &'a str,
}

fn print_json(result: &qk_core::EvaluationResult, sql: &str, dialect: qk_sql::SqlDialect) {
    let fingerprint = qk_core::sql_fingerprint(sql);
    let output = InspectJson {
        decision: result.decision.as_str().to_uppercase(),
        reason_code: result.reason_code.as_str(),
        message: &result.message,
        matched_policy: &result.matched_policy,
        table: &result.table,
        column: &result.column,
        operation: &result.operation,
        risk_signals: risk_signals(sql, dialect),
        fingerprint: fingerprint.as_str(),
    };
    match serde_json::to_string_pretty(&output) {
        Ok(text) => println!("{text}"),
        Err(_) => println!("{{\"decision\":\"{}\"}}", output.decision),
    }
}
