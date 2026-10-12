//! CLI integration tests against the real `queryknight` executable.
//! Pins exit codes (0/1/2/3), stdout/stderr routing, and output shapes.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

fn binary() -> Command {
    Command::cargo_bin("queryknight").expect("binary")
}

fn compat(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/compatibility")
        .join(name)
}

fn standard_policy() -> PathBuf {
    compat("policies/standard.yaml")
}

fn temp_file(name: &str, contents: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("qk-cli-{}-{}-{name}", std::process::id(), unique()));
    std::fs::write(&path, contents).expect("write temp file");
    path
}

fn unique() -> String {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    NEXT.fetch_add(1, Ordering::SeqCst).to_string()
}

const PASSING_CASES: &str = "tests:\n  - name: lookup\n    sql: SELECT id FROM public.customers LIMIT 5\n    expect: allow\n  - name: blocked\n    sql: DROP TABLE customers\n    expect: deny\n    reason: DENY_RULE\n";

const FAILING_CASES: &str =
    "tests:\n  - name: wrong\n    sql: DROP TABLE customers\n    expect: allow\n";

// ---------------------------------------------------------------------------
// Help / version / dispatch.
// ---------------------------------------------------------------------------

#[test]
fn help_flag() {
    binary()
        .arg("--help")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("queryknight"))
        .stdout(predicate::str::contains("inspect"));
}

#[test]
fn version_forms() {
    for args in [vec!["--version"], vec!["-v"], vec!["version"]] {
        binary()
            .args(&args)
            .assert()
            .code(0)
            .stdout(predicate::str::contains("QueryKnight 0.1.0"));
    }
}

#[test]
fn bare_invocation_is_help_exit_1() {
    binary()
        .assert()
        .code(1)
        .stdout(predicate::str::contains("queryknight"));
}

#[test]
fn unknown_command_is_help_exit_1() {
    binary()
        .arg("frobnicate")
        .assert()
        .code(1)
        .stdout(predicate::str::contains("queryknight"));
}

#[test]
fn unknown_flag_is_usage_exit_2() {
    binary()
        .args(["inspect", "--bogus", "SELECT 1"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("error"));
}

// ---------------------------------------------------------------------------
// inspect.
// ---------------------------------------------------------------------------

fn inspect_args(extra: &[&str]) -> Vec<String> {
    let mut args = vec![
        "inspect".to_owned(),
        "--dialect".to_owned(),
        "postgres".to_owned(),
        "--policy".to_owned(),
        standard_policy().display().to_string(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    args
}

#[test]
fn inspect_allow_exit_0() {
    binary()
        .args(inspect_args(&["SELECT id FROM public.customers LIMIT 5"]))
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Decision: ALLOW"))
        .stdout(predicate::str::contains("Reason: ALLOW_RULE"))
        .stdout(predicate::str::contains(
            "Matched policy: production.main.allow[0]",
        ));
}

#[test]
fn inspect_deny_exit_3() {
    binary()
        .args(inspect_args(&["DELETE FROM customers"]))
        .assert()
        .code(3)
        .stdout(predicate::str::contains("Decision: DENY"))
        .stdout(predicate::str::contains("Reason: UNBOUNDED_DELETE"))
        .stdout(predicate::str::contains("Table: customers"));
}

#[test]
fn inspect_approval_exit_3() {
    binary()
        .args(inspect_args(&["DELETE FROM customers WHERE id = 1"]))
        .assert()
        .code(3)
        .stdout(predicate::str::contains("Decision: REQUIRE_APPROVAL"))
        .stdout(predicate::str::contains("Reason: REQUIRE_APPROVAL"));
}

#[test]
fn inspect_malformed_exit_3() {
    binary()
        .args(inspect_args(&["FROBNICATE THE customers !!"]))
        .assert()
        .code(3)
        .stdout(predicate::str::contains("Decision: DENY"))
        .stdout(predicate::str::contains("Reason: DENY_PARSE_ERROR"));
}

#[test]
fn inspect_unknown_dialect_exit_2() {
    binary()
        .args([
            "inspect",
            "--dialect",
            "mssql",
            "--policy",
            &standard_policy().display().to_string(),
            "SELECT 1",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unsupported dialect"));
}

#[test]
fn inspect_missing_policy_exit_2() {
    binary()
        .args([
            "inspect",
            "--policy",
            "/nonexistent/policy.yaml",
            "SELECT 1",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot read policy"));
}

#[test]
fn inspect_invalid_policy_exit_2() {
    let path = temp_file(
        "bad-policy.yaml",
        "version: 1\ndefaults:\n  decision: maybe\n",
    );
    binary()
        .args([
            "inspect",
            "--policy",
            &path.display().to_string(),
            "SELECT 1",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid policy"));
}

#[test]
fn inspect_no_sql_exit_2() {
    binary()
        .args(["inspect", "--dialect", "postgres"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("usage: queryknight inspect"));
}

#[test]
fn inspect_stdin_pipe() {
    binary()
        .args(inspect_args(&[]))
        .write_stdin("SELECT id FROM public.customers LIMIT 5")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Decision: ALLOW"));
}

#[test]
fn inspect_json_shape() {
    let assert = binary()
        .args(inspect_args(&[
            "--json",
            "DELETE FROM customers WHERE id = 1",
        ]))
        .assert()
        .code(3);
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["decision"], "REQUIRE_APPROVAL");
    assert_eq!(value["reason_code"], "REQUIRE_APPROVAL");
    assert_eq!(value["operation"], "delete");
    assert!(value["fingerprint"].as_str().is_some_and(|s| s.len() == 16));
    assert!(value["message"].as_str().is_some());
}

#[test]
fn inspect_sensitive_reports_column() {
    binary()
        .args(inspect_args(&["SELECT password_hash FROM users LIMIT 1"]))
        .assert()
        .code(3)
        .stdout(predicate::str::contains("Column: password_hash"))
        .stdout(predicate::str::contains("Table: users"))
        .stdout(predicate::str::contains(
            "Matched policy: production.main.sensitive",
        ));
}

#[test]
fn inspect_oversized_sql_exit_3() {
    // Piped rather than argv: OS argument lists cap out well below the
    // 1 MiB QueryKnight budget, while stdin exercises the same path.
    let big = format!("SELECT 1 -- {}", "x".repeat(1_100_000));
    binary()
        .args(inspect_args(&[]))
        .write_stdin(big)
        .assert()
        .code(3)
        .stdout(predicate::str::contains("QUERY_TOO_LARGE"));
}

// ---------------------------------------------------------------------------
// policy validate.
// ---------------------------------------------------------------------------

#[test]
fn validate_valid() {
    binary()
        .args([
            "policy",
            "validate",
            &standard_policy().display().to_string(),
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains(
            "valid (version 1, 1 database scope(s), 0 embedded test(s))",
        ));
}

#[test]
fn validate_invalid() {
    let path = temp_file(
        "invalid.yaml",
        "version: 1\ndefaults:\n  decision: deny\nbossmode: true\n",
    );
    binary()
        .args(["policy", "validate", &path.display().to_string()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid policy"))
        .stderr(predicate::str::contains("unknown field 'bossmode'"));
}

#[test]
fn validate_missing_file() {
    binary()
        .args(["policy", "validate", "/nonexistent/x.yaml"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot read policy"));
}

#[test]
fn validate_no_arg() {
    binary()
        .args(["policy", "validate"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "usage: queryknight policy validate",
        ));
}

#[test]
fn policy_bare_is_usage_exit_1() {
    binary()
        .args(["policy"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("usage: queryknight policy"));
}

// ---------------------------------------------------------------------------
// policy test.
// ---------------------------------------------------------------------------

#[test]
fn policy_test_all_pass() {
    let cases = temp_file("passing.yaml", PASSING_CASES);
    binary()
        .args([
            "policy",
            "test",
            &standard_policy().display().to_string(),
            &cases.display().to_string(),
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("PASS lookup (ALLOW_RULE)"))
        .stdout(predicate::str::contains("2/2 passed"));
}

#[test]
fn policy_test_one_failure() {
    let cases = temp_file("failing.yaml", FAILING_CASES);
    binary()
        .args([
            "policy",
            "test",
            &standard_policy().display().to_string(),
            &cases.display().to_string(),
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains(
            "FAIL wrong: expected allow, got deny/DENY_RULE",
        ))
        .stdout(predicate::str::contains("0/1 passed"));
}

#[test]
fn policy_test_malformed_cases() {
    let cases = temp_file("malformed.yaml", "version: [1\n");
    binary()
        .args([
            "policy",
            "test",
            &standard_policy().display().to_string(),
            &cases.display().to_string(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid cases file"));
}

#[test]
fn policy_test_no_cases() {
    binary()
        .args(["policy", "test", &standard_policy().display().to_string()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("no test cases"));
}

#[test]
fn policy_test_no_policy() {
    binary()
        .args(["policy", "test"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("usage: queryknight policy test"));
}

#[test]
fn openshell_help_exposes_secure_serve_and_doctor_commands() {
    binary()
        .args(["openshell", "--help"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("serve"))
        .stdout(predicate::str::contains("doctor"));
    binary()
        .args(["openshell", "serve", "--help"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("--tls-cert"))
        .stdout(predicate::str::contains("--tls-key"))
        .stdout(predicate::str::contains("--gateway-id"))
        .stdout(predicate::str::contains("--audience"))
        .stdout(predicate::str::contains("--jwks-file"))
        .stdout(predicate::str::contains("--insecure-local"));
}

#[test]
fn openshell_serve_requires_authenticated_configuration_by_default() {
    let home = std::env::temp_dir().join(format!("qk-openshell-cli-{}", unique()));
    binary()
        .args([
            "openshell",
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--home",
            &home.display().to_string(),
        ])
        .env_remove("DATABASE_URL")
        .env_remove("MYSQL_URL")
        .env_remove("QUERYKNIGHT_DAEMON_URL")
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "authenticated OpenShell mode requires --tls-cert",
        ));
}

#[test]
fn openshell_doctor_is_local_and_does_not_echo_database_credentials() {
    let home = std::env::temp_dir().join(format!("qk-openshell-doctor-{}", unique()));
    let output = binary()
        .args([
            "openshell",
            "doctor",
            "--insecure-local",
            "--home",
            &home.display().to_string(),
        ])
        .env_remove("MYSQL_URL")
        .env_remove("QUERYKNIGHT_DAEMON_URL")
        .env(
            "DATABASE_URL",
            "postgresql://user:DB_URL_SECRET_SENTINEL@127.0.0.1/not-used",
        )
        .output()
        .expect("run OpenShell doctor");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("doctor stdout");
    let stderr = String::from_utf8(output.stderr).expect("doctor stderr");
    assert!(stdout.contains("OpenShell protocol"));
    assert!(stdout.contains("OpenShellInsecureLocal"));
    assert!(stdout.contains("Ready for local development only"));
    assert!(stdout.contains("not checked (OpenShell ValidateConfig is authoritative)"));
    assert!(format!("{stdout}{stderr}").contains("DEVELOPMENT / TRUSTED TRANSPORT ONLY"));
    assert!(!format!("{stdout}{stderr}").contains("DB_URL_SECRET_SENTINEL"));
}

#[test]
fn openshell_insecure_development_mode_rejects_non_loopback() {
    let home = std::env::temp_dir().join(format!("qk-openshell-nonloopback-{}", unique()));
    binary()
        .args([
            "openshell",
            "doctor",
            "--insecure-local",
            "--listen",
            "0.0.0.0:50051",
            "--home",
            &home.display().to_string(),
        ])
        .env("DATABASE_URL", "postgresql://user:pass@127.0.0.1/not-used")
        .env_remove("MYSQL_URL")
        .env_remove("QUERYKNIGHT_DAEMON_URL")
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "OpenShellInsecureLocal requires a loopback",
        ));
}
