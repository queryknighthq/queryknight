//! Policy v1 typed data model, YAML loading, and strict validation.
//!
//! Mirrors the TypeScript oracle (`policy-file.ts`): unknown fields are
//! rejected at every level, operations/mutations validate against explicit
//!allowlists, and every failure reports a stable `path: message` error.
//! YAML syntax diagnostics from the underlying parser are normalized to
//! [`PolicyLoadError::InvalidYaml`]; parser prose never leaks.

use std::collections::BTreeMap;

use yaml_serde::{Mapping, Value};

use crate::error::PolicyLoadError;
use crate::glob::check_glob;

/// Result of policy loading and validation.
pub type Result<T> = std::result::Result<T, PolicyLoadError>;

/// Policy verdict configured by a rule or default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Allow the statement.
    Allow,
    /// Deny the statement.
    Deny,
    /// Park the statement for human approval.
    RequireApproval,
}

/// Fallback for unparseable or unsupported statements (`deny` default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ParseFallback {
    /// Fail closed.
    #[default]
    Deny,
    /// Park for human approval.
    RequireApproval,
}

/// Action for sensitive-column hits (`deny` default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SensitiveAction {
    /// Deny access.
    #[default]
    Deny,
    /// Park for human approval.
    RequireApproval,
}

/// One allow/deny/approval_required rule. All present fields must match (AND);
/// an empty rule matches everything.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyRule {
    /// Statement kinds / operation categories (lowercased, allowlist-checked).
    pub operations: Vec<String>,
    /// Schema globs.
    pub schemas: Vec<String>,
    /// Table globs (bare or schema-qualified).
    pub tables: Vec<String>,
    /// Column globs (bare, table-qualified, or fully qualified).
    pub columns: Vec<String>,
    /// Agent id globs.
    pub agents: Vec<String>,
    /// Integration name globs.
    pub integrations: Vec<String>,
    /// Tool name globs.
    pub tools: Vec<String>,
    /// Risk-signal globs.
    pub signals: Vec<String>,
}

/// Sensitive-column block: glob list plus deny/approval action.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SensitivePolicy {
    /// Column globs.
    pub columns: Vec<String>,
    /// What to do on a hit.
    pub action: SensitiveAction,
}

/// Mutation guards (`deny_without_where` subset of update/delete/insert).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MutationsPolicy {
    /// Mutation kinds denied without a WHERE clause (lowercased).
    pub deny_without_where: Vec<String>,
}

/// Read-size guards for SELECT statements.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RowSafety {
    /// Deny LIMIT-less SELECTs.
    pub require_limit: bool,
    /// Deny SELECTs with LIMIT above this value.
    pub max_limit: Option<u64>,
}

/// Per-database policy block.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DatabasePolicy {
    /// Rules granting access.
    pub allow: Vec<PolicyRule>,
    /// Rules denying access (beat approval and allow).
    pub deny: Vec<PolicyRule>,
    /// Rules parking statements for approval.
    pub approval_required: Vec<PolicyRule>,
    /// Sensitive-column handling.
    pub sensitive: Option<SensitivePolicy>,
    /// Mutation guards.
    pub mutations: Option<MutationsPolicy>,
    /// Read-size guards.
    pub row_safety: Option<RowSafety>,
}

/// Named environment scope holding database policies.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvironmentPolicy {
    /// Database policies keyed by policy identity (`*` is the wildcard).
    /// `BTreeMap` keeps iteration deterministic regardless of document order.
    pub databases: BTreeMap<String, DatabasePolicy>,
}

/// Global defaults applied when no rule matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Defaults {
    /// Verdict when no rule matches.
    pub decision: Decision,
    /// Fallback for unparseable SQL.
    pub on_parse_error: ParseFallback,
    /// Fallback for unsupported statement kinds.
    pub on_unknown: ParseFallback,
    /// Deny LIMIT-less SELECTs globally.
    pub require_limit: bool,
    /// Global LIMIT ceiling.
    pub max_limit: Option<u64>,
}

/// Embedded `policy test` case (also used for standalone cases files).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyTestCase {
    /// Case name.
    pub name: String,
    /// SQL under test.
    pub sql: String,
    /// SQL dialect override.
    pub dialect: Option<String>,
    /// Database scope override.
    pub database: Option<String>,
    /// Environment scope override.
    pub environment: Option<String>,
    /// Agent id override.
    pub agent_id: Option<String>,
    /// Integration override.
    pub integration: Option<String>,
    /// Expected verdict.
    pub expect: Decision,
    /// Expected exact reason code.
    pub reason: Option<String>,
}

/// Validated policy v1 file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyFile {
    /// Always `1`; anything else is [`PolicyLoadError::UnsupportedVersion`].
    pub version: u8,
    /// Global defaults.
    pub defaults: Defaults,
    /// Environment scopes, sorted for deterministic iteration.
    pub environments: BTreeMap<String, EnvironmentPolicy>,
    /// Embedded test cases.
    pub tests: Vec<PolicyTestCase>,
}

/// Statement kinds, operation categories, and legacy classes a rule may name.
/// Explicit allowlist so a typo can never silently disable a rule.
pub const KNOWN_OPERATIONS: &[&str] = &[
    "select",
    "insert",
    "update",
    "delete",
    "merge",
    "create",
    "alter",
    "drop",
    "truncate",
    "rename",
    "grant",
    "revoke",
    "call",
    "copy",
    "load",
    "set",
    "show",
    "describe",
    "explain",
    "use",
    "transaction",
    "unknown",
    "read",
    "write",
    "ddl",
    "destructive",
    "privilege",
    "admin",
    "administrative",
];

/// Mutation kinds accepted in `deny_without_where`.
pub const KNOWN_MUTATIONS: &[&str] = &["update", "delete", "insert"];

const DECISION_NAMES: &[&str] = &["allow", "deny", "require_approval"];
const FALLBACK_NAMES: &[&str] = &["deny", "require_approval"];
const SENSITIVE_ACTIONS: &[&str] = &["deny", "require_approval"];

/// Parse and strictly validate a policy v1 YAML document.
///
/// An empty or whitespace-only document is not valid YAML input for our
/// purposes and reports `policy: expected a mapping at the top level`,
/// matching the oracle. Syntax failures report [`PolicyLoadError::InvalidYaml`]
/// with position only.
pub fn parse_policy(text: &str) -> Result<PolicyFile> {
    if text.trim().is_empty() {
        return Err(PolicyLoadError::InvalidConfiguration {
            path: "policy".to_owned(),
            message: "expected a mapping at the top level".to_owned(),
        });
    }
    let value: Value = yaml_serde::from_str(text).map_err(|e| {
        let (line, column) = match e.location() {
            Some(loc) => (Some(loc.line()), Some(loc.column())),
            None => (None, None),
        };
        PolicyLoadError::InvalidYaml { line, column }
    })?;
    validate_policy(&value)
}

fn validate_policy(value: &Value) -> Result<PolicyFile> {
    let root = as_mapping(value, "policy", "expected a mapping at the top level")?;
    no_extra_keys(
        root,
        &["version", "defaults", "environments", "tests"],
        "policy",
    )?;

    let version_value = root.get("version");
    let version = match version_value {
        Some(Value::Number(n)) if n.as_u64() == Some(1) => 1u8,
        _ => {
            return Err(PolicyLoadError::UnsupportedVersion {
                found: render_scalar(version_value),
            });
        }
    };

    let defaults_value =
        root.get("defaults")
            .ok_or_else(|| PolicyLoadError::InvalidConfiguration {
                path: "policy.defaults".to_owned(),
                message: "expected an object".to_owned(),
            })?;
    let defaults = validate_defaults(defaults_value)?;

    let mut environments = BTreeMap::new();
    if let Some(envs_value) = root.get("environments") {
        let envs = as_mapping(envs_value, "policy.environments", "expected a mapping")?;
        for (key, raw) in envs {
            let name = mapping_key_name(key);
            let path = format!("policy.environments.{name}");
            let env_map = as_mapping(raw, &path, "expected an object")?;
            no_extra_keys(env_map, &["databases"], &path)?;
            let mut env = EnvironmentPolicy::default();
            if let Some(dbs_value) = env_map.get("databases") {
                let dbs = as_mapping(
                    dbs_value,
                    &format!("{path}.databases"),
                    "expected a mapping",
                )?;
                for (db_key, db_raw) in dbs {
                    let db_name = mapping_key_name(db_key);
                    let db_path = format!("{path}.databases.{db_name}");
                    env.databases
                        .insert(db_name, validate_database_policy(db_raw, &db_path)?);
                }
            }
            environments.insert(name, env);
        }
    }

    let mut tests = Vec::new();
    if let Some(tests_value) = root.get("tests") {
        let list = as_sequence(tests_value, "policy.tests", "expected a list")?;
        for (i, raw) in list.iter().enumerate() {
            tests.push(validate_test_case(raw, &format!("policy.tests[{i}]"))?);
        }
    }

    Ok(PolicyFile {
        version,
        defaults,
        environments,
        tests,
    })
}

fn validate_defaults(value: &Value) -> Result<Defaults> {
    let map = as_mapping(value, "policy.defaults", "expected an object")?;
    no_extra_keys(
        map,
        &[
            "decision",
            "on_parse_error",
            "on_unknown",
            "require_limit",
            "max_limit",
        ],
        "policy.defaults",
    )?;
    let decision = match map.get("decision") {
        Some(Value::String(s)) if DECISION_NAMES.contains(&s.as_str()) => parse_decision(s),
        _ => {
            return Err(PolicyLoadError::InvalidConfiguration {
                path: "policy.defaults.decision".to_owned(),
                message: format!("expected one of {}", DECISION_NAMES.join(", ")),
            });
        }
    };
    let on_parse_error = validate_fallback(map, "policy.defaults.on_parse_error")?;
    let on_unknown = validate_fallback(map, "policy.defaults.on_unknown")?;
    let require_limit =
        validate_optional_bool(map, "policy.defaults.require_limit")?.unwrap_or(false);
    let max_limit = validate_optional_limit(map, "policy.defaults.max_limit")?;
    Ok(Defaults {
        decision,
        on_parse_error,
        on_unknown,
        require_limit,
        max_limit,
    })
}

fn validate_fallback(map: &Mapping, path: &str) -> Result<ParseFallback> {
    let key = path.rsplit('.').next().unwrap_or(path);
    match map.get(key) {
        None => Ok(ParseFallback::Deny),
        Some(Value::String(s)) if FALLBACK_NAMES.contains(&s.as_str()) => {
            Ok(if s == "require_approval" {
                ParseFallback::RequireApproval
            } else {
                ParseFallback::Deny
            })
        }
        Some(_) => Err(PolicyLoadError::InvalidConfiguration {
            path: path.to_owned(),
            message: "expected 'deny' or 'require_approval'".to_owned(),
        }),
    }
}

fn validate_database_policy(value: &Value, path: &str) -> Result<DatabasePolicy> {
    let map = as_mapping(value, path, "expected a database policy object")?;
    no_extra_keys(
        map,
        &[
            "allow",
            "deny",
            "approval_required",
            "sensitive",
            "mutations",
            "row_safety",
        ],
        path,
    )?;
    Ok(DatabasePolicy {
        allow: validate_rule_list(map, "allow", path)?,
        deny: validate_rule_list(map, "deny", path)?,
        approval_required: validate_rule_list(map, "approval_required", path)?,
        sensitive: validate_sensitive(map, path)?,
        mutations: validate_mutations(map, path)?,
        row_safety: validate_row_safety(map, path)?,
    })
}

fn validate_rule_list(map: &Mapping, key: &str, path: &str) -> Result<Vec<PolicyRule>> {
    let rule_path = format!("{path}.{key}");
    let Some(value) = map.get(key) else {
        return Ok(Vec::new());
    };
    let list = as_sequence(value, &rule_path, "expected a list of rules")?;
    list.iter()
        .enumerate()
        .map(|(i, raw)| validate_rule(raw, &format!("{rule_path}[{i}]")))
        .collect()
}

fn validate_rule(value: &Value, path: &str) -> Result<PolicyRule> {
    let map = as_mapping(value, path, "expected a rule object")?;
    no_extra_keys(
        map,
        &[
            "operations",
            "schemas",
            "tables",
            "columns",
            "agents",
            "integrations",
            "tools",
            "signals",
        ],
        path,
    )?;
    let mut rule = PolicyRule::default();
    if let Some(ops) = map.get("operations") {
        let names = string_array(ops, &format!("{path}.operations"))?;
        for name in &names {
            let lower = name.to_lowercase();
            if !KNOWN_OPERATIONS.contains(&lower.as_str()) {
                return Err(PolicyLoadError::InvalidOperation {
                    path: format!("{path}.operations"),
                    operation: lower,
                    allowed: KNOWN_OPERATIONS.join(", "),
                });
            }
        }
        rule.operations = names.iter().map(|s| s.to_lowercase()).collect();
    }
    for field in [
        "schemas",
        "tables",
        "columns",
        "agents",
        "integrations",
        "tools",
        "signals",
    ] {
        if let Some(raw) = map.get(field) {
            let patterns = string_array(raw, &format!("{path}.{field}"))?;
            for pattern in &patterns {
                if !check_glob(pattern) {
                    return Err(PolicyLoadError::InvalidGlob {
                        path: format!("{path}.{field}"),
                    });
                }
            }
            match field {
                "schemas" => rule.schemas = patterns,
                "tables" => rule.tables = patterns,
                "columns" => rule.columns = patterns,
                "agents" => rule.agents = patterns,
                "integrations" => rule.integrations = patterns,
                "tools" => rule.tools = patterns,
                _ => rule.signals = patterns,
            }
        }
    }
    Ok(rule)
}

fn validate_sensitive(map: &Mapping, path: &str) -> Result<Option<SensitivePolicy>> {
    let Some(value) = map.get("sensitive") else {
        return Ok(None);
    };
    let sub_path = format!("{path}.sensitive");
    let sub = as_mapping(value, &sub_path, "expected an object")?;
    no_extra_keys(sub, &["columns", "action"], &sub_path)?;
    let mut out = SensitivePolicy::default();
    if let Some(cols) = sub.get("columns") {
        out.columns = string_array(cols, &format!("{sub_path}.columns"))?;
        for pattern in &out.columns {
            if !check_glob(pattern) {
                return Err(PolicyLoadError::InvalidGlob {
                    path: format!("{sub_path}.columns"),
                });
            }
        }
    }
    if let Some(action) = sub.get("action") {
        match action {
            Value::String(s) if SENSITIVE_ACTIONS.contains(&s.as_str()) => {
                out.action = if s == "require_approval" {
                    SensitiveAction::RequireApproval
                } else {
                    SensitiveAction::Deny
                };
            }
            _ => {
                return Err(PolicyLoadError::InvalidConfiguration {
                    path: format!("{sub_path}.action"),
                    message: format!("expected one of {}", SENSITIVE_ACTIONS.join(", ")),
                });
            }
        }
    }
    Ok(Some(out))
}

fn validate_mutations(map: &Mapping, path: &str) -> Result<Option<MutationsPolicy>> {
    let Some(value) = map.get("mutations") else {
        return Ok(None);
    };
    let sub_path = format!("{path}.mutations");
    let sub = as_mapping(value, &sub_path, "expected an object")?;
    no_extra_keys(sub, &["deny_without_where"], &sub_path)?;
    let mut out = MutationsPolicy::default();
    if let Some(raw) = sub.get("deny_without_where") {
        let names = string_array(raw, &format!("{sub_path}.deny_without_where"))?;
        for name in &names {
            let lower = name.to_lowercase();
            if !KNOWN_MUTATIONS.contains(&lower.as_str()) {
                return Err(PolicyLoadError::InvalidConfiguration {
                    path: format!("{sub_path}.deny_without_where"),
                    message: format!(
                        "unknown mutation '{lower}' (allowed: {})",
                        KNOWN_MUTATIONS.join(", ")
                    ),
                });
            }
            out.deny_without_where.push(lower);
        }
    }
    Ok(Some(out))
}

fn validate_row_safety(map: &Mapping, path: &str) -> Result<Option<RowSafety>> {
    let Some(value) = map.get("row_safety") else {
        return Ok(None);
    };
    let sub_path = format!("{path}.row_safety");
    let sub = as_mapping(value, &sub_path, "expected an object")?;
    no_extra_keys(sub, &["require_limit", "max_limit"], &sub_path)?;
    Ok(Some(RowSafety {
        require_limit: validate_optional_bool(sub, &format!("{sub_path}.require_limit"))?
            .unwrap_or(false),
        max_limit: validate_optional_limit(sub, &format!("{sub_path}.max_limit"))?,
    }))
}

fn validate_test_case(value: &Value, path: &str) -> Result<PolicyTestCase> {
    let map = as_mapping(value, path, "expected an object")?;
    no_extra_keys(
        map,
        &[
            "name",
            "sql",
            "dialect",
            "database",
            "environment",
            "agent_id",
            "integration",
            "expect",
            "reason",
        ],
        path,
    )?;
    let name = required_string(map, "name", path)?;
    let sql = required_string(map, "sql", path)?;
    let expect = match map.get("expect") {
        Some(Value::String(s)) if DECISION_NAMES.contains(&s.as_str()) => parse_decision(s),
        _ => {
            return Err(PolicyLoadError::InvalidConfiguration {
                path: format!("{path}.expect"),
                message: format!("expected one of {}", DECISION_NAMES.join(", ")),
            });
        }
    };
    Ok(PolicyTestCase {
        name,
        sql,
        dialect: optional_string(map, "dialect", path)?,
        database: optional_string(map, "database", path)?,
        environment: optional_string(map, "environment", path)?,
        agent_id: optional_string(map, "agent_id", path)?,
        integration: optional_string(map, "integration", path)?,
        expect,
        reason: optional_string(map, "reason", path)?,
    })
}

fn parse_decision(name: &str) -> Decision {
    match name {
        "allow" => Decision::Allow,
        "require_approval" => Decision::RequireApproval,
        _ => Decision::Deny,
    }
}

fn as_mapping<'a>(value: &'a Value, path: &str, message: &str) -> Result<&'a Mapping> {
    match value {
        Value::Mapping(map) => Ok(map),
        _ => Err(PolicyLoadError::InvalidConfiguration {
            path: path.to_owned(),
            message: message.to_owned(),
        }),
    }
}

fn as_sequence<'a>(value: &'a Value, path: &str, message: &str) -> Result<&'a Vec<Value>> {
    match value {
        Value::Sequence(list) => Ok(list),
        _ => Err(PolicyLoadError::InvalidConfiguration {
            path: path.to_owned(),
            message: message.to_owned(),
        }),
    }
}

fn no_extra_keys(map: &Mapping, allowed: &[&str], path: &str) -> Result<()> {
    for key in map.keys() {
        let name = mapping_key_name(key);
        if !allowed.contains(&name.as_str()) {
            return Err(PolicyLoadError::UnknownField {
                path: path.to_owned(),
                field: name,
                allowed: allowed.join(", "),
            });
        }
    }
    Ok(())
}

fn mapping_key_name(key: &Value) -> String {
    match key {
        Value::String(s) => s.clone(),
        Value::Number(n) => render_number(n),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_owned(),
        _ => "<non-scalar key>".to_owned(),
    }
}

fn render_scalar(value: Option<&Value>) -> String {
    match value {
        None => "missing".to_owned(),
        Some(Value::Null) => "null".to_owned(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => render_number(n),
        Some(Value::Sequence(_)) => "<list>".to_owned(),
        Some(Value::Mapping(_)) => "<mapping>".to_owned(),
        Some(Value::Tagged(t)) => render_scalar(Some(&t.value)),
    }
}

fn render_number(n: &yaml_serde::Number) -> String {
    if let Some(u) = n.as_u64() {
        u.to_string()
    } else if let Some(i) = n.as_i64() {
        i.to_string()
    } else if let Some(f) = n.as_f64() {
        f.to_string()
    } else {
        "<number>".to_owned()
    }
}

fn string_array(value: &Value, path: &str) -> Result<Vec<String>> {
    let list = as_sequence(value, path, "expected a list of strings")?;
    let mut out = Vec::with_capacity(list.len());
    for (i, item) in list.iter().enumerate() {
        match item {
            Value::String(s) if !s.is_empty() => out.push(s.clone()),
            _ => {
                return Err(PolicyLoadError::InvalidConfiguration {
                    path: format!("{path}[{i}]"),
                    message: "expected a non-empty string".to_owned(),
                });
            }
        }
    }
    Ok(out)
}

fn required_string(map: &Mapping, key: &str, path: &str) -> Result<String> {
    match map.get(key) {
        Some(Value::String(s)) if !s.is_empty() => Ok(s.clone()),
        _ => Err(PolicyLoadError::InvalidConfiguration {
            path: format!("{path}.{key}"),
            message: "expected a non-empty string".to_owned(),
        }),
    }
}

fn optional_string(map: &Mapping, key: &str, path: &str) -> Result<Option<String>> {
    match map.get(key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(PolicyLoadError::InvalidConfiguration {
            path: format!("{path}.{key}"),
            message: "expected a string".to_owned(),
        }),
    }
}

fn validate_optional_bool(map: &Mapping, path: &str) -> Result<Option<bool>> {
    let key = path.rsplit('.').next().unwrap_or(path);
    match map.get(key) {
        None => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(PolicyLoadError::InvalidConfiguration {
            path: path.to_owned(),
            message: "expected a boolean".to_owned(),
        }),
    }
}

fn validate_optional_limit(map: &Mapping, path: &str) -> Result<Option<u64>> {
    let key = path.rsplit('.').next().unwrap_or(path);
    match map.get(key) {
        None => Ok(None),
        Some(Value::Number(n)) => match n.as_u64() {
            Some(v) if v >= 1 => Ok(Some(v)),
            _ => Err(PolicyLoadError::InvalidLimit {
                path: path.to_owned(),
            }),
        },
        Some(_) => Err(PolicyLoadError::InvalidLimit {
            path: path.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_policy;

    #[test]
    fn empty_document_is_not_a_mapping() {
        let err = parse_policy("   \n ").expect_err("empty must fail");
        assert_eq!(
            err.to_string(),
            "policy: expected a mapping at the top level"
        );
    }

    #[test]
    fn scalar_document_is_not_a_mapping() {
        let err = parse_policy("just a string").expect_err("scalar must fail");
        assert_eq!(
            err.to_string(),
            "policy: expected a mapping at the top level"
        );
    }

    #[test]
    fn syntax_error_carries_position_only() {
        let err = parse_policy("version: [1\ndefaults: {decision: deny\n")
            .expect_err("broken yaml must fail");
        assert!(err.to_string().starts_with("invalid YAML"), "{err}");
    }

    #[test]
    fn minimal_policy_validates() {
        let policy = match parse_policy("version: 1\ndefaults:\n  decision: deny\n") {
            Ok(policy) => policy,
            Err(e) => panic!("minimal policy must validate: {e}"),
        };
        assert_eq!(policy.version, 1);
        assert!(policy.environments.is_empty());
        assert!(policy.tests.is_empty());
    }
}
