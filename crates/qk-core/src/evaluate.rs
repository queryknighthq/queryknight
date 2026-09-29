//! Deterministic SQL policy evaluator: the single logical decision path.
//!
//! Precedence (first match wins; mirrors the reference implementation):
//!
//! 1. empty SQL -> deny `EMPTY_QUERY`
//! 2. oversized SQL -> deny `QUERY_TOO_LARGE`
//! 3. unparseable analysis -> `defaults.on_parse_error` (`DENY_PARSE_ERROR`)
//! 4. unknown/unsupported shapes -> `defaults.on_unknown`
//!    (`DENY_UNKNOWN_STATEMENT`)
//! 5. depth-truncated analysis -> `defaults.on_unknown`
//!    (`DENY_UNKNOWN_STATEMENT`; deliberate: an uninspected remainder may
//!    hide anything, closest to "unknown")
//! 6. sensitive columns -> deny or require_approval (`SENSITIVE_COLUMN`)
//! 7. explicit deny rules, first match (`DENY_RULE`)
//! 8. mutations without WHERE, top-level then nested (`UNBOUNDED_*`)
//! 9. row safety (`LIMIT_REQUIRED`, `LIMIT_EXCEEDED`)
//! 10. approval rules, first match (`REQUIRE_APPROVAL`; terminal: a later
//!     layer resolves approvals, this function never invokes providers)
//! 11. allow rules, first match (`ALLOW_RULE`)
//! 12. `defaults.decision` (`DEFAULT_*`)
//!
//! The evaluator is synchronous, side-effect free, and deterministic: same
//! context, SQL, dialect, policy, and options always yield the same result.
//! Untrusted SQL and analysis failures become deterministic `Deny` results,
//! never `Err` (callers must not remember to "deny manually"). Only
//! misused API inputs that are programmer errors surface as `Err`, and none
//! exist in this signature: every failure mode has a frozen deny mapping.

use std::collections::BTreeSet;

use qk_sql::{
    analyze_with_options, defensive_scan, AnalysisCompleteness, AnalyzeOptions, ColumnName,
    LimitValue, OpCategory, Operation, QueryAnalysis, SqlAnalysisError, SqlDialect, SqlInspection,
};

use crate::context::ExecutionContext;
use crate::decision::{Decision, ReasonCode};
use crate::glob::glob_match;
use crate::policy::{DatabasePolicy, ParseFallback, PolicyFile, PolicyRule, SensitiveAction};

/// Inputs to one evaluation: trusted context, untrusted SQL, frozen policy.
#[derive(Debug, Clone)]
pub struct EvaluationRequest<'a> {
    /// Trusted execution context (integration scope, never from SQL text).
    pub context: &'a ExecutionContext,
    /// Dialect used for analysis (dialect differences belong to `qk-sql`).
    pub dialect: SqlDialect,
    /// Untrusted SQL text under evaluation.
    pub sql: &'a str,
    /// Validated policy file.
    pub policy: &'a PolicyFile,
}

/// Evaluation knobs. Default carries the frozen input budget.
#[derive(Debug, Clone, Copy)]
pub struct EvaluateOptions {
    /// Maximum accepted SQL byte length.
    pub max_bytes: usize,
}

impl Default for EvaluateOptions {
    fn default() -> Self {
        Self {
            max_bytes: qk_sql::MAX_SQL_BYTES,
        }
    }
}

/// Externally meaningful decision output. Deterministic and verdict-only:
/// no fingerprints, timestamps, or transport metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationResult {
    /// The verdict.
    pub decision: Decision,
    /// Machine reason code (frozen values).
    pub reason_code: ReasonCode,
    /// Human diagnostic message (normalized wording, not a contract).
    pub message: String,
    /// Decisive policy path (e.g. `production.main.deny[0]`), when any rule
    /// or default beyond the envelope decided.
    pub matched_policy: Option<String>,
    /// Sensitive/unbounded target table, when the reason names one.
    pub table: Option<String>,
    /// Sensitive column, when the reason names one.
    pub column: Option<String>,
    /// Statement kinds (`select,drop`, ...), mirroring the reference shape.
    pub operation: Option<String>,
}

impl EvaluationResult {
    /// Whether this evaluation contains the given top-level statement
    /// operation. This reads evaluator-produced typed-name metadata; it does
    /// not reparse SQL or infer operations from user strings.
    #[must_use]
    pub fn includes_operation(&self, operation: &Operation) -> bool {
        self.operation
            .as_deref()
            .is_some_and(|names| names.split(',').any(|name| name == operation.name()))
    }
}

/// Evaluate SQL against policy: the single decision path for every
/// integration (MCP, CLI, proxy, OpenShell call this; never per-engine or
/// per-transport variants).
pub fn evaluate(request: &EvaluationRequest<'_>, options: &EvaluateOptions) -> EvaluationResult {
    if request.sql.trim().is_empty() {
        return deny(
            ReasonCode::EmptyQuery,
            "empty SQL is not permitted",
            None,
            None,
            None,
            None,
        );
    }

    // One inspection bundles AST analysis and defensive evidence. The
    // defensive scan only enriches failure-path diagnostics; it never
    // alters verdicts (INV-023).
    let inspection = SqlInspection {
        analysis: analyze_with_options(
            request.sql,
            request.dialect,
            AnalyzeOptions {
                max_bytes: options.max_bytes,
            },
        ),
        defensive: defensive_scan(request.sql, request.dialect),
    };
    let analysis = match inspection.analysis {
        Ok(analysis) => analysis,
        Err(error) => return analysis_failure(request, &error, &inspection.defensive),
    };
    evaluate_analyzed(request, &analysis, &inspection.defensive)
}

fn analysis_failure(
    request: &EvaluationRequest<'_>,
    error: &SqlAnalysisError,
    defensive: &qk_sql::DefensiveScan,
) -> EvaluationResult {
    let possible = possible_list(defensive);
    match error {
        SqlAnalysisError::InputTooLarge { max_bytes, .. } => deny(
            ReasonCode::QueryTooLarge,
            &format!("SQL exceeds size limit of {max_bytes} bytes"),
            None,
            None,
            None,
            None,
        ),
        // Comments-only (or otherwise statement-less) input reached the
        // analyzer: the text was not empty, so this is an unparseable
        // analysis like any other, matching the reference behavior.
        SqlAnalysisError::EmptyQuery | SqlAnalysisError::ParseError { .. } => deny_or_approval(
            fallback_decision(request.policy.defaults.on_parse_error),
            ReasonCode::DenyParseError,
            &parse_message(&possible),
            Some("defaults.on_parse_error".to_owned()),
            None,
            None,
            Some("unknown".to_owned()),
        ),
        // Complexity exhaustion and internal failures mean shapes went
        // unseen: closest frozen semantics is the unknown-statement path.
        // This is a deliberate conservative choice (the reference has no
        // equivalent state); see INV-022.
        SqlAnalysisError::ComplexityLimitExceeded { .. }
        | SqlAnalysisError::AnalysisError { .. } => deny_or_approval(
            fallback_decision(request.policy.defaults.on_unknown),
            ReasonCode::DenyUnknownStatement,
            &unknown_message("unseen statements", &possible),
            Some("defaults.on_unknown".to_owned()),
            None,
            None,
            Some("unknown".to_owned()),
        ),
        SqlAnalysisError::UnsupportedDialect(_) => deny(
            ReasonCode::PolicyError,
            "unsupported dialect for evaluation",
            None,
            None,
            None,
            None,
        ),
    }
}

/// Sorted defensive operation names for failure-path messages.
fn possible_list(defensive: &qk_sql::DefensiveScan) -> String {
    let mut names: Vec<&str> = defensive
        .possible_operations
        .iter()
        .map(|o| o.name())
        .collect();
    names.sort_unstable();
    names.join(", ")
}

fn parse_message(possible: &str) -> String {
    if possible.is_empty() {
        "SQL could not be parsed (unknown syntax); failing closed".to_owned()
    } else {
        format!("SQL could not be parsed (possible: {possible}); failing closed")
    }
}

fn unknown_message(kinds: &str, possible: &str) -> String {
    if possible.is_empty() {
        format!("unsupported statement kind ({kinds}); failing closed")
    } else {
        format!("unsupported statement kind ({kinds}; possible: {possible}); failing closed")
    }
}

fn evaluate_analyzed(
    request: &EvaluationRequest<'_>,
    analysis: &QueryAnalysis,
    defensive: &qk_sql::DefensiveScan,
) -> EvaluationResult {
    let kinds = operation_kinds(analysis);
    let possible = possible_list(defensive);

    // Unknown or unsupported shapes fail closed via on_unknown. CALL is
    // included deliberately: a procedure may do anything, so its effect is
    // unknown in every dialect (matches the reference verdict).
    let unknown = analysis
        .operations
        .iter()
        .any(|op| matches!(op.category(), OpCategory::Unknown) || *op == Operation::Call);
    if unknown {
        return deny_or_approval(
            fallback_decision(request.policy.defaults.on_unknown),
            ReasonCode::DenyUnknownStatement,
            &unknown_message(&kinds, &possible),
            Some("defaults.on_unknown".to_owned()),
            None,
            None,
            Some(kinds),
        );
    }

    // Truncated analysis is never a complete inspection: same fail-closed
    // family as unknown shapes (deliberate; the reference cannot produce
    // this state). Truncation outranks rule matching because no rule can
    // be soundly evaluated against unseen statements.
    if analysis.completeness == AnalysisCompleteness::DepthTruncated {
        let message = if possible.is_empty() {
            "analysis incomplete (depth truncated); failing closed".to_owned()
        } else {
            format!("analysis incomplete (depth truncated; possible: {possible}); failing closed")
        };
        return deny_or_approval(
            fallback_decision(request.policy.defaults.on_unknown),
            ReasonCode::DenyUnknownStatement,
            &message,
            Some("defaults.on_unknown".to_owned()),
            None,
            None,
            Some(kinds),
        );
    }

    let (db_policy, db_path) = resolve_scope(request.policy, request.context);

    if let Some(policy) = db_policy {
        if let Some(sensitive) = &policy.sensitive {
            if !sensitive.columns.is_empty() {
                if let Some(hit) = find_sensitive_column(analysis, &sensitive.columns) {
                    let message = if sensitive.action == SensitiveAction::Deny {
                        format!("access to sensitive column {}", hit.qualified)
                    } else {
                        format!("approval required for sensitive column {}", hit.qualified)
                    };
                    return deny_or_approval(
                        sensitive_action_decision(sensitive.action),
                        ReasonCode::SensitiveColumn,
                        &message,
                        Some(format!("{db_path}.sensitive")),
                        Some(hit.table),
                        Some(hit.column),
                        None,
                    );
                }
            }
        }

        if let Some((index, rule)) = first_matching(&policy.deny, analysis, request.context) {
            return deny(
                ReasonCode::DenyRule,
                &format!("matched deny rule ({})", describe_rule(rule)),
                Some(format!("{db_path}.deny[{index}]")),
                None,
                None,
                Some(kinds),
            );
        }

        // Absent mutation config defaults to update+delete (reference);
        // a present-but-empty list disables the check (also reference).
        let unbounded_denied = |kind: &str| match &policy.mutations {
            None => kind == "update" || kind == "delete",
            Some(mutations) => mutations.deny_without_where.iter().any(|m| m == kind),
        };
        for statement in &analysis.statements {
            let kind = statement.operation.name();
            if matches!(statement.operation, Operation::Update | Operation::Delete)
                && unbounded_denied(kind)
                && statement.has_where != Some(true)
            {
                let code = if statement.operation == Operation::Update {
                    ReasonCode::UnboundedUpdate
                } else {
                    ReasonCode::UnboundedDelete
                };
                let table = statement
                    .mutated_tables
                    .first()
                    .map(|t| t.to_string())
                    .or_else(|| statement.tables.first().map(|t| t.to_string()));
                return deny(
                    code,
                    &format!(
                        "{} without a WHERE clause is not permitted",
                        statement.operation.name().to_uppercase()
                    ),
                    Some(format!("{db_path}.mutations.deny_without_where")),
                    table,
                    None,
                    Some(kind.to_owned()),
                );
            }
            for nested in &statement.nested_unbounded {
                let kind = nested.name();
                if unbounded_denied(kind) {
                    let code = if *nested == Operation::Update {
                        ReasonCode::UnboundedUpdate
                    } else {
                        ReasonCode::UnboundedDelete
                    };
                    return deny(
                        code,
                        &format!(
                            "{} without a WHERE clause is not permitted",
                            kind.to_uppercase()
                        ),
                        Some(format!("{db_path}.mutations.deny_without_where")),
                        None,
                        None,
                        Some(kind.to_owned()),
                    );
                }
            }
        }

        let row_require_limit = policy
            .row_safety
            .as_ref()
            .map(|row| row.require_limit)
            .unwrap_or(request.policy.defaults.require_limit);
        if row_require_limit {
            let unlimited = analysis
                .statements
                .iter()
                .any(|s| s.operation == Operation::Select && s.limit.is_none());
            if unlimited {
                return deny(
                    ReasonCode::LimitRequired,
                    "SELECT without a LIMIT clause is not permitted by policy",
                    Some(format!("{db_path}.row_safety.require_limit")),
                    None,
                    None,
                    Some("select".to_owned()),
                );
            }
        }
        let row_max_limit = policy
            .row_safety
            .as_ref()
            .and_then(|row| row.max_limit)
            .or(request.policy.defaults.max_limit);
        if let Some(max) = row_max_limit {
            let first_literal = analysis
                .statements
                .iter()
                .filter_map(|s| match s.limit {
                    Some(LimitValue::Literal(n)) => Some(n),
                    _ => None,
                })
                .next();
            if let Some(value) = first_literal {
                if value > max {
                    return deny(
                        ReasonCode::LimitExceeded,
                        &format!("LIMIT {value} exceeds policy maximum {max}"),
                        Some(format!("{db_path}.row_safety.max_limit")),
                        None,
                        None,
                        Some("select".to_owned()),
                    );
                }
            }
        }

        if let Some((index, rule)) =
            first_matching(&policy.approval_required, analysis, request.context)
        {
            return EvaluationResult {
                decision: Decision::RequireApproval,
                reason_code: ReasonCode::RequireApproval,
                message: format!("matched approval rule ({})", describe_rule(rule)),
                matched_policy: Some(format!("{db_path}.approval_required[{index}]")),
                table: None,
                column: None,
                operation: Some(kinds),
            };
        }

        if let Some((index, rule)) = first_matching(&policy.allow, analysis, request.context) {
            return EvaluationResult {
                decision: Decision::Allow,
                reason_code: ReasonCode::AllowRule,
                message: format!("matched allow rule ({})", describe_rule(rule)),
                matched_policy: Some(format!("{db_path}.allow[{index}]")),
                table: None,
                column: None,
                operation: Some(kinds),
            };
        }
    }

    let fallback = request.policy.defaults.decision;
    let (decision, code) = match fallback {
        crate::policy::Decision::Allow => (Decision::Allow, ReasonCode::DefaultAllow),
        crate::policy::Decision::RequireApproval => {
            (Decision::RequireApproval, ReasonCode::DefaultApproval)
        }
        crate::policy::Decision::Deny => (Decision::Deny, ReasonCode::DefaultDeny),
    };
    deny_or_approval(
        decision,
        code,
        &format!(
            "no policy rule matched; default decision: {}",
            fallback.as_str()
        ),
        Some("defaults.decision".to_owned()),
        None,
        None,
        Some(kinds),
    )
}

/// Statement kinds in source order, duplicates kept (reference shape).
fn operation_kinds(analysis: &QueryAnalysis) -> String {
    analysis
        .statements
        .iter()
        .map(|s| s.operation.name())
        .collect::<Vec<_>>()
        .join(",")
}

fn deny(
    code: ReasonCode,
    message: &str,
    matched: Option<String>,
    table: Option<String>,
    column: Option<String>,
    operation: Option<String>,
) -> EvaluationResult {
    EvaluationResult {
        decision: Decision::Deny,
        reason_code: code,
        message: message.to_owned(),
        matched_policy: matched,
        table,
        column,
        operation,
    }
}

fn deny_or_approval(
    decision: Decision,
    code: ReasonCode,
    message: &str,
    matched: Option<String>,
    table: Option<String>,
    column: Option<String>,
    operation: Option<String>,
) -> EvaluationResult {
    EvaluationResult {
        decision,
        reason_code: code,
        message: message.to_owned(),
        matched_policy: matched,
        table,
        column,
        operation,
    }
}

/// Policy `on_parse_error` / `on_unknown` fallbacks only admit deny or
/// require_approval by schema; map them onto decisions.
fn fallback_decision(fallback: ParseFallback) -> Decision {
    match fallback {
        ParseFallback::Deny => Decision::Deny,
        ParseFallback::RequireApproval => Decision::RequireApproval,
    }
}

fn sensitive_action_decision(action: SensitiveAction) -> Decision {
    match action {
        SensitiveAction::Deny => Decision::Deny,
        SensitiveAction::RequireApproval => Decision::RequireApproval,
    }
}

fn resolve_scope<'p>(
    policy: &'p PolicyFile,
    ctx: &ExecutionContext,
) -> (Option<&'p DatabasePolicy>, String) {
    let Some(env) = policy.environments.get(&ctx.environment) else {
        return (None, "defaults".to_owned());
    };
    if env.databases.is_empty() {
        return (None, "defaults".to_owned());
    }
    let key = ctx.database_key();
    if !key.is_empty() {
        if let Some(db) = env.databases.get(key) {
            return (Some(db), format!("{}.{}", ctx.environment, key));
        }
    }
    if let Some(db) = env.databases.get("*") {
        return (Some(db), format!("{}.*", ctx.environment));
    }
    (None, "defaults".to_owned())
}

fn first_matching<'p>(
    rules: &'p [PolicyRule],
    analysis: &QueryAnalysis,
    ctx: &ExecutionContext,
) -> Option<(usize, &'p PolicyRule)> {
    rules
        .iter()
        .enumerate()
        .find(|(_, rule)| rule_matches(rule, analysis, ctx))
}

fn rule_matches(rule: &PolicyRule, analysis: &QueryAnalysis, ctx: &ExecutionContext) -> bool {
    if !rule.operations.is_empty() && !match_operations(&rule.operations, analysis) {
        return false;
    }
    if !rule.schemas.is_empty() && !match_schemas(&rule.schemas, analysis) {
        return false;
    }
    if !rule.tables.is_empty() && !match_tables(&rule.tables, analysis) {
        return false;
    }
    if !rule.columns.is_empty() && !match_columns(&rule.columns, analysis) {
        return false;
    }
    if !rule.agents.is_empty() && !match_value(&rule.agents, ctx.agent_key()) {
        return false;
    }
    if !rule.integrations.is_empty() && !match_value(&rule.integrations, &ctx.integration) {
        return false;
    }
    if !rule.tools.is_empty() && !match_value(&rule.tools, ctx.tool_key()) {
        return false;
    }
    if !rule.signals.is_empty()
        && !rule.signals.iter().any(|pattern| {
            analysis
                .risk_signals
                .iter()
                .any(|signal| glob_match(pattern, signal.name()))
        })
    {
        return false;
    }
    true
}

/// Operation candidates: kind names, category names, and the
/// `administrative` alias for admin operations (reference parity).
/// Top-level and nested operations both participate: a nested DELETE must
/// satisfy the same rules as a visible one.
fn operation_candidates(analysis: &QueryAnalysis) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for statement in &analysis.statements {
        for op in std::iter::once(&statement.operation).chain(&statement.nested_operations) {
            candidates.insert(op.name().to_owned());
            candidates.insert(op.category().name().to_owned());
            if op.category() == OpCategory::Admin {
                candidates.insert("administrative".to_owned());
            }
        }
    }
    candidates
}

fn match_operations(patterns: &[String], analysis: &QueryAnalysis) -> bool {
    let candidates = operation_candidates(analysis);
    patterns
        .iter()
        .any(|p| candidates.iter().any(|c| glob_match(p, c)))
}

fn match_schemas(patterns: &[String], analysis: &QueryAnalysis) -> bool {
    analysis
        .tables
        .iter()
        .filter_map(|t| t.schema.as_ref())
        .any(|schema| patterns.iter().any(|p| glob_match(p, &schema.value)))
}

fn match_tables(patterns: &[String], analysis: &QueryAnalysis) -> bool {
    analysis.tables.iter().any(|t| {
        let bare = t.name.value.clone();
        let qualified = match &t.schema {
            Some(schema) => format!("{}.{bare}", schema.value),
            None => bare.clone(),
        };
        // Three-part names add the fully-qualified form; the reference has
        // no equivalent, so this only ever matches policies the reference
        // could not express.
        let full = match (&t.database, &t.schema) {
            (Some(db), Some(schema)) => format!("{}.{}.{bare}", db.value, schema.value),
            _ => qualified.clone(),
        };
        patterns
            .iter()
            .any(|p| glob_match(p, &bare) || glob_match(p, &qualified) || glob_match(p, &full))
    })
}

fn column_strings(analysis: &QueryAnalysis) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for column in &analysis.columns {
        let name = match &column.name {
            ColumnName::Star => "*".to_owned(),
            ColumnName::Name(id) => id.value.clone(),
        };
        let qualifier: Vec<String> = column.qualifier.iter().map(|id| id.value.clone()).collect();
        candidates.insert(name.clone());
        if !qualifier.is_empty() {
            candidates.insert(format!("{}.{}", qualifier.join("."), name));
        }
    }
    // Cross-product with tables for unqualified columns, mirroring the
    // reference: an unqualified column may belong to any table present.
    for table in &analysis.tables {
        for column in &analysis.columns {
            if column.qualifier.is_empty() {
                let name = match &column.name {
                    ColumnName::Star => "*".to_owned(),
                    ColumnName::Name(id) => id.value.clone(),
                };
                let scoped = match &table.schema {
                    Some(schema) => {
                        format!("{}.{}.{}", schema.value, table.name.value, name)
                    }
                    None => format!("{}.{}", table.name.value, name),
                };
                candidates.insert(scoped);
            }
        }
    }
    candidates
}

fn match_columns(patterns: &[String], analysis: &QueryAnalysis) -> bool {
    let candidates = column_strings(analysis);
    patterns
        .iter()
        .any(|p| candidates.iter().any(|c| glob_match(p, c)))
}

fn match_value(patterns: &[String], value: &str) -> bool {
    patterns.iter().any(|p| glob_match(p, value))
}

struct SensitiveHit {
    qualified: String,
    table: String,
    column: String,
}

/// Faithful port of the reference sensitive-column search: unqualified
/// columns fan out to every table in the analysis; table lookup is
/// case-insensitive on both sides; each column tries `table.column`, bare,
/// then schema-qualified forms in order. `*` is an ordinary string here
/// (the reference never expands it against sensitive patterns).
fn find_sensitive_column(analysis: &QueryAnalysis, patterns: &[String]) -> Option<SensitiveHit> {
    let table_names: Vec<String> = analysis
        .tables
        .iter()
        .map(|t| t.name.value.clone())
        .collect();
    for column in &analysis.columns {
        let name = match &column.name {
            ColumnName::Star => "*".to_owned(),
            ColumnName::Name(id) => id.value.clone(),
        };
        let leading: Vec<String> = column.qualifier.iter().map(|id| id.value.clone()).collect();
        let fan_out: Vec<String> = if leading.is_empty() {
            table_names.clone()
        } else {
            leading[leading.len().saturating_sub(1)..].to_vec()
        };
        let fan_out = if fan_out.is_empty() {
            vec![String::new()]
        } else {
            fan_out
        };
        for table_name in fan_out {
            let table = analysis
                .tables
                .iter()
                .find(|t| t.name.value.to_lowercase() == table_name.to_lowercase());
            let schema_qualified = match table.and_then(|t| t.schema.as_ref()) {
                Some(schema) => format!("{}.{table_name}.{name}", schema.value),
                None => format!("{table_name}.{name}"),
            };
            for qualifier in [
                format!("{table_name}.{name}"),
                name.clone(),
                schema_qualified,
            ] {
                if patterns.iter().any(|p| glob_match(p, &qualifier)) {
                    return Some(SensitiveHit {
                        qualified: qualifier,
                        table: table_name.clone(),
                        column: name.clone(),
                    });
                }
            }
        }
    }
    None
}

fn describe_rule(rule: &PolicyRule) -> String {
    let mut parts = Vec::new();
    if !rule.operations.is_empty() {
        parts.push(format!("operations={}", rule.operations.join("|")));
    }
    if !rule.schemas.is_empty() {
        parts.push(format!("schemas={}", rule.schemas.join("|")));
    }
    if !rule.tables.is_empty() {
        parts.push(format!("tables={}", rule.tables.join("|")));
    }
    if !rule.columns.is_empty() {
        parts.push(format!("columns={}", rule.columns.join("|")));
    }
    if !rule.agents.is_empty() {
        parts.push(format!("agents={}", rule.agents.join("|")));
    }
    if !rule.integrations.is_empty() {
        parts.push(format!("integrations={}", rule.integrations.join("|")));
    }
    if !rule.tools.is_empty() {
        parts.push(format!("tools={}", rule.tools.join("|")));
    }
    if !rule.signals.is_empty() {
        parts.push(format!("signals={}", rule.signals.join("|")));
    }
    if parts.is_empty() {
        parts.push("match-all".to_owned());
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::{evaluate, EvaluateOptions, EvaluationRequest};
    use crate::context::ExecutionContext;
    use crate::decision::{Decision, ReasonCode};
    use crate::policy::parse_policy;
    use qk_sql::SqlDialect;

    const STANDARD: &str = "version: 1\ndefaults:\n  decision: deny\nenvironments:\n  production:\n    databases:\n      main:\n        allow:\n          - operations: [select]\n            schemas: [public]\n        deny:\n          - operations: [drop, truncate]\n        approval_required:\n          - operations: [update, delete, insert]\n        sensitive:\n          columns: [users.password_hash, \"*.api_key\"]\n        mutations:\n          deny_without_where: [update, delete]\n        row_safety:\n          max_limit: 1000\n";

    fn ctx() -> ExecutionContext {
        ExecutionContext {
            integration: "mcp".to_owned(),
            environment: "production".to_owned(),
            database: Some("main".to_owned()),
            agent_id: None,
            tool: None,
            session_id: None,
        }
    }

    fn decide(policy_yaml: &str, sql: &str) -> super::EvaluationResult {
        let policy = parse_policy(policy_yaml).expect("test policy");
        let context = ctx();
        evaluate(
            &EvaluationRequest {
                context: &context,
                dialect: SqlDialect::PostgreSql,
                sql,
                policy: &policy,
            },
            &EvaluateOptions::default(),
        )
    }

    #[test]
    fn precedence_matrix() {
        // allow + deny: deny wins.
        let policy = "version: 1\ndefaults:\n  decision: deny\nenvironments:\n  production:\n    databases:\n      main:\n        allow:\n          - operations: [delete]\n        deny:\n          - operations: [delete]\n";
        let r = decide(policy, "DELETE FROM t WHERE id = 1");
        assert_eq!(
            (r.decision, r.reason_code),
            (Decision::Deny, ReasonCode::DenyRule)
        );
        // deny + approval: deny wins.
        let policy = "version: 1\ndefaults:\n  decision: deny\nenvironments:\n  production:\n    databases:\n      main:\n        deny:\n          - operations: [delete]\n        approval_required:\n          - operations: [delete]\n";
        let r = decide(policy, "DELETE FROM t WHERE id = 1");
        assert_eq!(
            (r.decision, r.reason_code),
            (Decision::Deny, ReasonCode::DenyRule)
        );
        // allow + approval: approval wins (allow consulted last).
        let policy = "version: 1\ndefaults:\n  decision: deny\nenvironments:\n  production:\n    databases:\n      main:\n        allow:\n          - operations: [delete]\n        approval_required:\n          - operations: [delete]\n";
        let r = decide(policy, "DELETE FROM t WHERE id = 1");
        assert_eq!(
            (r.decision, r.reason_code),
            (Decision::RequireApproval, ReasonCode::RequireApproval)
        );
        // sensitive beats allow.
        let policy = "version: 1\ndefaults:\n  decision: deny\nenvironments:\n  production:\n    databases:\n      main:\n        allow:\n          - operations: [select]\n        sensitive:\n          columns: [users.password_hash]\n";
        let r = decide(policy, "SELECT password_hash FROM users LIMIT 1");
        assert_eq!(
            (r.decision, r.reason_code),
            (Decision::Deny, ReasonCode::SensitiveColumn)
        );
        assert_eq!(r.column.as_deref(), Some("password_hash"));
        assert_eq!(r.table.as_deref(), Some("users"));
        assert_eq!(
            r.matched_policy.as_deref(),
            Some("production.main.sensitive")
        );
        // unbounded beats approval.
        let r = decide(STANDARD, "DELETE FROM customers");
        assert_eq!(
            (r.decision, r.reason_code),
            (Decision::Deny, ReasonCode::UnboundedDelete)
        );
        // scoped allow vs default deny: unknown database falls through.
        let policy = parse_policy(STANDARD).expect("policy");
        let mut other = ctx();
        other.database = Some("other".to_owned());
        let r = evaluate(
            &EvaluationRequest {
                context: &other,
                dialect: SqlDialect::PostgreSql,
                sql: "SELECT 1",
                policy: &policy,
            },
            &EvaluateOptions::default(),
        );
        assert_eq!(
            (r.decision, r.reason_code),
            (Decision::Deny, ReasonCode::DefaultDeny)
        );
        assert_eq!(r.matched_policy.as_deref(), Some("defaults.decision"));
    }

    #[test]
    fn wildcard_scope_and_specificity() {
        let policy = "version: 1\ndefaults:\n  decision: deny\nenvironments:\n  production:\n    databases:\n      '*':\n        allow:\n          - operations: [select]\n      main:\n        deny:\n          - operations: [select]\n";
        // Exact scope beats wildcard.
        let r = decide(policy, "SELECT 1");
        assert_eq!(
            (r.decision, r.reason_code),
            (Decision::Deny, ReasonCode::DenyRule)
        );
        assert_eq!(r.matched_policy.as_deref(), Some("production.main.deny[0]"));
        // Wildcard serves other databases.
        let parsed = parse_policy(policy).expect("policy");
        let mut other = ctx();
        other.database = Some("analytics".to_owned());
        let r = evaluate(
            &EvaluationRequest {
                context: &other,
                dialect: SqlDialect::PostgreSql,
                sql: "SELECT 1",
                policy: &parsed,
            },
            &EvaluateOptions::default(),
        );
        assert_eq!(
            (r.decision, r.reason_code),
            (Decision::Allow, ReasonCode::AllowRule)
        );
        assert_eq!(r.matched_policy.as_deref(), Some("production.*.allow[0]"));
    }

    #[test]
    fn grant_without_explicit_rule_falls_to_default() {
        // Frozen regression: GRANT is not covered by the standard policy, so
        // it yields DEFAULT_DENY, not DENY_RULE. Do not "correct" this.
        let r = decide(STANDARD, "GRANT SELECT ON customers TO analyst");
        assert_eq!(
            (r.decision, r.reason_code),
            (Decision::Deny, ReasonCode::DefaultDeny)
        );
        assert_eq!(r.matched_policy.as_deref(), Some("defaults.decision"));
    }

    #[test]
    fn call_is_unknown_not_default() {
        // Reference parity: CALL fails closed via on_unknown even though the
        // operation has an Admin-adjacent shape in our model.
        let r = decide(STANDARD, "CALL refresh_reports()");
        assert_eq!(
            (r.decision, r.reason_code),
            (Decision::Deny, ReasonCode::DenyUnknownStatement)
        );
        assert_eq!(r.matched_policy.as_deref(), Some("defaults.on_unknown"));
    }

    #[test]
    fn nested_delete_requires_approval_not_plain_read() {
        // Deliberate divergence: the reference cannot parse data-modifying
        // CTEs (DENY_PARSE_ERROR); we see the nested DELETE and hold it for
        // approval, exactly as restrictive as a directly visible bounded
        // DELETE under the same policy.
        let r = decide(
            STANDARD,
            "WITH deleted AS (DELETE FROM customers WHERE id = 10 RETURNING *) SELECT * FROM deleted",
        );
        assert_eq!(
            (r.decision, r.reason_code),
            (Decision::RequireApproval, ReasonCode::RequireApproval)
        );
        let direct = decide(STANDARD, "DELETE FROM customers WHERE id = 10");
        assert_eq!(direct.decision, r.decision);
        assert_eq!(direct.reason_code, r.reason_code);
    }

    #[test]
    fn nested_unbounded_delete_denies() {
        // A nested DELETE without WHERE is as dangerous as a top-level one.
        let r = decide(
            STANDARD,
            "WITH deleted AS (DELETE FROM customers RETURNING *) SELECT * FROM deleted",
        );
        assert_eq!(
            (r.decision, r.reason_code),
            (Decision::Deny, ReasonCode::UnboundedDelete)
        );
    }

    #[test]
    fn failure_paths_never_allow() {
        for (sql, code) in [
            ("FROBNICATE THE t !!", ReasonCode::DenyParseError),
            ("CALL refresh_reports()", ReasonCode::DenyUnknownStatement),
            ("   ", ReasonCode::EmptyQuery),
        ] {
            let r = decide(STANDARD, sql);
            assert_eq!(r.decision, Decision::Deny, "{sql:?}");
            assert_eq!(r.reason_code, code, "{sql:?}");
        }
        // AST error + defensive SELECT-only evidence stays DENY.
        let r = decide(STANDARD, "SELECT FROBNICATE !!");
        assert_eq!(r.decision, Decision::Deny);
    }

    #[test]
    fn empty_and_oversized_envelope() {
        let r = decide(STANDARD, "   ");
        assert_eq!(r.reason_code, ReasonCode::EmptyQuery);
        assert!(r.matched_policy.is_none());
        let policy = parse_policy(STANDARD).expect("policy");
        let context = ctx();
        let big = "SELECT 1".to_owned() + &" + 1".repeat(300_000);
        let r = evaluate(
            &EvaluationRequest {
                context: &context,
                dialect: SqlDialect::PostgreSql,
                sql: &big,
                policy: &policy,
            },
            &EvaluateOptions { max_bytes: 4 },
        );
        assert_eq!(
            (r.decision, r.reason_code),
            (Decision::Deny, ReasonCode::QueryTooLarge)
        );
    }

    #[test]
    fn row_limits() {
        let r = decide(STANDARD, "SELECT * FROM public.customers LIMIT 5000");
        assert_eq!(
            (r.decision, r.reason_code),
            (Decision::Deny, ReasonCode::LimitExceeded)
        );
        assert_eq!(r.operation.as_deref(), Some("select"));
        let r = decide(STANDARD, "SELECT * FROM public.customers LIMIT 1000");
        assert_eq!(
            (r.decision, r.reason_code),
            (Decision::Allow, ReasonCode::AllowRule)
        );
    }

    #[test]
    fn agent_tool_and_signal_scoping() {
        let policy = "version: 1\ndefaults:\n  decision: deny\nenvironments:\n  production:\n    databases:\n      main:\n        allow:\n          - operations: [select]\n            agents: [etl-*]\n            tools: [db_query]\n";
        let parsed = parse_policy(policy).expect("policy");
        let mut context = ctx();
        context.agent_id = Some("etl-nightly".to_owned());
        context.tool = Some("db_query".to_owned());
        let r = evaluate(
            &EvaluationRequest {
                context: &context,
                dialect: SqlDialect::PostgreSql,
                sql: "SELECT 1",
                policy: &parsed,
            },
            &EvaluateOptions::default(),
        );
        assert_eq!(r.decision, Decision::Allow);
        context.agent_id = Some("intruder".to_owned());
        let r = evaluate(
            &EvaluationRequest {
                context: &context,
                dialect: SqlDialect::PostgreSql,
                sql: "SELECT 1",
                policy: &parsed,
            },
            &EvaluateOptions::default(),
        );
        assert_eq!(r.decision, Decision::Deny);
    }
}
