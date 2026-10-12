//! Observation: one guarded authorization/execution attempt distilled into
//! audit inputs. Derived from typed policy/approval outcomes plus structural
//! facts re-read from `qk-sql` analysis (deterministic, side-effect-free —
//! never a second policy evaluation and never an approval contact).

use qk_core::{Decision, ReasonCode};
use qk_db::{AuthorizationOutcome, DbErrorKind, ExecutionOutcome};
use qk_sql::SqlDialect;

use crate::event::level_sql;
use crate::event::{timestamp_iso, AttemptOutcome, AuditDecision, AuditEvent};
use crate::level::SqlLogLevel;

/// Approval facts for an observed attempt, from typed resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservedApproval {
    /// No approval involved (direct allow/deny).
    None,
    /// Waiting on a human (opaque public id).
    Waiting {
        /// Public approval id.
        id: String,
    },
    /// Resolved with a verdict.
    Resolved {
        /// Public approval id, when known.
        id: Option<String>,
        /// Human approved.
        approved: bool,
    },
    /// No provider configured.
    Unavailable,
    /// Provider call failed.
    Error,
}

/// Authorization/execution facts for an observed attempt, from its typed outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservedExecution {
    /// Authorized for an external executor; this process did not execute the statement.
    Authorized,
    /// Refused without database contact.
    Refused,
    /// Waiting on a human (no contact).
    Pending,
    /// Statement executed.
    Done {
        /// Rows changed, when reported.
        rows_affected: Option<u64>,
        /// Rows shown.
        rows_shown: usize,
        /// Any budget cut.
        truncated: bool,
    },
    /// Authorized but the database failed.
    Failed {
        /// Normalized error kind.
        kind: DbErrorKind,
        /// Bounded normalized detail.
        message: String,
        /// Timeout uncertainty preserved.
        may_still_run: bool,
    },
}

/// One completed authorization/execution attempt: everything the observer
/// needs, nothing it must infer. Identity/timing inputs are caller-supplied.
#[derive(Debug, Clone)]
pub struct Observation {
    /// UUID v4 event id (caller-supplied; CSPRNG in production).
    pub event_id: String,
    /// Observation timestamp in millis since epoch (caller-supplied).
    pub timestamp_ms: u64,
    /// Handling duration in ms (caller-measured).
    pub duration_ms: u64,
    /// Evaluation duration in ms, when separately measured (feeds the
    /// evaluation-duration histogram; total handling time is NOT
    /// mislabeled as evaluation time).
    pub evaluation_duration_ms: Option<u64>,
    /// Optional correlating request id.
    pub request_id: Option<String>,
    /// Integration name (trusted).
    pub integration: String,
    /// Environment scope (trusted).
    pub environment: String,
    /// Database key (trusted), when any.
    pub database: Option<String>,
    /// Agent identity, when any.
    pub agent_id: Option<String>,
    /// Session identity, when any.
    pub session_id: Option<String>,
    /// Human user, when any.
    pub user: Option<String>,
    /// Tool source, when any.
    pub tool: Option<String>,
    /// Analysis dialect (trusted).
    pub dialect: SqlDialect,
    /// Untrusted SQL text (level-gated before storage).
    pub sql: String,
    /// Final verdict.
    pub decision: Decision,
    /// Machine reason code.
    pub reason_code: ReasonCode,
    /// Decisive policy path, when any.
    pub matched_policy: Option<String>,
    /// Approval facts.
    pub approval: ObservedApproval,
    /// Execution facts.
    pub execution: ObservedExecution,
}

impl Observation {
    /// Build from a guarded `ExecutionOutcome` plus trusted context.
    /// Structural facts (operation, tables, statements, parser status)
    /// are re-read from `qk-sql` analysis of the same SQL+dialect.
    #[allow(clippy::too_many_arguments)]
    pub fn from_outcome(
        event_id: String,
        timestamp_ms: u64,
        duration_ms: u64,
        evaluation_duration_ms: Option<u64>,
        request_id: Option<String>,
        integration: String,
        environment: String,
        database: Option<String>,
        agent_id: Option<String>,
        session_id: Option<String>,
        user: Option<String>,
        tool: Option<String>,
        dialect: SqlDialect,
        sql: String,
        outcome: &ExecutionOutcome,
    ) -> Self {
        let (decision, reason_code, matched_policy, approval, execution) = match outcome {
            ExecutionOutcome::Executed(report) => (
                Decision::Allow,
                report.reason_code,
                report.matched_policy.clone(),
                match report.approval_id.as_ref() {
                    Some(id) => ObservedApproval::Resolved {
                        id: Some(id.as_str().to_owned()),
                        approved: true,
                    },
                    None => ObservedApproval::None,
                },
                ObservedExecution::Done {
                    rows_affected: report.result.rows_affected,
                    rows_shown: report.result.rows_shown,
                    truncated: report.result.truncated,
                },
            ),
            ExecutionOutcome::Blocked(reason) => (
                Decision::Deny,
                parse_reason(&reason.code),
                reason.matched_policy.clone(),
                ObservedApproval::None,
                ObservedExecution::Refused,
            ),
            ExecutionOutcome::PendingApproval(pending) => (
                Decision::RequireApproval,
                parse_reason(&pending.reason_code),
                None,
                ObservedApproval::Waiting {
                    id: pending.approval_id.clone(),
                },
                ObservedExecution::Pending,
            ),
            ExecutionOutcome::Failed(error) => (
                // The statement WAS authorized (execution reached the
                // adapter): audit decision Allow with a failed outcome,
                // never a Deny.
                Decision::Allow,
                ReasonCode::ApprovalError,
                None,
                ObservedApproval::None,
                ObservedExecution::Failed {
                    kind: error.kind().clone(),
                    message: error.message().to_owned(),
                    may_still_run: *error.kind() == DbErrorKind::Timeout,
                },
            ),
        };
        Self {
            event_id,
            timestamp_ms,
            duration_ms,
            evaluation_duration_ms,
            request_id,
            integration,
            environment,
            database,
            agent_id,
            session_id,
            user,
            tool,
            dialect,
            sql,
            decision,
            reason_code,
            matched_policy,
            approval,
            execution,
        }
    }

    /// Build from a zero-database-contact authorization outcome.
    ///
    /// A permitted capability becomes `Authorized`, never `Done`; callers
    /// must drop the permit after extracting these safe decision facts.
    #[allow(clippy::too_many_arguments)]
    pub fn from_authorization_outcome(
        event_id: String,
        timestamp_ms: u64,
        duration_ms: u64,
        evaluation_duration_ms: Option<u64>,
        request_id: Option<String>,
        integration: String,
        environment: String,
        database: Option<String>,
        agent_id: Option<String>,
        session_id: Option<String>,
        user: Option<String>,
        tool: Option<String>,
        dialect: SqlDialect,
        sql: String,
        outcome: &AuthorizationOutcome,
    ) -> Self {
        let (decision, reason_code, matched_policy, approval, execution) = match outcome {
            AuthorizationOutcome::Permitted(permit) => (
                Decision::Allow,
                *permit.reason_code(),
                permit.matched_policy().map(str::to_owned),
                permit
                    .approval_id()
                    .map(|id| ObservedApproval::Resolved {
                        id: Some(id.as_str().to_owned()),
                        approved: true,
                    })
                    .unwrap_or(ObservedApproval::None),
                ObservedExecution::Authorized,
            ),
            AuthorizationOutcome::Blocked(reason) => {
                let reason_code = parse_reason(&reason.code);
                let approval = match reason_code {
                    ReasonCode::ApprovalUnavailable => ObservedApproval::Unavailable,
                    ReasonCode::ApprovalError => ObservedApproval::Error,
                    ReasonCode::ApprovalDenied => ObservedApproval::Resolved {
                        id: None,
                        approved: false,
                    },
                    _ => ObservedApproval::None,
                };
                (
                    Decision::Deny,
                    reason_code,
                    reason.matched_policy.clone(),
                    approval,
                    ObservedExecution::Refused,
                )
            }
            AuthorizationOutcome::PendingApproval(pending) => (
                Decision::RequireApproval,
                parse_reason(&pending.reason_code),
                None,
                ObservedApproval::Waiting {
                    id: pending.approval_id.clone(),
                },
                ObservedExecution::Pending,
            ),
            AuthorizationOutcome::Failed(_) => (
                Decision::Deny,
                ReasonCode::PolicyError,
                None,
                ObservedApproval::None,
                ObservedExecution::Refused,
            ),
        };
        Self {
            event_id,
            timestamp_ms,
            duration_ms,
            evaluation_duration_ms,
            request_id,
            integration,
            environment,
            database,
            agent_id,
            session_id,
            user,
            tool,
            dialect,
            sql,
            decision,
            reason_code,
            matched_policy,
            approval,
            execution,
        }
    }

    /// Render the frozen `AuditEvent` at a SQL log level.
    pub fn audit_event(&self, level: SqlLogLevel) -> AuditEvent {
        let analysis = qk_sql::analyze(&self.sql, &self.dialect.to_string()).ok();
        let (operation, kinds, tables, columns, statements, parser_ok) = match analysis.as_ref() {
            Some(analysis) => (
                analysis
                    .statements
                    .first()
                    .map(|statement| statement.operation.name())
                    .unwrap_or("unknown"),
                analysis
                    .operations
                    .iter()
                    .map(|operation| operation.name().to_owned())
                    .collect::<Vec<_>>(),
                analysis.tables.iter().map(table_name).collect::<Vec<_>>(),
                analysis.columns.iter().map(column_name).collect::<Vec<_>>(),
                analysis.statements.len(),
                // Parsed cleanly (truncation is a completeness
                // signal, not a parse failure).
                true,
            ),
            None => ("unknown", Vec::new(), Vec::new(), Vec::new(), 0, false),
        };
        let (normalized_sql, sql) = level_sql(&self.sql, level);
        let (
            outcome,
            error_kind,
            error_message,
            rows_affected,
            rows_shown,
            truncated,
            timeout_may_still_run,
        ) = match &self.execution {
            ObservedExecution::Authorized => (
                AttemptOutcome::Authorized,
                None,
                None,
                None,
                None,
                None,
                None,
            ),
            ObservedExecution::Refused => {
                (AttemptOutcome::Blocked, None, None, None, None, None, None)
            }
            ObservedExecution::Pending => {
                (AttemptOutcome::Pending, None, None, None, None, None, None)
            }
            ObservedExecution::Done {
                rows_affected,
                rows_shown,
                truncated,
            } => (
                AttemptOutcome::Executed,
                None,
                None,
                *rows_affected,
                Some(*rows_shown),
                Some(*truncated),
                None,
            ),
            ObservedExecution::Failed {
                kind,
                message,
                may_still_run,
            } => (
                AttemptOutcome::Failed,
                Some(db_error_kind_name(kind)),
                Some(message.clone()),
                None,
                None,
                None,
                // Uncertainty preserved only for timeouts; other
                // failures carry no may-still-run claim at all.
                may_still_run.then_some(true),
            ),
        };
        let approval_id = match &self.approval {
            ObservedApproval::None | ObservedApproval::Unavailable | ObservedApproval::Error => {
                None
            }
            ObservedApproval::Waiting { id } => Some(id.clone()),
            ObservedApproval::Resolved { id, .. } => id.clone(),
        };
        AuditEvent {
            timestamp: timestamp_iso(self.timestamp_ms),
            event_id: self.event_id.clone(),
            request_id: self.request_id.clone(),
            agent_id: self.agent_id.clone(),
            session_id: self.session_id.clone(),
            integration: self.integration.clone(),
            environment: self.environment.clone(),
            database: self.database.clone(),
            user: self.user.clone(),
            tool: self.tool.clone(),
            dialect: dialect_name(&self.dialect),
            statements,
            operation: operation.to_owned(),
            kinds,
            tables,
            columns: level.includes_metadata().then_some(columns),
            fingerprint: qk_core::sql_fingerprint(&self.sql).as_str().to_owned(),
            normalized_sql,
            sql,
            decision: match self.decision {
                Decision::Allow => AuditDecision::Allow,
                Decision::Deny => AuditDecision::Deny,
                Decision::RequireApproval => AuditDecision::RequireApproval,
            },
            reason_code: self.reason_code.as_str().to_owned(),
            matched_policy: self.matched_policy.clone(),
            approval_id,
            duration_ms: self.duration_ms,
            parser_ok,
            enforced: true,
            outcome,
            error_kind,
            error_message,
            rows_affected,
            rows_shown,
            truncated,
            timeout_may_still_run,
        }
    }
}

fn parse_reason(code: &str) -> ReasonCode {
    match code {
        "UNSUPPORTED_SQL_ANALYSIS" => ReasonCode::DenyParseError,
        "UNSUPPORTED_OPERATION" => ReasonCode::DenyUnknownStatement,
        _ => qk_core::parse_reason_code(code).unwrap_or(ReasonCode::ApprovalError),
    }
}
/// Frozen engine-name dialect rendering (`postgres`, not
/// `postgresql` — matches the reference analysis dialect strings).
fn dialect_name(dialect: &SqlDialect) -> String {
    match dialect {
        SqlDialect::PostgreSql => "postgres".to_owned(),
        SqlDialect::MySql => "mysql".to_owned(),
        SqlDialect::Sqlite => "sqlite".to_owned(),
    }
}

fn db_error_kind_name(kind: &DbErrorKind) -> String {
    match kind {
        DbErrorKind::Connection => "connection",
        DbErrorKind::Authentication => "authentication",
        DbErrorKind::Timeout => "timeout",
        DbErrorKind::Query => "query",
        DbErrorKind::Constraint => "constraint",
        DbErrorKind::Unsupported => "unsupported",
        DbErrorKind::Transport => "transport",
        DbErrorKind::Protocol => "protocol",
        DbErrorKind::Internal => "internal",
    }
    .to_owned()
}

fn table_name(table: &qk_sql::TableRef) -> String {
    table.to_string()
}

/// Frozen `table.column` / `column` rendering.
fn column_name(column: &qk_sql::ColumnRef) -> String {
    let mut parts: Vec<String> = column
        .qualifier
        .iter()
        .map(|identifier| identifier.value.clone())
        .collect();
    parts.push(match &column.name {
        qk_sql::ColumnName::Star => "*".to_owned(),
        qk_sql::ColumnName::Name(identifier) => identifier.value.clone(),
    });
    parts.join(".")
}

/// Canned event for sink unit tests (deterministic, secret-free).
#[cfg(test)]
pub fn test_event() -> AuditEvent {
    use crate::event::AttemptOutcome;
    AuditEvent {
        timestamp: "2026-09-30T12:00:00.000Z".to_owned(),
        event_id: "00000000-0000-4000-8000-000000000000".to_owned(),
        request_id: None,
        agent_id: None,
        session_id: None,
        integration: "test".to_owned(),
        environment: "production".to_owned(),
        database: None,
        user: None,
        tool: None,
        dialect: "sqlite".to_owned(),
        statements: 1,
        operation: "select".to_owned(),
        kinds: vec!["select".to_owned()],
        tables: vec![],
        columns: None,
        fingerprint: "0d2e6c16b5960f15".to_owned(),
        normalized_sql: None,
        sql: None,
        decision: crate::event::AuditDecision::Allow,
        reason_code: "ALLOW_RULE".to_owned(),
        matched_policy: None,
        approval_id: None,
        duration_ms: 1,
        parser_ok: true,
        enforced: true,
        outcome: AttemptOutcome::Executed,
        error_kind: None,
        error_message: None,
        rows_affected: None,
        rows_shown: Some(1),
        truncated: Some(false),
        timeout_may_still_run: None,
    }
}
