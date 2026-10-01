//! The single observation hook: one guarded authorization/execution attempt
//! in, one audit event plus metric increments out. Sinks and the registry
//! are owned here (no globals); failures are returned for operational
//! visibility and never feed back into authorization.

use std::sync::Arc;

use qk_core::{Decision, ReasonCode};
use qk_metrics::MetricsRegistry;

use crate::event::AuditEvent;
use crate::level::SqlLogLevel;
use crate::observation::{Observation, ObservedApproval, ObservedExecution};
use crate::sink::{AuditSink, AuditSinkError};

/// Observation point: audit sinks + metrics registry behind one call.
/// Clone shares both (suitable for server state).
#[derive(Clone, Default)]
pub struct Observer {
    sinks: Vec<Arc<dyn AuditSink>>,
    metrics: Arc<MetricsRegistry>,
}

impl Observer {
    /// Build from explicit sinks (empty = metrics only). No globals.
    pub fn new(sinks: Vec<Arc<dyn AuditSink>>) -> Self {
        Self {
            sinks,
            metrics: Arc::new(MetricsRegistry::new()),
        }
    }

    /// Shared metrics registry (powers renderers/tests).
    pub fn metrics(&self) -> &MetricsRegistry {
        &self.metrics
    }

    /// Observe one completed attempt: render the audit event at
    /// `level`, record it to every sink, and increment metrics from
    /// typed facts. Returns sink failures for operational visibility
    /// (log to stderr, bounded); metrics updates are infallible.
    /// Exactly one audit event per call — never per pipeline stage.
    pub fn observe(&self, observation: &Observation, level: SqlLogLevel) -> Vec<AuditSinkError> {
        let event = observation.audit_event(level);
        let mut failures = Vec::new();
        for sink in &self.sinks {
            if let Err(error) = sink.record(&event) {
                failures.push(error);
            }
        }
        record_metrics(&self.metrics, observation, &event);
        failures
    }
}

/// Increment frozen metrics from typed observation facts (never by
/// parsing strings).
fn record_metrics(registry: &MetricsRegistry, observation: &Observation, event: &AuditEvent) {
    let database = observation.database.as_deref().unwrap_or("");
    let base = [
        ("integration", observation.integration.as_str()),
        ("environment", observation.environment.as_str()),
        ("database", database),
        ("operation", event.operation.as_str()),
    ];
    registry.counter(qk_metrics::REQUESTS_TOTAL, &base, 1);
    let decision = match observation.decision {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
        Decision::RequireApproval => "require_approval",
    };
    let mut decision_labels = base.to_vec();
    decision_labels.push(("decision", decision));
    decision_labels.push(("reason_code", observation.reason_code.as_str()));
    registry.counter(qk_metrics::DECISIONS_TOTAL, &decision_labels, 1);
    if observation.decision == Decision::Deny {
        let mut deny_labels = base.to_vec();
        deny_labels.push(("reason_code", observation.reason_code.as_str()));
        registry.counter(qk_metrics::POLICY_DENIALS_TOTAL, &deny_labels, 1);
    }
    if !event.parser_ok {
        registry.counter(
            qk_metrics::PARSE_ERRORS_TOTAL,
            &[
                ("integration", observation.integration.as_str()),
                ("dialect", event.dialect.as_str()),
            ],
            1,
        );
    }
    // Approval counter (frozen): APPROVAL_GRANTED → approved,
    // APPROVAL_DENIED → denied, everything else approval-shaped
    // (pending/unavailable/error) → waiting.
    let approval_result = match &observation.approval {
        ObservedApproval::None => {
            let code = observation.reason_code.as_str();
            if !code.starts_with("APPROVAL_") {
                None
            } else if code == ReasonCode::ApprovalDenied.as_str() {
                Some("denied")
            } else {
                Some("waiting")
            }
        }
        ObservedApproval::Waiting { .. } => Some("waiting"),
        ObservedApproval::Resolved { approved, .. } => {
            Some(if *approved { "approved" } else { "denied" })
        }
        ObservedApproval::Unavailable | ObservedApproval::Error => Some("waiting"),
    };
    if let Some(result) = approval_result {
        let mut approval_labels = base.to_vec();
        approval_labels.push(("result", result));
        registry.counter(qk_metrics::APPROVAL_REQUESTS_TOTAL, &approval_labels, 1);
    }
    if let Some(duration_ms) = observation.evaluation_duration_ms {
        registry.observe_duration_seconds(
            qk_metrics::EVALUATION_DURATION_SECONDS,
            duration_ms as f64 / 1000.0,
        );
    }
}

/// Build the approval observation from a typed resolution outcome.
/// Kept beside the observer so all integrations map identically.
pub fn observed_approval_from_outcome(outcome: &qk_db::ExecutionOutcome) -> ObservedApproval {
    match outcome {
        qk_db::ExecutionOutcome::Executed(report) => match report.approval_id.as_ref() {
            Some(id) => ObservedApproval::Resolved {
                id: Some(id.as_str().to_owned()),
                approved: true,
            },
            None => ObservedApproval::None,
        },
        qk_db::ExecutionOutcome::Blocked(reason) => {
            // Approval-refused executions (unavailable/denied/error)
            // surface as blocked denies; only the code distinguishes.
            let _ = reason;
            ObservedApproval::None
        }
        qk_db::ExecutionOutcome::PendingApproval(pending) => ObservedApproval::Waiting {
            id: pending.approval_id.clone(),
        },
        qk_db::ExecutionOutcome::Failed(_) => ObservedApproval::None,
    }
}

/// Build the execution observation from a typed outcome.
pub fn observed_execution_from_outcome(outcome: &qk_db::ExecutionOutcome) -> ObservedExecution {
    match outcome {
        qk_db::ExecutionOutcome::Executed(report) => ObservedExecution::Done {
            rows_affected: report.result.rows_affected,
            rows_shown: report.result.rows_shown,
            truncated: report.result.truncated,
        },
        qk_db::ExecutionOutcome::Blocked(_) => ObservedExecution::Refused,
        qk_db::ExecutionOutcome::PendingApproval(_) => ObservedExecution::Pending,
        qk_db::ExecutionOutcome::Failed(error) => ObservedExecution::Failed {
            kind: error.kind().clone(),
            message: error.message().to_owned(),
            may_still_run: *error.kind() == qk_db::DbErrorKind::Timeout,
        },
    }
}
