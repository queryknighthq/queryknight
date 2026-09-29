//! History recording: best-effort `POST /events` after each tool
//! outcome, mirroring the frozen `track()` behavior. Execution results
//! are authoritative; history failure is diagnostic only and never
//! changes outcomes or triggers re-execution.
//!
//! The recorded SQL text follows the frozen contract (the reference
//! sends full SQL to daemon history); no credentials are ever
//! recorded (connection keys are password-stripped upstream).

use qk_control_plane::ControlPlaneClient;

pub use qk_control_plane::classify_sql_for_history as classify_for_history;

/// Best-effort history recorder: daemon endpoint plus session binding.
/// `None` (daemon down) disables recording; tools run unchanged.
#[derive(Debug, Clone)]
pub struct HistoryRecorder {
    client: ControlPlaneClient,
    session_id: String,
    connection_key: String,
}

impl HistoryRecorder {
    /// Start a session (`POST /sessions`, source `mcp`) and bind the
    /// recorder. `None` when the daemon is unreachable.
    pub fn start(client: &ControlPlaneClient, connection_key: &str) -> Option<Self> {
        let session_id = client.create_session(connection_key, "mcp").ok()?;
        Some(Self {
            client: client.clone(),
            session_id,
            connection_key: connection_key.to_owned(),
        })
    }

    /// Session id for approval scope binding.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Record one tool outcome. Fire-and-forget semantics: failures
    /// are swallowed (best-effort, frozen `track()` catch).
    pub fn record(&self, event: HistoryEvent) {
        let (class, risk) = classify_for_history(&event.sql);
        let fingerprint = qk_core::sql_fingerprint(&event.sql);
        let body = serde_json::json!({
            "sessionId": self.session_id,
            "connectionKey": self.connection_key,
            "source": "mcp",
            "sql": event.sql,
            "sqlFingerprint": fingerprint.as_str(),
            "classification": {"class": class, "risk": risk},
            "decision": event.decision,
            "durationMs": event.duration_ms,
            "rowsReturned": event.rows_returned,
            "rowsAffected": event.rows_affected,
            "bytesReturned": event.bytes_returned,
            "estimatedTokensReturned": event.estimated_tokens_returned,
            "estimatedTokensAvoided": event.estimated_tokens_avoided,
            "errorCode": event.error_code,
        });
        let _ = self.client.record_event(&body);
    }
}

/// One tool-call outcome for history (frozen field set).
#[derive(Debug, Clone, Default)]
pub struct HistoryEvent {
    /// SQL text (frozen: full text recorded).
    pub sql: String,
    /// Outcome decision (`executed`, `denied`, `expired`, `error`).
    pub decision: Option<String>,
    /// Error code for failures (bounded driver/policy text).
    pub error_code: Option<String>,
    /// Wall duration in ms.
    pub duration_ms: Option<u64>,
    /// Result counters (success path).
    pub rows_returned: Option<usize>,
    /// Result counters (success path).
    pub rows_affected: Option<u64>,
    /// Result counters (success path).
    pub bytes_returned: Option<usize>,
    /// Result counters (success path).
    pub estimated_tokens_returned: Option<usize>,
    /// Result counters (success path).
    pub estimated_tokens_avoided: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_classification() {
        assert_eq!(classify_for_history("SELECT 1"), ("read", "low"));
        assert_eq!(classify_for_history("  delete FROM t"), ("write", "high"));
        assert_eq!(
            classify_for_history("DROP TABLE t"),
            ("destructive", "critical")
        );
        assert_eq!(classify_for_history("VACUUM"), ("unknown", "unknown"));
    }
}
