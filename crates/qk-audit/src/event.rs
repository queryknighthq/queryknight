//! Frozen `AuditEvent` model: typed construction, stable JSON
//! serialization (absent optionals omitted, never `null`).

use serde::Serialize;

use crate::level::{truncate_chars, SqlLogLevel, MAX_SQL_LOG_CHARS};

/// Audit decision (frozen lowercase values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditDecision {
    /// The statement may execute (or did).
    Allow,
    /// The statement must not execute.
    Deny,
    /// A human must decide / is deciding.
    RequireApproval,
}

/// Authorization/execution phase of one observed attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AttemptOutcome {
    /// Authorized by QueryKnight for an external executor; QueryKnight did not execute it.
    Authorized,
    /// The statement executed.
    Executed,
    /// Refused without database contact.
    Blocked,
    /// Waiting on a human decision.
    Pending,
    /// Authorized but the database failed.
    Failed,
}

/// Frozen audit event. All identity/timing inputs are caller-supplied
/// (deterministic tests, no hidden clocks).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEvent {
    /// ISO-8601 timestamp (caller-supplied millis).
    pub timestamp: String,
    /// UUID v4 event id (caller-supplied; CSPRNG in production).
    pub event_id: String,
    /// Correlating request id, when any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Agent identity, when any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Session identity, when any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Integration name (trusted).
    pub integration: String,
    /// Environment scope (trusted).
    pub environment: String,
    /// Database key (trusted), when any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    /// Human user, when any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Tool/operation source, when any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Analysis dialect (trusted).
    pub dialect: String,
    /// Statement count.
    pub statements: usize,
    /// Primary operation (`select`, `update`, ...; `unknown` when
    /// analysis failed).
    pub operation: String,
    /// Operation kinds present.
    pub kinds: Vec<String>,
    /// Referenced tables (`schema.name` or `name`).
    pub tables: Vec<String>,
    /// Referenced columns (`table.column` or `column`; metadata+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub columns: Option<Vec<String>>,
    /// 16-hex shape fingerprint (always present).
    pub fingerprint: String,
    /// Literal-stripped normalized SQL (metadata+; bounded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized_sql: Option<String>,
    /// Raw SQL text (full_sql only; bounded; may contain secrets).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sql: Option<String>,
    /// Final verdict.
    pub decision: AuditDecision,
    /// Machine reason code.
    pub reason_code: String,
    /// Decisive policy path, when any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_policy: Option<String>,
    /// Opaque public approval id, when any (never digests).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    /// Handling duration in ms.
    pub duration_ms: u64,
    /// The SQL parsed cleanly.
    pub parser_ok: bool,
    /// Enforcement active (always true; observe mode is not ported).
    pub enforced: bool,
    /// Authorization/execution outcome. `Authorized` never means that an external operation ran.
    pub outcome: AttemptOutcome,
    /// Database error kind, when failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    /// Bounded normalized DB error detail, when failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    /// Rows changed by an executed mutation, when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows_affected: Option<u64>,
    /// Rows shown by an executed read, when executed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows_shown: Option<usize>,
    /// Any budget cut occurred, when executed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    /// The timeout may still be running server-side (uncertainty
    /// preserved, never "rolled back").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_may_still_run: Option<bool>,
}

/// Level-gated SQL/normalized attachment. Pure helper so builders
/// and tests share the exact inclusion rules.
pub fn level_sql(sql: &str, level: SqlLogLevel) -> (Option<String>, Option<String>) {
    let normalized = level
        .includes_metadata()
        .then(|| truncate_chars(&qk_core::normalize_sql(sql), MAX_SQL_LOG_CHARS).to_owned());
    let raw = level
        .includes_raw_sql()
        .then(|| truncate_chars(sql, MAX_SQL_LOG_CHARS).to_owned());
    (normalized, raw)
}

/// Milliseconds since Unix epoch → ISO-8601 UTC (`2026-09-30T…Z`,
/// millis precision). Pure civil math, no clock, no chrono.
pub fn timestamp_iso(millis: u64) -> String {
    let secs = millis / 1000;
    let ms = millis % 1000;
    let days = (secs / 86_400) as i64;
    let day_secs = (secs % 86_400) as u32;
    let (year, month, day) = civil_from_unix_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{ms:03}Z",
        hour = day_secs / 3_600,
        minute = (day_secs / 60) % 60,
        second = day_secs % 60,
    )
}

/// Unix days → (year, month, day) (Hinnant algorithm).
fn civil_from_unix_days(days: i64) -> (i32, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let doe = shifted.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if month <= 2 { year + 1 } else { year };
    (year as i32, month, day)
}

/// Random UUID v4 event id (OS CSPRNG; tests supply fixed ids).
pub fn new_event_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("system randomness available");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
        bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_and_ids() {
        assert_eq!(timestamp_iso(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(timestamp_iso(1_790_769_600_123), "2026-09-30T12:00:00.123Z");
        let id = new_event_id();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert!(["8", "9", "a", "b"].contains(&&id[19..20]));
        assert_ne!(new_event_id(), new_event_id());
    }

    #[test]
    fn level_gating() {
        let (norm, raw) = level_sql("SELECT * FROM t WHERE a = 'x'", SqlLogLevel::None);
        assert!(norm.is_none() && raw.is_none());
        let (norm, raw) = level_sql("SELECT * FROM t WHERE a = 'x'", SqlLogLevel::Fingerprint);
        assert!(norm.is_none() && raw.is_none());
        let (norm, raw) = level_sql("SELECT * FROM t WHERE a = 'x'", SqlLogLevel::Metadata);
        assert_eq!(norm.as_deref(), Some("select * from t where a = ?"));
        assert!(raw.is_none());
        let (norm, raw) = level_sql("SELECT * FROM t WHERE a = 'x'", SqlLogLevel::FullSql);
        assert!(norm.is_some());
        assert_eq!(raw.as_deref(), Some("SELECT * FROM t WHERE a = 'x'"));
    }
}
