//! Deterministic `AuditEvent → OcsfEvent` conversion (OCSF 1.5.0,
//! Application Activity / API Activity, class 6003). The audit event
//! stays the source of truth; the full decision is preserved under
//! `unmapped` so mapping skew can never lose the security signal.

use serde::Serialize;

use crate::event::{AttemptOutcome, AuditDecision, AuditEvent};

/// OCSF version emitted (frozen).
pub const OCSF_VERSION: &str = "1.5.0";
/// Frozen class/category mapping (database activity surfaces as API
/// Activity alongside OpenShell's own OCSF logs).
pub const CATEGORY_UID: u32 = 6;
/// Frozen class/category mapping.
pub const CATEGORY_NAME: &str = "Application Activity";
/// Frozen class/category mapping.
pub const CLASS_UID: u32 = 6003;
/// Frozen class/category mapping.
pub const CLASS_NAME: &str = "API Activity";

/// OCSF severity (frozen ids/names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum OcsfSeverity {
    /// Informational (1).
    Informational,
    /// Low (2).
    Low,
    /// High (4).
    High,
}

/// OCSF status (frozen ids/names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum OcsfStatus {
    /// Success (1).
    Success,
    /// Failure (2).
    Failure,
    /// Unknown (0).
    Unknown,
}

/// OCSF activity (frozen ids/names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum OcsfActivity {
    /// Allow (6).
    Allow,
    /// Deny (7).
    Deny,
    /// RequireApproval (0/Unknown).
    Unknown,
}

/// Frozen OCSF event shape (`undefined` stays omitted via
/// `skip_serializing_if`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OcsfEvent {
    /// Milliseconds since epoch (`Date.parse` of the audit timestamp).
    pub time: u64,
    /// OCSF schema version.
    pub ocsf_version: String,
    /// Category UID (6).
    pub category_uid: u32,
    /// Category name.
    pub category_name: String,
    /// Class UID (6003).
    pub class_uid: u32,
    /// Class name.
    pub class_name: String,
    /// Activity id.
    pub activity_id: u32,
    /// Activity name.
    pub activity_name: String,
    /// Severity id.
    pub severity_id: u32,
    /// Severity name.
    pub severity: String,
    /// Status id.
    pub status_id: u32,
    /// Status name.
    pub status: String,
    /// Product metadata.
    pub metadata: OcsfMetadata,
    /// Actor (agent or user name), when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<OcsfActor>,
    /// API operation (`<integration>:<operation>`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api: Option<OcsfApi>,
    /// Full decision preserved (mapping-skew safety).
    pub unmapped: serde_json::Value,
}

/// OCSF metadata block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OcsfMetadata {
    /// Product name/version.
    pub product: OcsfProduct,
    /// Schema version.
    pub version: String,
}

/// OCSF product block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OcsfProduct {
    /// Product name (`QueryKnight`).
    pub name: String,
    /// Product version.
    pub version: String,
}

/// OCSF actor block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OcsfActor {
    /// User identity.
    pub user: OcsfUser,
}

/// OCSF user block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OcsfUser {
    /// Identity name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// OCSF API block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OcsfApi {
    /// Operation (`<integration>:<operation>`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
}

/// Convert an audit event to OCSF. Deny → 7/Deny/High/Failure;
/// RequireApproval → 0/Unknown/Low/Unknown. Allow is a successful OCSF
/// operation only for `AttemptOutcome::Executed`; authorization-only
/// `Authorized` remains status Unknown, and a database `Failed` remains
/// Failure. `product_version` feeds the product block (package metadata at
/// call sites).
pub fn to_ocsf(event: &AuditEvent, product_version: &str) -> OcsfEvent {
    let (activity, severity) = match event.decision {
        AuditDecision::Deny => (OcsfActivity::Deny, OcsfSeverity::High),
        AuditDecision::RequireApproval => (OcsfActivity::Unknown, OcsfSeverity::Low),
        AuditDecision::Allow => (OcsfActivity::Allow, OcsfSeverity::Informational),
    };
    let status = match event.decision {
        AuditDecision::Deny => OcsfStatus::Failure,
        AuditDecision::RequireApproval => OcsfStatus::Unknown,
        AuditDecision::Allow => match &event.outcome {
            AttemptOutcome::Executed => OcsfStatus::Success,
            AttemptOutcome::Failed => OcsfStatus::Failure,
            AttemptOutcome::Authorized | AttemptOutcome::Blocked | AttemptOutcome::Pending => {
                OcsfStatus::Unknown
            }
        },
    };
    let (activity_id, activity_name) = match activity {
        OcsfActivity::Allow => (6, "Allow"),
        OcsfActivity::Deny => (7, "Deny"),
        OcsfActivity::Unknown => (0, "Unknown"),
    };
    let (severity_id, severity_name) = match severity {
        OcsfSeverity::Informational => (1, "Informational"),
        OcsfSeverity::Low => (2, "Low"),
        OcsfSeverity::High => (4, "High"),
    };
    let (status_id, status_name) = match status {
        OcsfStatus::Success => (1, "Success"),
        OcsfStatus::Failure => (2, "Failure"),
        OcsfStatus::Unknown => (0, "Unknown"),
    };
    OcsfEvent {
        time: event_timestamp_ms(event),
        ocsf_version: OCSF_VERSION.to_owned(),
        category_uid: CATEGORY_UID,
        category_name: CATEGORY_NAME.to_owned(),
        class_uid: CLASS_UID,
        class_name: CLASS_NAME.to_owned(),
        activity_id,
        activity_name: activity_name.to_owned(),
        severity_id,
        severity: severity_name.to_owned(),
        status_id,
        status: status_name.to_owned(),
        metadata: OcsfMetadata {
            product: OcsfProduct {
                name: "QueryKnight".to_owned(),
                version: product_version.to_owned(),
            },
            version: OCSF_VERSION.to_owned(),
        },
        actor: event
            .agent_id
            .clone()
            .or_else(|| event.user.clone())
            .map(|name| OcsfActor {
                user: OcsfUser { name: Some(name) },
            }),
        api: Some(OcsfApi {
            operation: Some(format!("{}:{}", event.integration, event.operation)),
        }),
        unmapped: serde_json::json!({
            "qk_event_id": event.event_id,
            "qk_reason_code": event.reason_code,
            "qk_matched_policy": event.matched_policy,
            "qk_fingerprint": event.fingerprint,
            "qk_tables": event.tables,
            "qk_kinds": event.kinds,
            "qk_database": event.database,
            "qk_environment": event.environment,
            "qk_enforced": event.enforced,
            "qk_outcome": &event.outcome,
            "qk_approval_id": event.approval_id,
        }),
    }
}

/// Audit timestamps are ISO-8601 UTC with millis; parse back to epoch
/// millis for the OCSF `time` field (no chrono, no clock).
fn event_timestamp_ms(event: &AuditEvent) -> u64 {
    parse_iso_millis(&event.timestamp).unwrap_or(0)
}

fn parse_iso_millis(text: &str) -> Option<u64> {
    // `YYYY-MM-DDTHH:MM:SS.mmmZ` (our own emission shape).
    let (date, time) = text.split_once('T')?;
    let mut date = date.split('-');
    let year: i64 = date.next()?.parse().ok()?;
    let month: i64 = date.next()?.parse().ok()?;
    let day: i64 = date.next()?.parse().ok()?;
    let time = time.strip_suffix('Z')?;
    let (hms, ms) = time.split_once('.')?;
    let mut hms = hms.split(':');
    let hour: i64 = hms.next()?.parse().ok()?;
    let minute: i64 = hms.next()?.parse().ok()?;
    let second: i64 = hms.next()?.parse().ok()?;
    let millis: i64 = ms.parse().ok()?;
    let days = days_from_civil(year, month, day)?;
    Some(
        (days * 86_400 + hour as u64 * 3_600 + minute as u64 * 60 + second as u64) * 1000
            + millis as u64,
    )
}

fn days_from_civil(year: i64, month: i64, day: i64) -> Option<u64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let mp = (month + 9).rem_euclid(12);
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    u64::try_from(era * 146_097 + doe - 719_468).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_round_trip() {
        assert_eq!(
            parse_iso_millis("2026-09-30T12:00:00.123Z"),
            Some(1_790_769_600_123)
        );
        assert_eq!(parse_iso_millis("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(parse_iso_millis("garbage"), None);
    }
}
