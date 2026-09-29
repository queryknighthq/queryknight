//! HTTP data-transfer objects. Field names and casing mirror the frozen
//! daemon JSON contract exactly; absent optional fields are omitted (never
//! `null`), matching the reference serializer. Storage structs are never
//! serialized directly.

use qk_approval::{ApprovalBinding, GrantStatus, Scope, StoredGrant};

// ---------------------------------------------------------------------------
// Approvals.
// ---------------------------------------------------------------------------

/// Approval view (frozen shape plus additive `bindingKind`, which exposes
/// legacy/incomplete state the reference cannot represent).
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalView {
    /// Approval id.
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Session id.
    pub session_id: Option<String>,
    /// Human-readable reason.
    pub reason: String,
    /// Risk text.
    pub risk: String,
    /// Operation summary.
    pub operation_summary: String,
    /// Query-shape fingerprint.
    pub fingerprint: String,
    /// Status wire name.
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Reuse scope.
    pub scope: Option<&'static str>,
    /// Expiry in ms since epoch.
    pub expires_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Current schema snapshots (before image).
    pub schema_ddl: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Unified before/after diff (after execution).
    pub schema_diff: Option<serde_json::Value>,
    /// Binding kind (`exact_v1`, `exact_v2`, `shape_v1`, or
    /// `legacy_shape`): additive visibility for quarantined rows,
    /// which can never authorize. The digest VALUE is never exposed
    /// (internal authorization material; see INV-041).
    pub binding_kind: &'static str,
    /// Integration scope dimension.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integration: Option<String>,
    /// Environment scope dimension.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Database scope dimension.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    /// Agent scope dimension.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Tool scope dimension.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
}

impl ApprovalView {
    /// Shape a stored grant for output. Invalid embedded JSON degrades to
    /// omitted fields (display leniency; authorization validity is
    /// unaffected because matching never reads these columns).
    pub fn from_grant(
        grant: &StoredGrant,
        schema_ddl: Option<serde_json::Value>,
        schema_diff: Option<serde_json::Value>,
    ) -> Self {
        Self {
            id: grant.id.as_str().to_owned(),
            session_id: grant.scope.session_id.clone(),
            reason: grant.message.clone(),
            risk: grant.risk.clone(),
            operation_summary: grant.operation_summary.clone(),
            fingerprint: grant.shape.as_str().to_owned(),
            status: match grant.status {
                GrantStatus::Waiting => "waiting",
                GrantStatus::Approved => "approved",
                GrantStatus::Denied => "denied",
            },
            scope: Some(match grant.reuse {
                Scope::Once => "once",
                Scope::Session => "session",
            }),
            expires_at: grant.expires_at_ms,
            schema_ddl,
            schema_diff,
            binding_kind: match grant.binding {
                ApprovalBinding::ExactV1(_) => "exact_v1",
                ApprovalBinding::ExactV2(_) => "exact_v2",
                ApprovalBinding::ShapeV1 => "shape_v1",
                ApprovalBinding::LegacyShape => "legacy_shape",
            },
            integration: Some(grant.scope.integration.clone()),
            environment: Some(grant.scope.environment.clone()),
            database: Some(grant.scope.database.clone()),
            agent_id: Some(grant.scope.agent_id.clone()),
            tool: Some(grant.scope.tool.clone()),
        }
    }
}

/// Create-approval request body (extra fields tolerated, like the
/// reference; required fields reject empty values with 400).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateApprovalRequest {
    /// Session id.
    pub session_id: Option<String>,
    /// Connection key (upserted into a connection row).
    pub connection_key: Option<String>,
    /// Query-shape fingerprint.
    pub fingerprint: Option<String>,
    /// Human-readable reason.
    pub reason: Option<String>,
    /// Risk text.
    pub risk: Option<String>,
    /// Operation summary.
    pub operation_summary: Option<String>,
    /// Lifetime in ms (default 60s).
    pub timeout_ms: Option<u64>,
    /// Current schema snapshots (must be an array when present).
    pub schema_ddl: Option<serde_json::Value>,
    /// Integration scope dimension.
    pub integration: Option<String>,
    /// Environment scope dimension.
    pub environment: Option<String>,
    /// Database scope dimension.
    pub database: Option<String>,
    /// Agent scope dimension.
    pub agent_id: Option<String>,
    /// Tool scope dimension.
    pub tool: Option<String>,
    /// Exact execution digest as 64 hex chars (opaque binding for
    /// trusted service paths; stored, never returned in views).
    /// Required with `binding_kind` `exact_v1`/`exact_v2`, forbidden
    /// with `shape_v1`.
    pub exact_digest: Option<String>,
    /// Binding kind override (`exact_v1`, `exact_v2`; default
    /// `shape_v1` for UI/human rows that carry no SQL identity).
    pub binding_kind: Option<String>,
}

/// Verify-approval request body: proves an approval id authorizes an
/// exact request WITHOUT exposing digests in URLs, logs, or views.
/// The digest travels in this POST body only (trusted loopback path).
/// Scope dims default to `""` (matching store defaults) when absent.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyApprovalRequest {
    /// Expected digest as 64 hex chars.
    pub digest: String,
    /// Expected version (`exact_v1` or `exact_v2`).
    pub version: String,
    /// Expected session scope dimension.
    pub session_id: Option<String>,
    /// Expected integration scope dimension.
    pub integration: Option<String>,
    /// Expected environment scope dimension.
    pub environment: Option<String>,
    /// Expected database scope dimension.
    pub database: Option<String>,
    /// Expected agent scope dimension.
    pub agent_id: Option<String>,
    /// Expected tool scope dimension.
    pub tool: Option<String>,
}

/// Decide-approval request body.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct DecideApprovalRequest {
    /// `approved` or `denied` (anything else is 422).
    pub status: DecideStatus,
    /// Decision source (default `ui`).
    pub source: Option<DecisionSourceWire>,
    /// Reuse scope (default `once`).
    pub scope: Option<ScopeWire>,
}

/// Approval verdict values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecideStatus {
    /// Human approved.
    Approved,
    /// Human denied.
    Denied,
}

/// Decision source wire values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecisionSourceWire {
    /// Terminal UI.
    Tui,
    /// Command line.
    Cli,
    /// Web UI.
    Ui,
    /// Agent chat flow.
    Mcp,
}

/// Reuse scope wire values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeWire {
    /// Single retry token.
    Once,
    /// Session-shape reuse.
    Session,
}

/// Schema-diff request body.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaDiffRequest {
    /// Unified diff entries (must be an array when present).
    pub schema_diff: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Sessions.
// ---------------------------------------------------------------------------

/// Create-session request body.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionRequest {
    /// Connection key (upserted).
    pub connection_key: Option<String>,
    /// Source (`mcp`, `proxy`, `manual`, ...).
    pub source: Option<String>,
    /// Agent name.
    pub agent: Option<String>,
}

/// Session summary (frozen shape; computed on read, never persisted).
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    /// Session id.
    pub id: String,
    /// Connection id.
    pub connection_id: String,
    /// Milliseconds since epoch.
    pub started_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Milliseconds since epoch, when ended.
    pub ended_at: Option<u64>,
    /// Source.
    pub source: String,
    /// Total events counted.
    pub queries: usize,
    /// Read-class events.
    pub reads: usize,
    /// Write-class events.
    pub writes: usize,
    /// Schema-change-class events.
    pub schema_changes: usize,
    /// Sum of rows affected.
    pub rows_modified: i64,
    /// Sum of bytes returned.
    pub bytes_returned: i64,
    /// Sum of estimated tokens avoided.
    pub estimated_tokens_avoided: i64,
}

// ---------------------------------------------------------------------------
// Events.
// ---------------------------------------------------------------------------

/// Record-event request body (mirrors the history client payload).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateEventRequest {
    /// Owning session id.
    pub session_id: Option<String>,
    /// Connection key (upserted).
    pub connection_key: Option<String>,
    /// Source.
    pub source: Option<String>,
    /// Query-shape fingerprint.
    pub sql_fingerprint: Option<String>,
    /// Raw SQL when recorded.
    pub sql: Option<String>,
    /// Classification (`{class, risk}`).
    pub classification: Option<EventClassification>,
    /// Decision text (default `executed`, mirroring the client default).
    pub decision: Option<String>,
    /// Duration in ms.
    pub duration_ms: Option<u64>,
    /// Rows returned.
    pub rows_returned: Option<i64>,
    /// Rows affected.
    pub rows_affected: Option<i64>,
    /// Bytes returned.
    pub bytes_returned: Option<i64>,
    /// Estimated tokens returned.
    pub estimated_tokens_returned: Option<i64>,
    /// Estimated tokens avoided.
    pub estimated_tokens_avoided: Option<i64>,
    /// Error code text.
    pub error_code: Option<String>,
}

/// Event classification sub-object.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct EventClassification {
    /// Class text (`read`, `write`, ...).
    pub class: String,
    /// Risk text.
    pub risk: String,
}

/// Event view (frozen subset and order).
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventViewJson {
    /// Event id.
    pub id: String,
    /// Owning session id.
    pub session_id: String,
    /// Source.
    pub source: String,
    /// Query-shape fingerprint.
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Raw SQL when recorded.
    pub sql: Option<String>,
    /// Classification class text.
    pub query_class: String,
    /// Risk text.
    pub risk: String,
    /// Decision text.
    pub decision: String,
    /// Milliseconds since epoch.
    pub started_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Rows returned.
    pub rows_returned: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Rows affected.
    pub rows_affected: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Bytes returned.
    pub bytes_returned: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Error code text.
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// Connections.
// ---------------------------------------------------------------------------

/// Connection metadata view. The store holds no connection URL (frozen
/// shape minus `url`, which lived in a separate JSON file upstream);
/// all other fields mirror the redacted daemon output.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectionView {
    /// Connection id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Engine text.
    pub engine: String,
    /// Environment text.
    pub environment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Database name.
    pub database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Host label.
    pub host_label: Option<String>,
}

// ---------------------------------------------------------------------------
// Health.
// ---------------------------------------------------------------------------

/// Health check entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthCheck {
    /// Check name.
    pub name: String,
    /// Whether it passed.
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Detail on failure.
    pub detail: Option<String>,
}

/// Readiness body (`ok` vs `degraded`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct Readiness {
    /// Overall status.
    pub status: &'static str,
    /// Per-check results.
    pub checks: Vec<HealthCheck>,
}
