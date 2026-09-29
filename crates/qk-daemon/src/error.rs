//! Central daemon error mapping. Handlers return `DaemonError`; exactly
//! one place converts to HTTP status + body. Frozen distinctions are
//! preserved (401/403 text bodies, 400 decide quirk); everything else is
//! JSON `{"error": ...}` with no engine internals, backtraces, or secrets.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Handler failures with centrally mapped HTTP semantics.
#[derive(Debug)]
pub enum DaemonError {
    /// Missing or wrong token. Frozen: 401 text `unauthorized`.
    Unauthorized,
    /// Non-loopback Host. Frozen: 403 text `invalid host`.
    InvalidHost,
    /// Non-loopback Origin. Frozen: 403 text `invalid origin`.
    InvalidOrigin,
    /// Malformed request content for a decision action. Frozen quirk:
    /// 400 text `Error: <message>` (matches the reference decide path).
    BadAction(String),
    /// Unknown approval/session/route target.
    NotFound(String),
    /// Store busy/locked exhaustion.
    Unavailable(String),
    /// Store conflict (duplicate id).
    Conflict(String),
    /// Store-level invalid content.
    Invalid(String),
    /// Anything else (engine failures, poisoned locks).
    Internal(String),
}

impl From<qk_store::StoreError> for DaemonError {
    fn from(error: qk_store::StoreError) -> Self {
        map_store_error(error)
    }
}

impl DaemonError {
    fn message(&self) -> String {
        match self {
            Self::Unauthorized => "unauthorized".to_owned(),
            Self::InvalidHost => "invalid host".to_owned(),
            Self::InvalidOrigin => "invalid origin".to_owned(),
            Self::BadAction(detail) => format!("Error: {detail}"),
            Self::NotFound(detail) => detail.clone(),
            Self::Unavailable(detail) => detail.clone(),
            Self::Conflict(detail) => detail.clone(),
            Self::Invalid(detail) => detail.clone(),
            Self::Internal(_) => "internal error".to_owned(),
        }
    }
}

impl IntoResponse for DaemonError {
    fn into_response(self) -> Response {
        match &self {
            // Frozen text bodies (the reference serves these as text).
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
            Self::InvalidHost => (StatusCode::FORBIDDEN, "invalid host").into_response(),
            Self::InvalidOrigin => (StatusCode::FORBIDDEN, "invalid origin").into_response(),
            Self::BadAction(_) => (StatusCode::BAD_REQUEST, self.message()).into_response(),
            // Unknown rows are plain-text `not found` (the reference
            // answers `c.text('not found', 404)` on API lookups).
            Self::NotFound(_) => (StatusCode::NOT_FOUND, "not found").into_response(),
            Self::Unavailable(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(serde_json::json!({"error": self.message()})),
            )
                .into_response(),
            Self::Conflict(_) => (
                StatusCode::CONFLICT,
                axum::Json(serde_json::json!({"error": self.message()})),
            )
                .into_response(),
            Self::Invalid(_) => (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({"error": self.message()})),
            )
                .into_response(),
            Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error": self.message()})),
            )
                .into_response(),
        }
    }
}

/// Map store failures onto daemon errors. Busy is 503-worthy
/// (`Unavailable`); conflicts stay conflicts; corrupt rows are `Invalid`
/// (fail closed, never grants); the rest are `Internal`. No rusqlite text
/// leaks: messages are short owned strings without parameters.
pub fn map_store_error(error: qk_store::StoreError) -> DaemonError {
    use qk_store::StoreError as Source;
    match error {
        Source::Busy(detail) => DaemonError::Unavailable(detail),
        Source::Conflict(detail) => DaemonError::Conflict(detail),
        Source::NotFound(detail) => DaemonError::NotFound(detail),
        Source::NotWaiting(detail) => DaemonError::BadAction(detail),
        Source::Expired(detail) => DaemonError::BadAction(detail),
        Source::InvalidRow(detail) => DaemonError::Invalid(detail),
        Source::Open(detail)
        | Source::Migration(detail)
        | Source::SchemaMismatch(detail)
        | Source::Database(detail) => DaemonError::Internal(detail),
    }
}
