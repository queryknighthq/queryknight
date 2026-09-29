//! MCP-facing error taxonomy. QueryKnight `Blocked:`/pending results
//! are successful tool results (never protocol errors); everything
//! below is a genuine protocol failure. No credentials, no token
//! bytes, no SQL text in error shapes.

use rmcp::ErrorData as McpError;

/// Map an internal failure to a JSON-RPC protocol error. Messages are
/// short, stable, and secret-free; detailed diagnostics stay on stderr.
pub fn protocol_error(kind: ErrorKind) -> McpError {
    match kind {
        ErrorKind::Schema(message) => {
            McpError::invalid_params(format!("invalid tool arguments: {message}"), None)
        }
        ErrorKind::Database(error) => McpError::internal_error(
            format!("database error: {}", short_error(&error.to_string())),
            None,
        ),
        ErrorKind::Daemon(message) => {
            McpError::internal_error(format!("control plane unavailable: {message}"), None)
        }
        ErrorKind::Internal(message) => {
            McpError::internal_error(format!("internal error: {message}"), None)
        }
    }
}

/// MCP-level failure categories (§29 taxonomy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    /// Tool argument validation failed (never reached any service).
    Schema(String),
    /// Authorized statement failed at the database.
    Database(qk_db::DbError),
    /// Daemon control-plane call failed.
    Daemon(String),
    /// MCP plumbing failure (never policy/DB content).
    Internal(String),
}

/// Bound a free-form message for protocol/error surfaces.
fn short_error(message: &str) -> String {
    const MAX: usize = 300;
    if message.len() <= MAX {
        message.to_owned()
    } else {
        format!("{}…[truncated]", &message[..MAX])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_are_bounded_and_structural() {
        // Daemon failures use fixed strings (the sync client reports
        // `()` internally — response content and tokens cannot flow
        // into these messages by construction).
        let error = protocol_error(ErrorKind::Daemon("approvals listing failed".to_owned()));
        assert!(format!("{error:?}").contains("control plane unavailable"));
        let db = qk_db::DbError::new(qk_db::DbErrorKind::Connection, "x".repeat(600));
        let rendered = format!("{:?}", protocol_error(ErrorKind::Database(db)));
        assert!(rendered.len() < 600);
    }
}
