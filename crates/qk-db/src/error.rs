//! QueryKnight-owned database errors. Driver types never escape the
//! adapter modules; messages are bounded and credential-free.

use std::fmt::{self, Display, Formatter};

/// Maximum driver message length preserved in an error. Longer texts
/// are truncated (bounded diagnostics, no giant server dumps).
pub const MAX_ERROR_MESSAGE: usize = 500;

/// Database-side failure categories. Policy/approval outcomes are NOT
/// errors — they live in [`crate::service::ExecutionOutcome`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbErrorKind {
    /// TCP/connect handshake failed (including DNS/refused).
    Connection,
    /// Authentication rejected the credentials.
    Authentication,
    /// Bounded execution time elapsed. The statement MAY STILL BE
    /// RUNNING server-side unless the adapter proves cancellation.
    Timeout,
    /// The database rejected the statement (syntax at the engine,
    /// missing tables, constraint violations, ...). Note: this is
    /// AFTER authorization — a syntax-vs-semantic boundary.
    Query,
    /// Integrity constraint violation (unique, FK, check, not-null).
    Constraint,
    /// The operation is not supported by this adapter.
    Unsupported,
    /// Protocol/driver-level failure.
    Protocol,
    /// Anything else driver-shaped.
    Internal,
}

/// A bounded, credential-free database error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbError {
    kind: DbErrorKind,
    message: String,
}

impl DbError {
    /// Build from a category and free detail (truncated to
    /// [`MAX_ERROR_MESSAGE`]).
    pub fn new(kind: DbErrorKind, message: impl Into<String>) -> Self {
        let mut text: String = message.into();
        if text.len() > MAX_ERROR_MESSAGE {
            text.truncate(MAX_ERROR_MESSAGE);
            text.push_str("…[truncated]");
        }
        Self {
            kind,
            message: text,
        }
    }

    /// The failure category.
    pub fn kind(&self) -> &DbErrorKind {
        &self.kind
    }

    /// Bounded detail (safe for logs, MCP text, history codes).
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Display for DbError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let category = match self.kind {
            DbErrorKind::Connection => "connection",
            DbErrorKind::Authentication => "authentication",
            DbErrorKind::Timeout => "timeout",
            DbErrorKind::Query => "query",
            DbErrorKind::Constraint => "constraint",
            DbErrorKind::Unsupported => "unsupported",
            DbErrorKind::Protocol => "protocol",
            DbErrorKind::Internal => "internal",
        };
        write!(f, "db({category}): {}", self.message)
    }
}

impl std::error::Error for DbError {}

/// Classify a driver error string into connection/auth/query buckets.
/// Best-effort substring matching on stable server prefixes; unknown
/// text stays `Query` (statement-scoped) rather than `Connection`.
pub fn classify_driver_message(message: &str) -> DbErrorKind {
    let lower = message.to_ascii_lowercase();
    // Connection-level first (these never describe a single statement).
    for marker in [
        "connection refused",
        "could not connect",
        "no such host",
        "name resolution",
        "timed out",
        "timeout expired",
        "server closed the connection",
        "connection reset",
        "broken pipe",
        "too many clients",
        "too many connections",
    ] {
        if lower.contains(marker) {
            return DbErrorKind::Connection;
        }
    }
    // Unambiguous auth markers.
    for marker in [
        "password authentication failed",
        "authentication failed",
        "access denied",
        "auth failed",
        "login failed",
    ] {
        if lower.contains(marker) {
            return DbErrorKind::Authentication;
        }
    }
    // Ambiguous markers ("role ... does not exist" vs 'relation "t"
    // does not exist'): only auth when an auth word is present.
    if lower.contains("role ") || lower.contains("does not exist") {
        for word in ["password", "auth", "role", "login", "user"] {
            if lower.contains(word) {
                return DbErrorKind::Authentication;
            }
        }
    }
    for marker in [
        "duplicate",
        "unique constraint",
        "violates unique",
        "foreign key",
        "violates foreign",
        "violates not-null",
        "cannot be null",
        "check constraint",
        "violates check",
    ] {
        if lower.contains(marker) {
            return DbErrorKind::Constraint;
        }
    }
    DbErrorKind::Query
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_bounded() {
        let error = DbError::new(DbErrorKind::Query, "x".repeat(600));
        assert!(error.message().len() <= MAX_ERROR_MESSAGE + 20);
    }

    #[test]
    fn classification_buckets() {
        assert_eq!(
            classify_driver_message("connection refused on 127.0.0.1"),
            DbErrorKind::Connection
        );
        assert_eq!(
            classify_driver_message("password authentication failed for user \"qk\""),
            DbErrorKind::Authentication
        );
        assert_eq!(
            classify_driver_message("duplicate key value violates unique constraint \"t_pkey\""),
            DbErrorKind::Constraint
        );
        assert_eq!(
            classify_driver_message("syntax error at or near \"TYPO\""),
            DbErrorKind::Query
        );
        assert_eq!(
            classify_driver_message("relation \"nope\" does not exist"),
            DbErrorKind::Query
        );
    }
}
