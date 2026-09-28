//! Typed storage errors. Raw `rusqlite` diagnostics never cross the crate
//! boundary as machine values; messages stay short operator-facing text.

use std::fmt::{self, Display, Formatter};

/// Storage failures. Every variant is fail-closed for callers: none can be
/// mistaken for a successful authorization lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// Database file could not be opened or initialized.
    Open(String),
    /// Migration failed or was refused.
    Migration(String),
    /// On-disk schema is newer than this build understands.
    SchemaMismatch(String),
    /// Lock contention exhausted the bounded busy timeout.
    Busy(String),
    /// Row not found (decide/lookup by id).
    NotFound(String),
    /// Uniqueness violation (e.g. duplicate approval id).
    Conflict(String),
    /// Grant is not waiting (already decided).
    NotWaiting(String),
    /// Grant already expired at the given timestamp.
    Expired(String),
    /// Persisted row failed validation (bad digest, unknown enum, bad
    /// timestamp, missing required field). Never an active grant.
    InvalidRow(String),
    /// Any other database failure.
    Database(String),
}

impl Display for StoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open(detail) => write!(f, "cannot open database: {detail}"),
            Self::Migration(detail) => write!(f, "migration failed: {detail}"),
            Self::SchemaMismatch(detail) => write!(f, "schema mismatch: {detail}"),
            Self::Busy(detail) => write!(f, "database busy: {detail}"),
            Self::NotFound(detail) => write!(f, "not found: {detail}"),
            Self::Conflict(detail) => write!(f, "conflict: {detail}"),
            Self::Expired(detail) => write!(f, "approval expired: {detail}"),
            Self::NotWaiting(detail) => write!(f, "approval is not waiting: {detail}"),
            Self::InvalidRow(detail) => write!(f, "invalid stored row: {detail}"),
            Self::Database(detail) => write!(f, "database error: {detail}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Classify a rusqlite failure. Lock contention maps to `Busy`; UNIQUE
/// violations map to `Conflict`; everything else is an opaque `Database`
/// message (short engine text, no secrets: parameters are never echoed by
/// SQLite errors).
pub(crate) fn classify_rusqlite(error: rusqlite::Error) -> StoreError {
    use rusqlite::ErrorCode;
    match &error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::DatabaseBusy
                || failure.code == ErrorCode::DatabaseLocked =>
        {
            StoreError::Busy(trim_message(error.to_string()))
        }
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation =>
        {
            StoreError::Conflict(trim_message(error.to_string()))
        }
        _ => StoreError::Database(trim_message(error.to_string())),
    }
}

fn trim_message(message: String) -> String {
    const MAX: usize = 300;
    if message.len() <= MAX {
        return message;
    }
    message.chars().take(MAX).collect()
}
