//! QueryKnight-owned typed errors for SQL analysis. Raw `sqlparser-rs`
//! diagnostics never cross the crate boundary verbatim.

use std::fmt::{self, Display, Formatter};

/// Typed analysis failures. Parseable-but-unmapped statements are NOT errors;
/// they surface as [`crate::Operation::Unsupported`] in the analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqlAnalysisError {
    /// Unknown dialect name; carries the rejected input.
    UnsupportedDialect(String),
    /// Empty, whitespace-only, or comment-only input (zero statements).
    EmptyQuery,
    /// Input exceeds the frozen byte budget.
    InputTooLarge {
        /// Measured UTF-8 byte length.
        bytes: usize,
        /// Enforced limit ([`crate::MAX_SQL_BYTES`] by default).
        max_bytes: usize,
    },
    /// The parser rejected the input. Message is truncated parser detail
    /// (which may echo input fragments) plus optional source position.
    ParseError {
        /// Truncated diagnostic, never longer than 300 chars.
        message: String,
        /// 1-based line, when reported.
        line: Option<usize>,
        /// 1-based column, when reported.
        column: Option<usize>,
    },
    /// Internal analysis failure (parser thread spawn failure, parser panic).
    /// Fail-closed: the input is never treated as analyzed.
    AnalysisError {
        /// Stable QueryKnight-owned detail; never parser prose.
        message: String,
    },
}

impl Display for SqlAnalysisError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedDialect(name) => write!(
                f,
                "unsupported dialect '{name}' (expected postgresql, mysql, or sqlite)"
            ),
            Self::EmptyQuery => write!(f, "empty query: no statements to analyze"),
            Self::InputTooLarge { bytes, max_bytes } => write!(
                f,
                "SQL input of {bytes} bytes exceeds the limit of {max_bytes} bytes"
            ),
            Self::AnalysisError { message } => {
                write!(f, "SQL analysis failed: {message}")
            }
            Self::ParseError {
                message,
                line,
                column,
            } => {
                write!(f, "SQL could not be parsed")?;
                if let (Some(l), Some(c)) = (line, column) {
                    write!(f, " at line {l} column {c}")?;
                }
                write!(f, ": {message}")
            }
        }
    }
}

impl std::error::Error for SqlAnalysisError {}

/// Truncate parser detail to a bounded diagnostic. Char-boundary safe.
pub(crate) fn truncate_diagnostic(message: &str) -> String {
    const MAX_CHARS: usize = 300;
    if message.chars().count() <= MAX_CHARS {
        return message.to_owned();
    }
    message.chars().take(MAX_CHARS).collect()
}
