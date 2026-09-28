//! QueryKnight normalized SQL analysis ("what SQL is this?").
//!
//! Pipeline: SQL text -> [`SqlDialect`] selection -> `sqlparser-rs` ->
//! recursive AST walk -> owned [`QueryAnalysis`]. No policy decisions live
//! here; verdicts (allow/deny/require_approval) are a later layer.
//!
//! [`MAX_SQL_BYTES`] mirrors the frozen reference input budget
//! (`DEFAULT_MAX_SQL_BYTES = 1_000_000`). The 64 KiB / 8000-token heuristic
//! is a *result* budget owned by the future execution layer, not the parser.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod analyze;
pub mod dialect;
pub mod error;
pub mod model;

pub use analyze::{analyze, analyze_with_options, AnalyzeOptions};
pub use dialect::{parse_dialect, SqlDialect};
pub use error::SqlAnalysisError;
pub use model::{
    ColumnName, ColumnRef, Identifier, LimitValue, OpCategory, Operation, QueryAnalysis,
    RiskSignal, StatementAnalysis, TableRef,
};

/// Frozen SQL input budget in bytes: 1 MiB. Mirrors the reference
/// `DEFAULT_MAX_SQL_BYTES`. Enforced at this parse boundary so no unbounded
/// input ever reaches the parser; the future evaluator references this same
/// constant instead of introducing a second limit.
pub const MAX_SQL_BYTES: usize = 1_000_000;

/// Maximum AST walk depth. Deeper nesting stops descending and sets
/// [`RiskSignal::DepthTruncated`] instead of risking stack exhaustion on
/// adversarial input.
pub const MAX_WALK_DEPTH: usize = 64;
