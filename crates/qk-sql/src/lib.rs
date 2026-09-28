//! QueryKnight normalized SQL analysis ("what SQL is this?").
//!
//! Pipeline: SQL text -> input budget -> explicit parser recursion limit ->
//! bounded AST -> depth-capped traversal -> owned [`QueryAnalysis`]. No
//! policy decisions live here; verdicts (allow/deny/require_approval) are a
//! later layer.
//!
//! [`MAX_SQL_BYTES`] mirrors the frozen reference input budget
//! (`DEFAULT_MAX_SQL_BYTES = 1_000_000`). The 64 KiB / 8000-token heuristic
//! is a *result* budget owned by the future execution layer, not the parser.
//!
//! Resource design: no per-request threads and no giant reserved stacks.
//! Parser nesting is bounded by [`SQL_PARSER_RECURSION_LIMIT`]; the whole
//! pipeline runs inside one transient [`stacker`] segment (~21 us to
//! establish) so deep operator chains — which the parser counter cannot
//! see — can be walked and destroyed without aborting small stacks.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod analyze;
pub mod defensive;
pub mod dialect;
pub mod error;
pub mod model;

pub use analyze::{analyze, analyze_with_options, AnalyzeOptions};
pub use defensive::{
    defensive_scan, DefensiveScan, DefensiveSignal, PossibleOperation, ScanCompleteness,
    SqlInspection,
};
pub use dialect::{parse_dialect, SqlDialect};
pub use error::SqlAnalysisError;
pub use model::{
    AnalysisCompleteness, ColumnName, ColumnRef, Identifier, LimitValue, OpCategory, Operation,
    QueryAnalysis, RiskSignal, StatementAnalysis, TableRef,
};

/// Frozen SQL input budget in bytes: 1 MiB. Mirrors the reference
/// `DEFAULT_MAX_SQL_BYTES`. Enforced before parsing; the future evaluator
/// references this same constant instead of introducing a second limit.
pub const MAX_SQL_BYTES: usize = 1_000_000;

/// Explicit parser recursion limit (nesting shapes: subqueries, CTEs,
/// parenthesized expressions, right-associative operators). Matches the
/// upstream default: conservative, proven by the full fixture suite plus a
/// realistic-complex query test. Left-associative operator chains do not
/// consume this counter; they are bounded by [`MAX_SQL_BYTES`] for size and
/// by lazily-grown stack for destruction (see [`analyze`]).
pub const SQL_PARSER_RECURSION_LIMIT: usize = 50;

/// Maximum AST walk depth (QueryKnight traversal levels, not parser steps).
/// Differs from [`SQL_PARSER_RECURSION_LIMIT`] on purpose: one parser step
/// can emit several AST levels, and operator chains consume no parser steps
/// at all. Exceeding it sets [`RiskSignal::DepthTruncated`] and
/// [`AnalysisCompleteness::DepthTruncated`]; never silent.
pub const MAX_WALK_DEPTH: usize = 64;
