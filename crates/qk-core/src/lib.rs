//! QueryKnight core: policy v1 model, validation, and glob matching.
//!
//! Commit 1 scope only. No SQL parsing, execution, MCP, daemon, or
//! integrations live here yet.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod context;
pub mod decision;
pub mod error;
pub mod evaluate;
pub mod fingerprint;
pub mod glob;
pub mod policy;

pub use context::ExecutionContext;
pub use decision::{Decision, ReasonCode};
pub use error::PolicyLoadError;
pub use evaluate::{evaluate, EvaluateOptions, EvaluationRequest, EvaluationResult};
pub use fingerprint::{
    exact_request_digest, normalize_sql, sql_fingerprint, ExactRequestDigest, QueryShapeFingerprint,
};
pub use glob::{check_glob, glob_match};
/// Policy-file verdict type (config level), aliased to avoid clashing with
/// the evaluation [`Decision`].
pub use policy::Decision as PolicyDecision;
pub use policy::{
    parse_policy, DatabasePolicy, Defaults, EnvironmentPolicy, MutationsPolicy, ParseFallback,
    PolicyFile, PolicyRule, PolicyTestCase, RowSafety, SensitiveAction, SensitivePolicy,
};
