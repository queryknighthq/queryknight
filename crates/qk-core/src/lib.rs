//! QueryKnight core: policy v1 model, validation, and glob matching.
//!
//! Commit 1 scope only. No SQL parsing, execution, MCP, daemon, or
//! integrations live here yet.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod glob;
pub mod policy;

pub use error::PolicyLoadError;
pub use glob::{check_glob, glob_match};
pub use policy::{
    parse_policy, DatabasePolicy, Decision, Defaults, EnvironmentPolicy, MutationsPolicy,
    ParseFallback, PolicyFile, PolicyRule, PolicyTestCase, RowSafety, SensitiveAction,
    SensitivePolicy,
};
