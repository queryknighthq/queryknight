//! Guarded multi-dialect database execution: the final security choke
//! point between agent SQL and real databases.
//!
//! ```text
//! trusted connection + SQL request
//!   → evaluate() the exact SQL that will run
//!   → approval resolution when required (qk-approval, never local logic)
//!   → ONLY explicit executable Allow → adapter → bounded result
//! ```
//!
//! Drivers (tokio-postgres, mysql_async, rusqlite) never escape the
//! `adapters` modules; policy and approval never depend on them.
//! Contract: `docs/database-execution.md`.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod adapter;
pub mod adapters;
pub mod budget;
pub mod config;
pub mod cursor;
pub mod error;
pub mod result;
pub mod service;
pub mod value;

pub use adapter::{Capabilities, DatabaseAdapter, Param};
pub use budget::{ResultBudget, MAX_BYTES, MAX_ROWS, MAX_TOKENS};
pub use config::{DbConfig, SecretUrl};
pub use cursor::{CursorStore, StoredCursor, CURSOR_TTL};
pub use error::{DbError, DbErrorKind, MAX_ERROR_MESSAGE};
pub use result::{
    BudgetedResult, ColumnInfo, ForeignKeyInfo, ImpactEstimate, IndexInfo, PingResult, RawResult,
    SchemaInfo, TableInfo, TableKind, TableRef,
};
pub use service::{
    ApprovalSetup, BlockedReason, ExecuteRequest, ExecutionOutcome, ExecutionService, ExplainCall,
    GuardedCall, PendingApproval, TrustedContext, DEFAULT_TIMEOUT,
};
pub use value::{DbValue, MAX_SAFE_INTEGER};
