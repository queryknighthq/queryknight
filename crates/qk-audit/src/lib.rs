//! Observation-only security audit + OCSF export.
//!
//! ```text
//! guarded authorization/execution outcome → Observation → AuditEvent → sinks
//!                                                   ↘ OCSF → SIEM shape
//! ```
//!
//! Audit observes typed authorization/execution outcomes; it never
//! authorizes, never retries, and sink failures never feed back into enforcement.
//! `docs/audit.md`.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod event;
pub mod level;
pub mod observation;
pub mod observer;
pub mod ocsf;
pub mod redaction;
pub mod sink;

pub use event::{new_event_id, timestamp_iso, AttemptOutcome, AuditDecision, AuditEvent};
pub use level::{truncate_chars, SqlLogLevel, MAX_SQL_LOG_CHARS};
pub use observation::{Observation, ObservedApproval, ObservedExecution};
pub use observer::{observed_approval_from_outcome, observed_execution_from_outcome, Observer};
pub use ocsf::{
    to_ocsf, OcsfEvent, CATEGORY_NAME, CATEGORY_UID, CLASS_NAME, CLASS_UID, OCSF_VERSION,
};
pub use redaction::redact_credentials;
pub use sink::{AuditSink, AuditSinkError, MemorySink, NoopSink};
