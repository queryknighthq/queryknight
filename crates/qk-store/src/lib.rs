//! SQLite persistence for QueryKnight daemon state: approvals, sessions,
//! query events, and connections.
//!
//! Design notes:
//!
//! - Schema compatible with the TypeScript daemon database: existing TS
//!   databases open directly and migrate forward (additive `ALTER TABLE`
//!   steps only, never rebuilds). Version tracked by a single
//!   `PRAGMA user_version`.
//! - `rusqlite` with the `bundled` feature: deterministic SQLite build on
//!   every release target instead of whatever system library happens to be
//!   installed (the bundled version is fixed in `Cargo.lock`).
//! - One `Connection` behind a `Mutex` (rusqlite connections are `Send`);
//!   critical sections hold single statements or short explicit
//!   transactions. No pool, no connection ownership outside this crate.
//! - Persisted rows are untrusted input: every read validates digests,
//!   enums, and timestamps into typed errors (INV-026). Nothing panics on
//!   database contents.
//! - PRAGMAs set on open: `journal_mode=WAL` (reference parity; daemon
//!   read concurrency) and a bounded `busy_timeout` (5 s default;
//!   contention surfaces as typed `Busy`, never hangs forever). Nothing
//!   else is tuned: no evidence demands it.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod events;
pub mod schema;
pub mod sessions;
pub mod store;

pub use error::StoreError;
pub use events::{EventRecord, EventView, SessionEvent};
pub use schema::SCHEMA_VERSION;
pub use sessions::{ConnectionRecord, SessionRecord};
pub use store::{Store, DEFAULT_BUSY_TIMEOUT_MS, DEFAULT_EVENT_CAP};
