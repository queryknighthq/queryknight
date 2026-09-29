//! Local control-plane HTTP API over `qk-store`.
//!
//! Thin adapter only: routing, loopback binding, token authentication,
//! request/response mapping, and bounded timeouts live here.
//! Authorization semantics stay in `qk-core` / `qk-approval`; SQL is never
//! executed by this crate. No static UI serving, no token/pid/log files,
//! no MCP — those land in later commits.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod config;
pub mod dto;
pub mod error;
pub mod ids;
pub mod routes;
pub mod runtime;
pub mod server;
pub mod state;

pub use auth::{generate_token, AuthToken};
pub use config::{DaemonConfig, DEFAULT_BIND, DEFAULT_BODY_LIMIT_BYTES, DEFAULT_PORT};
pub use error::DaemonError;
pub use server::{router, serve};
pub use state::{store_op, DaemonState};
