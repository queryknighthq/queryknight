//! Thin MCP stdio adapter over the finished QueryKnight services.
//!
//! ```text
//! MCP stdio → argument validation → trusted context → qk-db guarded
//! execution (or daemon control plane) → frozen text results
//! ```
//!
//! No SQL analysis, policy, approval matching, or driver logic lives
//! here. Contract: `docs/mcp.md`.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod daemon;
pub mod error;
pub mod format;
pub mod history;
pub mod server;

pub use config::{database_key_for, environment_from_env, McpConnection};
pub use daemon::{DaemonApprovalProvider, DaemonEndpoint};
pub use error::{protocol_error, ErrorKind};
pub use format::{
    format_blocked, format_explain, format_pending_approval, format_query, format_schema_overview,
    format_table, format_tables, parse_table_ref,
};
pub use history::{classify_for_history, HistoryEvent, HistoryRecorder};
pub use server::{
    connection_url_from_env, instructions, load_policy, serve_stdio, ApprovalStatus,
    ApprovalsDecideArgs, DbDescribeArgs, DbExplainArgs, DbQueryArgs, DbSampleArgs, DbSchemaArgs,
    DbTablesArgs, McpState, QueryKnightServer, SERVER_NAME,
};
