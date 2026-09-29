//! QueryKnight-owned database adapter abstraction. Small on purpose:
//! only operations proven necessary by the reference/MCP audit. No ORM,
//! no capability normalization beyond the frozen capability flags.

use crate::config::SecretUrl;
use crate::error::{DbError, DbErrorKind};
use crate::result::{ImpactEstimate, PingResult, RawResult, TableInfo, TableRef};

/// Frozen capability flags (per-engine table from the audit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Named-schema introspection (`information_schema` / `SHOW`).
    pub schemas: bool,
    /// `EXPLAIN` support for estimates.
    pub explain: bool,
    /// `EXPLAIN` of write statements (planner-only, never ANALYZE).
    pub explain_writes: bool,
    /// Row sampling query support.
    pub sampling: bool,
}

/// A bound parameter value for driver binding (never interpolated).
#[derive(Debug, Clone, PartialEq)]
pub enum Param {
    /// SQL NULL.
    Null,
    /// Boolean.
    Bool(bool),
    /// Signed integer.
    Int(i64),
    /// Unsigned integer.
    UInt(u64),
    /// Binary float.
    Float(f64),
    /// Text.
    Text(String),
    /// Raw bytes.
    Bytes(Vec<u8>),
}

impl Param {
    /// Convert agent-supplied JSON params (frozen: raw JSON values).
    /// Objects/arrays are rejected (drivers bind scalars).
    pub fn from_json(value: &serde_json::Value) -> Result<Self, DbError> {
        match value {
            serde_json::Value::Null => Ok(Self::Null),
            serde_json::Value::Bool(value) => Ok(Self::Bool(*value)),
            serde_json::Value::Number(value) => {
                if let Some(int) = value.as_i64() {
                    Ok(Self::Int(int))
                } else if let Some(uint) = value.as_u64() {
                    Ok(Self::UInt(uint))
                } else if let Some(float) = value.as_f64() {
                    Ok(Self::Float(float))
                } else {
                    Err(DbError::new(
                        DbErrorKind::Query,
                        "unsupported numeric parameter",
                    ))
                }
            }
            serde_json::Value::String(text) => Ok(Self::Text(text.clone())),
            _ => Err(DbError::new(
                DbErrorKind::Query,
                "compound JSON values cannot be bound as parameters",
            )),
        }
    }
}

/// Case-insensitive keyword match on a word boundary (frozen `\b`
/// semantics for statement sniffing).
pub fn starts_with_word(text: &str, keyword: &str) -> bool {
    let trimmed = text.trim_start();
    if trimmed.len() < keyword.len() || !trimmed[..keyword.len()].eq_ignore_ascii_case(keyword) {
        return false;
    }
    trimmed.as_bytes()[keyword.len()..]
        .first()
        .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
}

/// Read-shaped statement detection for result routing
/// (`select/explain/with/values/show/desc`, frozen family).
pub fn looks_like_read(sql: &str) -> bool {
    ["select", "explain", "with", "values", "show", "desc"]
        .iter()
        .any(|keyword| starts_with_word(sql, keyword))
}

/// QueryKnight-owned adapter. Implementations hold no QueryKnight
/// state (no store access); connections are per-operation unless the
/// adapter documents otherwise.
#[async_trait::async_trait]
pub trait DatabaseAdapter: Send + Sync {
    /// Engine name (`postgres`, `mysql`, `sqlite`).
    fn engine(&self) -> &'static str;

    /// Frozen capability flags.
    fn capabilities(&self) -> Capabilities;

    /// Minimal handshake against the configured database: connect,
    /// run the engine's cheapest probe, report latency, disconnect.
    /// Never executes user SQL.
    async fn test_connection(&self, url: &SecretUrl) -> Result<PingResult, DbError>;

    /// Execute one single statement with bound params. Multi-statement
    /// input is rejected by the service before reaching here; adapters
    /// additionally refuse driver-level multi execution where the
    /// driver distinguishes it.
    async fn execute(
        &self,
        url: &SecretUrl,
        sql: &str,
        params: &[Param],
    ) -> Result<RawResult, DbError>;

    /// Planner-only `EXPLAIN` of one statement (never ANALYZE, never
    /// executed). Returns raw plan text for estimate parsing.
    async fn explain(
        &self,
        url: &SecretUrl,
        sql: &str,
        params: &[Param],
    ) -> Result<String, DbError>;

    /// List schemas (engines without schemas report their default).
    async fn list_schemas(&self, url: &SecretUrl) -> Result<Vec<String>, DbError>;

    /// List tables (and views) in a schema, or the default scope.
    async fn list_tables(
        &self,
        url: &SecretUrl,
        schema: Option<&str>,
    ) -> Result<Vec<TableRef>, DbError>;

    /// Describe one table by (schema, name) identifiers.
    async fn describe_table(
        &self,
        url: &SecretUrl,
        schema: Option<&str>,
        name: &str,
    ) -> Result<TableInfo, DbError>;

    /// Current-state DDL snapshot for one table. Postgres returns
    /// `Unsupported` (no subprocesses in the service).
    async fn dump_schema(
        &self,
        url: &SecretUrl,
        schema: Option<&str>,
        name: &str,
    ) -> Result<String, DbError> {
        let _ = (url, schema, name);
        Err(DbError::new(
            DbErrorKind::Unsupported,
            "schema dump is not supported for this engine",
        ))
    }

    /// Build a bounded random-sample SELECT for a table (pure
    /// constructor; execution goes through the normal path).
    fn sample_sql(&self, schema: Option<&str>, name: &str, limit: usize) -> String;

    /// Planner impact estimate for UPDATE/DELETE (planner row counts,
    /// upper bound). Returns `None` when not applicable; failures
    /// degrade to `None`, never to authorization changes.
    async fn estimate_impact(
        &self,
        url: &SecretUrl,
        sql: &str,
        params: &[Param],
    ) -> Result<Option<ImpactEstimate>, DbError> {
        let _ = (url, sql, params);
        Ok(None)
    }
}
