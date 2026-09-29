//! QueryKnight-owned result model. Rows are positional value arrays
//! plus column metadata — duplicate column names are preserved
//! positionally (documented against the TS last-wins objects).

use serde::ser::{Serialize, SerializeStruct, Serializer};

use crate::value::DbValue;

/// One executed statement's raw output, before budgets.
#[derive(Debug, Clone, PartialEq)]
pub struct RawResult {
    /// Column names in positional order (duplicates preserved).
    pub columns: Vec<String>,
    /// Rows as positional value arrays (`rows[i][j]` is column `j`).
    pub rows: Vec<Vec<DbValue>>,
    /// Rows changed by a mutation, when the driver reports it.
    pub rows_affected: Option<u64>,
}

impl RawResult {
    /// Empty result (mutations without row output).
    pub fn empty() -> Self {
        Self {
            columns: Vec::new(),
            rows: Vec::new(),
            rows_affected: None,
        }
    }

    /// Row count before budgeting.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }
}

/// Budgeted, agent-facing result (frozen `BudgetedQueryResult` shape).
#[derive(Debug, Clone, PartialEq)]
pub struct BudgetedResult {
    /// Column names in positional order.
    pub columns: Vec<String>,
    /// Kept rows (positional arrays).
    pub rows: Vec<Vec<DbValue>>,
    /// Rows changed by a mutation, when reported.
    pub rows_affected: Option<u64>,
    /// Rows actually shown (== `rows.len()`).
    pub rows_shown: usize,
    /// Planner row estimate for SELECTs, when obtainable.
    pub estimated_rows_matched: Option<u64>,
    /// Any budget cut occurred (row/byte/token cap or cap probe).
    pub truncated: bool,
    /// Serialized JSON bytes of the kept rows.
    pub bytes_returned: usize,
    /// `ceil(bytes / 4)` heuristic (estimate, never exact).
    pub estimated_tokens_returned: usize,
    /// Estimated tokens NOT sent thanks to truncation, when known.
    pub estimated_tokens_avoided: Option<usize>,
    /// Continuation cursor for truncated SELECTs, when enabled.
    pub cursor: Option<String>,
}

impl Serialize for BudgetedResult {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut out = serializer.serialize_struct("BudgetedResult", 9)?;
        out.serialize_field("columns", &self.columns)?;
        out.serialize_field("rows", &self.rows)?;
        out.serialize_field("rowsAffected", &self.rows_affected)?;
        out.serialize_field("rowsShown", &self.rows_shown)?;
        out.serialize_field("estimatedRowsMatched", &self.estimated_rows_matched)?;
        out.serialize_field("truncated", &self.truncated)?;
        out.serialize_field("bytesReturned", &self.bytes_returned)?;
        out.serialize_field("estimatedTokensReturned", &self.estimated_tokens_returned)?;
        out.serialize_field("estimatedTokensAvoided", &self.estimated_tokens_avoided)?;
        out.serialize_field("cursor", &self.cursor)?;
        out.end()
    }
}

/// Planner impact estimate for a mutation (estimated, never actual).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImpactEstimate {
    /// Estimated affected rows (planner row counts, upper bound).
    pub estimated_rows: u64,
}

/// Column metadata for introspection results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnInfo {
    /// Column name.
    pub name: String,
    /// Engine-reported type text.
    pub data_type: String,
    /// Whether NULL is allowed.
    pub nullable: bool,
    /// Default expression text, when any.
    pub default: Option<String>,
}

/// Index metadata for introspection results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexInfo {
    /// Index name.
    pub name: String,
    /// Indexed columns in order.
    pub columns: Vec<String>,
    /// Uniqueness flag.
    pub unique: bool,
}

/// Foreign-key metadata for introspection results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignKeyInfo {
    /// Constraint name (synthesized where the engine has none).
    pub name: String,
    /// Local columns.
    pub columns: Vec<String>,
    /// Referenced schema, when any.
    pub referenced_schema: Option<String>,
    /// Referenced table.
    pub referenced_table: String,
    /// Referenced columns.
    pub referenced_columns: Vec<String>,
}

/// Table description (frozen `TableDefinition` shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableInfo {
    /// Schema (engine default when the engine has none).
    pub schema: Option<String>,
    /// Table name.
    pub name: String,
    /// Table or view.
    pub kind: TableKind,
    /// Columns in ordinal order.
    pub columns: Vec<ColumnInfo>,
    /// Primary-key columns in order.
    pub primary_key: Vec<String>,
    /// Secondary indexes.
    pub indexes: Vec<IndexInfo>,
    /// Foreign keys.
    pub foreign_keys: Vec<ForeignKeyInfo>,
}

/// Table or view discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableKind {
    /// Base table.
    Table,
    /// View.
    View,
}

/// Schema listing entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaInfo {
    /// Schema name.
    pub name: String,
}

/// Table listing entry (columns excluded; use [`TableInfo`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableRef {
    /// Schema, when the engine reports one.
    pub schema: Option<String>,
    /// Table name.
    pub name: String,
    /// Table or view.
    pub kind: TableKind,
}

/// Connection handshake result (frozen `DatabasePingResult` shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingResult {
    /// The handshake succeeded.
    pub ok: bool,
    /// Round-trip milliseconds.
    pub latency_ms: u64,
    /// Server version string, when reported.
    pub server_version: Option<String>,
}
