//! Query-event history records. Raw retrieval for the future daemon/UI;
//! aggregation summaries are a daemon-layer concern, not storage.

use rusqlite::Row;

/// A query event as stored (all columns, including nullable metrics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    /// Event id (opaque; the daemon port mints `qke_<hex>`).
    pub id: String,
    /// Owning session id.
    pub session_id: String,
    /// Connection id.
    pub connection_id: String,
    /// Source (`mcp`, `proxy`, ...).
    pub source: String,
    /// Query-shape fingerprint (16-hex compat rendering).
    pub fingerprint: String,
    /// Raw SQL when recorded (may contain secrets; never logged by this crate).
    pub sql: Option<String>,
    /// Classification class text (`read`, `write`, ...).
    pub query_class: String,
    /// Risk text.
    pub risk: String,
    /// Decision text.
    pub decision: String,
    /// Milliseconds since Unix epoch.
    pub started_at_ms: u64,
    /// Duration in milliseconds.
    pub duration_ms: Option<u64>,
    /// Rows returned/affected and byte/token counters.
    pub rows_returned: Option<i64>,
    /// Rows affected.
    pub rows_affected: Option<i64>,
    /// Bytes returned.
    pub bytes_returned: Option<i64>,
    /// Estimated tokens returned.
    pub estimated_tokens_returned: Option<i64>,
    /// Estimated tokens avoided.
    pub estimated_tokens_avoided: Option<i64>,
    /// Error code text.
    pub error_code: Option<String>,
}

/// The UI/history projection returned by listings (mirrors the reference
/// `EventView`: a subset of columns in a fixed order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventView {
    /// Event id.
    pub id: String,
    /// Owning session id.
    pub session_id: String,
    /// Source.
    pub source: String,
    /// Query-shape fingerprint.
    pub fingerprint: String,
    /// Raw SQL when recorded.
    pub sql: Option<String>,
    /// Classification class text.
    pub query_class: String,
    /// Risk text.
    pub risk: String,
    /// Decision text.
    pub decision: String,
    /// Milliseconds since Unix epoch.
    pub started_at_ms: u64,
    /// Rows returned/affected and byte counters.
    pub rows_returned: Option<i64>,
    /// Rows affected.
    pub rows_affected: Option<i64>,
    /// Bytes returned.
    pub bytes_returned: Option<i64>,
    /// Error code text.
    pub error_code: Option<String>,
}

impl EventRecord {
    /// Read a full record row. Timestamps validate like views; metrics
    /// stay nullable by schema.
    pub(crate) fn read(row: &Row) -> Result<Self, crate::StoreError> {
        use crate::error::classify_rusqlite;
        use crate::store::as_u64;
        let started_at: i64 = row.get(9).map_err(classify_rusqlite)?;
        let duration: Option<i64> = row.get(10).map_err(classify_rusqlite)?;
        Ok(Self {
            id: row.get(0).map_err(classify_rusqlite)?,
            session_id: row.get(1).map_err(classify_rusqlite)?,
            connection_id: row.get(2).map_err(classify_rusqlite)?,
            source: row.get(3).map_err(classify_rusqlite)?,
            fingerprint: row.get(4).map_err(classify_rusqlite)?,
            sql: row.get(5).map_err(classify_rusqlite)?,
            query_class: row.get(6).map_err(classify_rusqlite)?,
            risk: row.get(7).map_err(classify_rusqlite)?,
            decision: row.get(8).map_err(classify_rusqlite)?,
            started_at_ms: as_u64(started_at, "query_events.started_at")?,
            duration_ms: duration
                .map(|value| as_u64(value, "query_events.duration_ms"))
                .transpose()?,
            rows_returned: row.get(11).map_err(classify_rusqlite)?,
            rows_affected: row.get(12).map_err(classify_rusqlite)?,
            bytes_returned: row.get(13).map_err(classify_rusqlite)?,
            estimated_tokens_returned: row.get(14).map_err(classify_rusqlite)?,
            estimated_tokens_avoided: row.get(15).map_err(classify_rusqlite)?,
            error_code: row.get(16).map_err(classify_rusqlite)?,
        })
    }
}

impl EventView {
    /// Read a listing row. Negative timestamps fail the conversion and
    /// surface as `InvalidRow` at the call site; everything else reads
    /// verbatim (display data, validated structurally, never silently
    /// defaulted).
    pub(crate) fn read(row: &Row) -> Result<Self, crate::StoreError> {
        use crate::error::classify_rusqlite;
        let started_at: i64 = row.get(8).map_err(classify_rusqlite)?;
        Ok(Self {
            id: row.get(0).map_err(classify_rusqlite)?,
            session_id: row.get(1).map_err(classify_rusqlite)?,
            source: row.get(2).map_err(classify_rusqlite)?,
            fingerprint: row.get(3).map_err(classify_rusqlite)?,
            sql: row.get(4).map_err(classify_rusqlite)?,
            query_class: row.get(5).map_err(classify_rusqlite)?,
            risk: row.get(6).map_err(classify_rusqlite)?,
            decision: row.get(7).map_err(classify_rusqlite)?,
            started_at_ms: crate::store::as_u64(started_at, "query_events.started_at")?,
            rows_returned: row.get(9).map_err(classify_rusqlite)?,
            rows_affected: row.get(10).map_err(classify_rusqlite)?,
            bytes_returned: row.get(11).map_err(classify_rusqlite)?,
            error_code: row.get(12).map_err(classify_rusqlite)?,
        })
    }
}

/// Input for recording one event (mirrors the reference `recordEvent`
/// fields; ids and timestamps are caller-supplied for testability).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEvent {
    /// Event id (opaque).
    pub id: String,
    /// Owning session id.
    pub session_id: String,
    /// Connection id (resolved by the caller).
    pub connection_id: String,
    /// Source.
    pub source: String,
    /// Query-shape fingerprint.
    pub fingerprint: String,
    /// Raw SQL when recorded.
    pub sql: Option<String>,
    /// Classification class text.
    pub query_class: String,
    /// Risk text.
    pub risk: String,
    /// Decision text.
    pub decision: String,
    /// Milliseconds since Unix epoch.
    pub started_at_ms: u64,
    /// Duration in milliseconds.
    pub duration_ms: Option<u64>,
    /// Rows returned.
    pub rows_returned: Option<i64>,
    /// Rows affected.
    pub rows_affected: Option<i64>,
    /// Bytes returned.
    pub bytes_returned: Option<i64>,
    /// Estimated tokens returned.
    pub estimated_tokens_returned: Option<i64>,
    /// Estimated tokens avoided.
    pub estimated_tokens_avoided: Option<i64>,
    /// Error code text.
    pub error_code: Option<String>,
}
