//! Session and connection records. Raw retrieval; summary aggregation is
//! a daemon-layer concern.

/// A stored session row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// Session id (opaque; the daemon port mints `qks_<hex>`).
    pub id: String,
    /// Connection id.
    pub connection_id: String,
    /// Agent name, when known.
    pub agent: Option<String>,
    /// Milliseconds since Unix epoch.
    pub started_at_ms: u64,
    /// Milliseconds since Unix epoch, when ended.
    pub ended_at_ms: Option<u64>,
    /// Source (`mcp`, `proxy`, `manual`, ...).
    pub source: String,
}

/// A stored connection row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRecord {
    /// Connection id (`qkc_<12hex>` of the key in the reference flow).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Engine text.
    pub engine: String,
    /// Environment text.
    pub environment: String,
    /// Source text.
    pub source: String,
    /// Database name, when known.
    pub database: Option<String>,
    /// Host label, when known.
    pub host_label: Option<String>,
}
