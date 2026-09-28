//! Trusted execution context for policy evaluation.
//!
//! These fields are populated by the integration layer (MCP, CLI, proxy),
//! never derived from SQL text. Free-form agent input must never flow into
//! identity fields; only the listed fields participate in rule matching.

/// Who is asking, and under which policy scope. All matching treats a
/// missing optional field as the empty string (least privilege: an unknown
/// agent, database, or tool matches only wildcard/empty patterns, exactly
/// like the reference implementation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionContext {
    /// Integration adapter name: `mcp`, `cli`, `proxy`, `openshell`, ...
    /// Required: rules can scope on it.
    pub integration: String,
    /// Environment scope key as named in the policy file (`production`, ...).
    /// Free-form string: must match policy keys to select a scope.
    pub environment: String,
    /// Database identity key as named in the policy file (`main`, ...).
    /// `None` falls back to the `*` scope, then to defaults.
    pub database: Option<String>,
    /// Agent identity for `agents` rules.
    pub agent_id: Option<String>,
    /// Tool/operation source for `tools` rules (e.g. `db_query`).
    pub tool: Option<String>,
    /// Session identity for approval binding (MCP/daemon session id).
    /// Unset outside sessioned transports; missing sessions never match
    /// session-scoped grants.
    pub session_id: Option<String>,
}

impl ExecutionContext {
    /// Database scope key used for policy resolution (`""` when unset).
    #[must_use]
    pub fn database_key(&self) -> &str {
        self.database.as_deref().unwrap_or("")
    }

    /// Agent identity used for `agents` rule matching (`""` when unset).
    #[must_use]
    pub fn agent_key(&self) -> &str {
        self.agent_id.as_deref().unwrap_or("")
    }

    /// Tool name used for `tools` rule matching (`""` when unset).
    #[must_use]
    pub fn tool_key(&self) -> &str {
        self.tool.as_deref().unwrap_or("")
    }
}
