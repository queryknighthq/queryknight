//! Approval scope: the typed dimensions an approval binds to.

use std::fmt::{self, Display, Formatter};

/// How long a grant stays usable once approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Usable for matching requests (retry with the same approval id).
    Once,
    /// Additionally usable without an id while session, fingerprint, and
    /// scope all match (mirrors the reference session-allow rows, except
    /// session grants honor approval expiry where the reference rows never
    /// expire — a deliberate conservative tightening).
    Session,
}

impl Scope {
    /// Frozen wire names (`once`, `session`).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Session => "session",
        }
    }

    /// Session scope means shape scope: the grant binds the normalized
    /// query shape (literal variants share it) rather than exact request
    /// bytes. `Once` always binds exact bytes.
    #[must_use]
    pub fn is_shape_scoped(&self) -> bool {
        matches!(self, Self::Session)
    }

    /// Parse a wire name; anything else is rejected (never defaulted).
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "once" => Some(Self::Once),
            "session" => Some(Self::Session),
            _ => None,
        }
    }
}

impl Display for Scope {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Who recorded a human decision. Frozen vocabulary from the reference
/// approval objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionSource {
    /// Terminal UI.
    Tui,
    /// Command line.
    Cli,
    /// Web UI.
    Ui,
    /// Agent chat flow.
    Mcp,
    /// Policy-driven (reserved for future daemon use).
    Policy,
}

impl DecisionSource {
    /// Frozen wire name.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tui => "tui",
            Self::Cli => "cli",
            Self::Ui => "ui",
            Self::Mcp => "mcp",
            Self::Policy => "policy",
        }
    }
}

/// Full binding dimensions for an approval. Built from the trusted
/// execution context; missing values normalize to `""` and match only
/// missing values (never broaden).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalScope {
    /// Session identity; `None` disables session-grant matching entirely.
    pub session_id: Option<String>,
    /// Integration adapter name.
    pub integration: String,
    /// Environment scope key.
    pub environment: String,
    /// Database scope key (`""` when unset).
    pub database: String,
    /// Agent identity (`""` when unset).
    pub agent_id: String,
    /// Tool name (`""` when unset).
    pub tool: String,
}

impl ApprovalScope {
    /// True when every dimension matches. Strict superset of the reference
    /// `(session_id, fingerprint)` check: the fingerprint is compared
    /// separately by the caller, all six dimensions here must also agree.
    #[must_use]
    pub fn matches(&self, other: &ApprovalScope) -> bool {
        self.session_id == other.session_id
            && self.integration == other.integration
            && self.environment == other.environment
            && self.database == other.database
            && self.agent_id == other.agent_id
            && self.tool == other.tool
    }
}

#[cfg(test)]
mod tests {
    use super::{ApprovalScope, Scope};

    fn scope() -> ApprovalScope {
        ApprovalScope {
            session_id: Some("s1".to_owned()),
            integration: "mcp".to_owned(),
            environment: "production".to_owned(),
            database: "main".to_owned(),
            agent_id: "a".to_owned(),
            tool: "db_query".to_owned(),
        }
    }

    #[test]
    fn scope_names() {
        assert_eq!(Scope::Once.as_str(), "once");
        assert_eq!(Scope::Session.as_str(), "session");
        assert_eq!(Scope::parse("once"), Some(Scope::Once));
        assert_eq!(Scope::parse("session"), Some(Scope::Session));
        assert_eq!(Scope::parse("forever"), None);
    }

    #[test]
    fn every_dimension_binds() {
        let base = scope();
        assert!(base.matches(&scope()));
        let mut changed = scope();
        changed.database = "other".to_owned();
        assert!(!base.matches(&changed));
        let mut changed = scope();
        changed.session_id = None;
        assert!(!base.matches(&changed));
        let mut changed = scope();
        changed.agent_id = String::new();
        assert!(!base.matches(&changed));
    }
}
