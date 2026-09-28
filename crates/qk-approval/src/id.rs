//! Approval identifiers: an opaque token type so ids can never be confused
//! with fingerprints, digests, or SQL at the type level.

use std::fmt::{self, Display, Formatter};

/// Opaque approval token. Created by providers (or test generators) and
/// echoed back on retry; carries no meaning itself — all authorization
/// comes from the bound grant row.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApprovalId(String);

impl ApprovalId {
    /// Wrap an externally supplied id (retry tokens, provider responses).
    pub fn new(id: String) -> Self {
        Self(id)
    }

    /// The token text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for ApprovalId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for ApprovalId {
    fn from(id: String) -> Self {
        Self(id)
    }
}

impl From<&str> for ApprovalId {
    fn from(id: &str) -> Self {
        Self(id.to_owned())
    }
}
