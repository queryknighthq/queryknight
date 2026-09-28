//! Approval storage: explicit ownership, no globals, no persistence here.
//! Grants are reusable (never consumed): a valid grant authorizes every
//! matching request until it expires. Denials persist too, so a denied
//! retry stays denied without re-asking the provider.

use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};

use qk_core::{ExactRequestDigest, QueryShapeFingerprint, ReasonCode};

use crate::id::ApprovalId;
use crate::scope::{ApprovalScope, DecisionSource, Scope};

/// Stored approval state. `Expired` is computed at match time, never
/// persisted (mirrors the reference lazy expiry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantStatus {
    /// Awaiting a human decision.
    Waiting,
    /// Human approved.
    Approved,
    /// Human denied.
    Denied,
}

/// One stored approval row.
///
/// Every grant carries both identities: `exact` binds approval-id retries
/// to the precise request bytes, while `shape` serves explicitly
/// shape-scoped session grants (and compatibility display). Storing both
/// is required because shape cannot be derived back from a one-way exact
/// digest when a waiting grant is later upgraded to session scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredGrant {
    /// Approval id (provider-assigned or generated).
    pub id: ApprovalId,
    /// Normalized query-shape identity (compat + session-shape binding).
    pub shape: QueryShapeFingerprint,
    /// Exact request identity (approval-token binding).
    pub exact: ExactRequestDigest,
    /// Scope the grant binds to.
    pub scope: ApprovalScope,
    /// Current state.
    pub status: GrantStatus,
    /// Once or session reuse.
    pub reuse: Scope,
    /// Milliseconds since Unix epoch; live while `now_ms < expires_at_ms`
    /// (boundary matches the reference: `expires_at <= now` is expired).
    pub expires_at_ms: u64,
    /// Reason that produced the approval request.
    pub reason_code: ReasonCode,
    /// Human message from evaluation.
    pub message: String,
    /// Decisive policy path, when any.
    pub matched_policy: Option<String>,
    /// Milliseconds since Unix epoch of the decision, when decided.
    pub decided_at_ms: Option<u64>,
    /// Who recorded the decision, when decided.
    pub decided_by: Option<DecisionSource>,
}

/// Failure to record a human decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecideError {
    /// No grant with that id.
    UnknownApproval,
    /// Grant is not waiting (already decided).
    NotWaiting,
    /// Grant already expired (boundary: `now_ms >= expires_at_ms`).
    Expired,
}

impl Display for DecideError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownApproval => write!(f, "approval not found"),
            Self::NotWaiting => write!(f, "approval is not waiting"),
            Self::Expired => write!(f, "approval expired"),
        }
    }
}

impl std::error::Error for DecideError {}

/// Approval storage abstraction. The daemon port implements this over
/// SQLite; this crate ships the in-memory implementation only.
pub trait ApprovalStore {
    /// Persist a grant (new requests and provider verdicts).
    fn insert(&mut self, grant: StoredGrant);
    /// Fetch by id (no expiry applied; matching applies it).
    fn get(&self, id: &str) -> Option<&StoredGrant>;
    /// Record a human decision on a live waiting grant.
    fn decide(
        &mut self,
        id: &str,
        status: GrantStatus,
        reuse: Scope,
        source: DecisionSource,
        now_ms: u64,
    ) -> Result<(), DecideError>;
    /// Find a live session-scoped approval matching session, query shape,
    /// and full scope. Expired grants never match.
    fn find_session_grant(
        &self,
        session_id: &str,
        shape: &QueryShapeFingerprint,
        scope: &ApprovalScope,
        now_ms: u64,
    ) -> Option<&StoredGrant>;
}

/// Explicitly owned in-memory store. Single-threaded clarity: `&mut` for
/// writes, `&` for reads, no locks, no globals.
#[derive(Debug, Default)]
pub struct InMemoryApprovalStore {
    grants: HashMap<String, StoredGrant>,
}

impl InMemoryApprovalStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Live (unexpired) waiting/approved/denied state for matching.
    fn live(grant: &StoredGrant, now_ms: u64) -> bool {
        now_ms < grant.expires_at_ms
    }
}

impl ApprovalStore for InMemoryApprovalStore {
    fn insert(&mut self, grant: StoredGrant) {
        self.grants.insert(grant.id.as_str().to_owned(), grant);
    }

    fn get(&self, id: &str) -> Option<&StoredGrant> {
        self.grants.get(id)
    }

    fn decide(
        &mut self,
        id: &str,
        status: GrantStatus,
        reuse: Scope,
        source: DecisionSource,
        now_ms: u64,
    ) -> Result<(), DecideError> {
        let Some(grant) = self.grants.get_mut(id) else {
            return Err(DecideError::UnknownApproval);
        };
        if !Self::live(grant, now_ms) {
            return Err(DecideError::Expired);
        }
        if grant.status != GrantStatus::Waiting {
            return Err(DecideError::NotWaiting);
        }
        grant.status = status;
        grant.reuse = reuse;
        grant.decided_at_ms = Some(now_ms);
        grant.decided_by = Some(source);
        Ok(())
    }

    fn find_session_grant(
        &self,
        session_id: &str,
        shape: &QueryShapeFingerprint,
        scope: &ApprovalScope,
        now_ms: u64,
    ) -> Option<&StoredGrant> {
        self.grants.values().find(|grant| {
            grant.status == GrantStatus::Approved
                && grant.reuse == Scope::Session
                && grant.shape == *shape
                && grant.scope.session_id.as_deref() == Some(session_id)
                && grant.scope.matches(scope)
                && Self::live(grant, now_ms)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{ApprovalStore, DecideError, GrantStatus, InMemoryApprovalStore, StoredGrant};
    use crate::id::ApprovalId;
    use crate::scope::{ApprovalScope, DecisionSource, Scope};
    use qk_core::{exact_request_digest, sql_fingerprint, ReasonCode};
    use qk_sql::SqlDialect;

    fn scope() -> ApprovalScope {
        ApprovalScope {
            session_id: Some("s1".to_owned()),
            integration: "mcp".to_owned(),
            environment: "production".to_owned(),
            database: "main".to_owned(),
            agent_id: String::new(),
            tool: String::new(),
        }
    }

    fn shape() -> qk_core::QueryShapeFingerprint {
        qk_core::sql_fingerprint("SELECT 1")
    }

    fn other_shape() -> qk_core::QueryShapeFingerprint {
        qk_core::sql_fingerprint("SELECT id FROM users")
    }

    fn grant() -> StoredGrant {
        StoredGrant {
            id: ApprovalId::new("qka-1".to_owned()),
            shape: sql_fingerprint("SELECT 1"),
            exact: exact_request_digest(SqlDialect::PostgreSql, "SELECT 1"),
            scope: scope(),
            status: GrantStatus::Waiting,
            reuse: Scope::Once,
            expires_at_ms: 1_000_000,
            reason_code: ReasonCode::RequireApproval,
            message: "m".to_owned(),
            matched_policy: None,
            decided_at_ms: None,
            decided_by: None,
        }
    }

    #[test]
    fn decide_lifecycle_and_boundaries() {
        let mut store = InMemoryApprovalStore::new();
        assert_eq!(
            store.decide(
                "missing",
                GrantStatus::Approved,
                Scope::Once,
                DecisionSource::Cli,
                0
            ),
            Err(DecideError::UnknownApproval)
        );
        store.insert(grant());
        // Expiry boundary: now == expires_at is expired (reference parity).
        assert_eq!(
            store.decide(
                "qka-1",
                GrantStatus::Approved,
                Scope::Session,
                DecisionSource::Cli,
                1_000_000
            ),
            Err(DecideError::Expired)
        );
        store
            .decide(
                "qka-1",
                GrantStatus::Approved,
                Scope::Session,
                DecisionSource::Cli,
                999_999,
            )
            .expect("decide");
        let stored = store.get("qka-1").expect("stored");
        assert_eq!(stored.status, GrantStatus::Approved);
        assert_eq!(stored.reuse, Scope::Session);
        assert_eq!(stored.decided_by, Some(DecisionSource::Cli));
        // Decided grants reject further decisions.
        assert_eq!(
            store.decide(
                "qka-1",
                GrantStatus::Denied,
                Scope::Once,
                DecisionSource::Ui,
                999_999
            ),
            Err(DecideError::NotWaiting)
        );
    }

    #[test]
    fn session_grant_matching() {
        let mut store = InMemoryApprovalStore::new();
        let mut approved = grant();
        approved.status = GrantStatus::Approved;
        approved.reuse = Scope::Session;
        store.insert(approved);
        assert!(store
            .find_session_grant("s1", &shape(), &scope(), 999_999)
            .is_some());
        // Wrong session, wrong fingerprint, expired, or Once reuse: no match.
        assert!(store
            .find_session_grant("s2", &shape(), &scope(), 999_999)
            .is_none());
        assert!(store
            .find_session_grant("s1", &other_shape(), &scope(), 999_999)
            .is_none());
        assert!(store
            .find_session_grant("s1", &shape(), &scope(), 1_000_000)
            .is_none());
        let mut other_scope = scope();
        other_scope.database = "other".to_owned();
        assert!(store
            .find_session_grant("s1", &shape(), &other_scope, 999_999)
            .is_none());
    }
}
