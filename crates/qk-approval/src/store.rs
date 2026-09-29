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

/// Binding completeness of a stored grant. Legacy and incomplete rows are
/// historical state only: the type system separates them from fully-bound
/// grants so no lookup path can accidentally treat one as the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalBinding {
    /// Complete modern binding: exact digest plus all scope dimensions.
    /// The only kind eligible for authorization.
    ExactV1,
    /// Migrated legacy state (or otherwise incomplete binding): visible
    /// for history and introspection, never authorization-capable.
    LegacyShape,
}

impl ApprovalBinding {
    /// Frozen storage rendering.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ExactV1 => "exact_v1",
            Self::LegacyShape => "legacy_shape",
        }
    }
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
    /// Binding completeness; only `ExactV1` can authorize.
    pub binding: ApprovalBinding,
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

/// Approval storage failure. Backend-neutral: SQLite maps lock
/// contention, constraint violations, corrupt rows, and engine errors onto
/// these; resolution maps every variant fail-closed (never `Allow`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalStoreError {
    /// Backend temporarily unavailable (lock contention, busy exhaustion).
    Unavailable(String),
    /// State conflict: duplicate id on insert, or a decision that lost a
    /// race against an already-decided grant.
    Conflict(String),
    /// Unknown approval id.
    NotFound(String),
    /// Grant exists but is not in a usable state (already decided, or
    /// expired at the given timestamp).
    InvalidState(String),
    /// Persisted row failed validation. Never an active grant.
    CorruptState(String),
    /// Any other backend failure (open, migration, engine errors).
    Internal(String),
}

impl Display for ApprovalStoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(detail) => write!(f, "approval store unavailable: {detail}"),
            Self::Conflict(detail) => write!(f, "approval store conflict: {detail}"),
            Self::NotFound(detail) => write!(f, "approval not found: {detail}"),
            Self::InvalidState(detail) => write!(f, "approval invalid state: {detail}"),
            Self::CorruptState(detail) => write!(f, "approval corrupt state: {detail}"),
            Self::Internal(detail) => write!(f, "approval store error: {detail}"),
        }
    }
}

impl std::error::Error for ApprovalStoreError {}

/// Approval storage abstraction over owned values. All operations are
/// explicitly fallible and shareable: `Send + Sync` so the future daemon
/// can hold one store behind `Arc` across requests. Reads return owned
/// grants (no borrowed rows escape a backend lock); matching semantics
/// stay in the resolver, never in the store.
pub trait ApprovalStore: Send + Sync {
    /// Persist a grant (new requests and provider verdicts). Duplicate ids
    /// are a `Conflict`, never an overwrite.
    fn insert_grant(&self, grant: StoredGrant) -> Result<(), ApprovalStoreError>;
    /// Fetch by id. `None` means absent; expiry is applied by matching,
    /// not here.
    fn get_grant(&self, id: &ApprovalId) -> Result<Option<StoredGrant>, ApprovalStoreError>;
    /// Record a human decision on a live waiting grant. Exactly one
    /// concurrent decider wins; losers observe `Conflict` (already
    /// decided) or `InvalidState` (expired).
    fn decide_grant(
        &self,
        id: &ApprovalId,
        status: GrantStatus,
        reuse: Scope,
        source: DecisionSource,
        now_ms: u64,
    ) -> Result<(), ApprovalStoreError>;
    /// Candidate session-scoped approvals for a session and shape. The
    /// store narrows (status, reuse, session, shape); the resolver still
    /// verifies binding, scope, and liveness before authorizing anything.
    fn find_session_grant(
        &self,
        session_id: &str,
        shape: &QueryShapeFingerprint,
        scope: &ApprovalScope,
        now_ms: u64,
    ) -> Result<Option<StoredGrant>, ApprovalStoreError>;
}

/// Explicitly owned in-memory store. A short mutex guards the map so the
/// store is `Send + Sync` like every backend must be; critical sections
/// are single hash operations.
#[derive(Debug, Default)]
pub struct InMemoryApprovalStore {
    grants: std::sync::Mutex<HashMap<String, StoredGrant>>,
}

impl InMemoryApprovalStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn poisoned() -> ApprovalStoreError {
        ApprovalStoreError::Internal("approval store lock poisoned".to_owned())
    }

    /// Live (unexpired) waiting/approved/denied state for matching.
    fn live(grant: &StoredGrant, now_ms: u64) -> bool {
        now_ms < grant.expires_at_ms
    }
}

impl ApprovalStore for InMemoryApprovalStore {
    fn insert_grant(&self, grant: StoredGrant) -> Result<(), ApprovalStoreError> {
        let mut grants = self.grants.lock().map_err(|_| Self::poisoned())?;
        if grants.contains_key(grant.id.as_str()) {
            return Err(ApprovalStoreError::Conflict(format!(
                "approval {} exists",
                grant.id
            )));
        }
        grants.insert(grant.id.as_str().to_owned(), grant);
        Ok(())
    }

    fn get_grant(&self, id: &ApprovalId) -> Result<Option<StoredGrant>, ApprovalStoreError> {
        Ok(self
            .grants
            .lock()
            .map_err(|_| Self::poisoned())?
            .get(id.as_str())
            .cloned())
    }

    fn decide_grant(
        &self,
        id: &ApprovalId,
        status: GrantStatus,
        reuse: Scope,
        source: DecisionSource,
        now_ms: u64,
    ) -> Result<(), ApprovalStoreError> {
        let mut grants = self.grants.lock().map_err(|_| Self::poisoned())?;
        let Some(grant) = grants.get_mut(id.as_str()) else {
            return Err(ApprovalStoreError::NotFound(format!("approval {id}")));
        };
        if !Self::live(grant, now_ms) {
            return Err(ApprovalStoreError::InvalidState(format!(
                "approval {id} expired"
            )));
        }
        if grant.status != GrantStatus::Waiting {
            return Err(ApprovalStoreError::Conflict(format!(
                "approval {id} already decided"
            )));
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
    ) -> Result<Option<StoredGrant>, ApprovalStoreError> {
        Ok(self
            .grants
            .lock()
            .map_err(|_| Self::poisoned())?
            .values()
            .find(|grant| {
                grant.binding == ApprovalBinding::ExactV1
                    && grant.status == GrantStatus::Approved
                    && grant.reuse == Scope::Session
                    && grant.shape == *shape
                    && grant.scope.session_id.as_deref() == Some(session_id)
                    && grant.scope.matches(scope)
                    && Self::live(grant, now_ms)
            })
            .cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ApprovalBinding, ApprovalStore, ApprovalStoreError, GrantStatus, InMemoryApprovalStore,
        StoredGrant,
    };
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
            binding: ApprovalBinding::ExactV1,
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

    fn id(text: &str) -> ApprovalId {
        ApprovalId::new(text.to_owned())
    }

    #[test]
    fn decide_lifecycle_and_boundaries() {
        let store = InMemoryApprovalStore::new();
        assert_eq!(
            store.decide_grant(
                &id("missing"),
                GrantStatus::Approved,
                Scope::Once,
                DecisionSource::Cli,
                0
            ),
            Err(ApprovalStoreError::NotFound("approval missing".to_owned()))
        );
        store.insert_grant(grant()).expect("insert");
        // Duplicate insert conflicts, never overwrites.
        assert!(matches!(
            store.insert_grant(grant()),
            Err(ApprovalStoreError::Conflict(_))
        ));
        // Expiry boundary: now == expires_at is expired (reference parity).
        assert!(matches!(
            store.decide_grant(
                &id("qka-1"),
                GrantStatus::Approved,
                Scope::Session,
                DecisionSource::Cli,
                1_000_000
            ),
            Err(ApprovalStoreError::InvalidState(_))
        ));
        store
            .decide_grant(
                &id("qka-1"),
                GrantStatus::Approved,
                Scope::Session,
                DecisionSource::Cli,
                999_999,
            )
            .expect("decide");
        let stored = store.get_grant(&id("qka-1")).expect("get").expect("stored");
        assert_eq!(stored.status, GrantStatus::Approved);
        assert_eq!(stored.reuse, Scope::Session);
        assert_eq!(stored.decided_by, Some(DecisionSource::Cli));
        // Decided grants reject further decisions as conflicts.
        assert!(matches!(
            store.decide_grant(
                &id("qka-1"),
                GrantStatus::Denied,
                Scope::Once,
                DecisionSource::Ui,
                999_999
            ),
            Err(ApprovalStoreError::Conflict(_))
        ));
    }

    #[test]
    fn session_grant_matching() {
        let store = InMemoryApprovalStore::new();
        let mut approved = grant();
        approved.status = GrantStatus::Approved;
        approved.reuse = Scope::Session;
        store.insert_grant(approved).expect("insert");
        assert!(store
            .find_session_grant("s1", &shape(), &scope(), 999_999)
            .expect("lookup")
            .is_some());
        // Wrong session, wrong fingerprint, expired, or Once reuse: no match.
        assert!(store
            .find_session_grant("s2", &shape(), &scope(), 999_999)
            .expect("lookup")
            .is_none());
        assert!(store
            .find_session_grant("s1", &other_shape(), &scope(), 999_999)
            .expect("lookup")
            .is_none());
        assert!(store
            .find_session_grant("s1", &shape(), &scope(), 1_000_000)
            .expect("lookup")
            .is_none());
        let mut other_scope = scope();
        other_scope.database = "other".to_owned();
        assert!(store
            .find_session_grant("s1", &shape(), &other_scope, 999_999)
            .expect("lookup")
            .is_none());
    }
}
