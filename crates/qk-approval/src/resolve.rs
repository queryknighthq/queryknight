//! Approval resolution layered after pure evaluation.
//!
//! Sequence:
//!
//! ```text
//! EvaluationResult
//!   Allow | Deny -> returned unchanged (provider never contacted)
//!   RequireApproval
//!     -> retry id resolves a live matching grant? use it (no provider call)
//!     -> live session grant matches? use it (no provider call)
//!     -> no provider? APPROVAL_UNAVAILABLE
//!     -> provider verdict Approved/Denied/Waiting (+ store the row)
//!     -> provider failure? APPROVAL_UNAVAILABLE / APPROVAL_ERROR
//! ```
//!
//! Approvals apply ONLY to `RequireApproval` (INV-024): the resolver takes
//! the evaluation as input and never re-examines policy, so a stored grant
//! cannot override a `Deny` — there is simply no path that consults grants
//! for non-approval evaluations.

use qk_core::{
    exact_request_digest, exact_request_digest_v2, sql_fingerprint, Decision, DigestParam,
    EvaluationResult, ExactDigest, ExecutionContext, QueryShapeFingerprint, ReasonCode,
};
use qk_sql::SqlDialect;

use crate::id::ApprovalId;
use crate::provider::{ApprovalProvider, ApprovalRequest, ProviderDecision, ProviderError};
use crate::scope::{ApprovalScope, Scope};
use crate::store::{ApprovalBinding, ApprovalStore, ApprovalStoreError, GrantStatus, StoredGrant};

/// Default approval lifetime in milliseconds (mirrors the reference
/// 60-second default). Explicit per call; never read from the environment.
pub const DEFAULT_APPROVAL_TTL_MS: u64 = 60_000;

/// Maximum provider-detail characters kept in a human message (reference
/// bound; machine values stay typed).
pub const MAX_PROVIDER_DETAIL_CHARS: usize = 300;

/// Inputs to one resolution. Time and TTL are explicit parameters:
/// no clock reads, no environment reads.
pub struct ResolveRequest<'a> {
    /// Pure evaluation result (only `RequireApproval` proceeds).
    pub evaluation: &'a EvaluationResult,
    /// Trusted context (scope binding + session identity).
    pub context: &'a ExecutionContext,
    /// Dialect the SQL was evaluated under (part of exact identity).
    pub dialect: SqlDialect,
    /// Untrusted SQL under evaluation (hashed, never stored raw).
    pub sql: &'a str,
    /// Ordered bound parameters for exact identity (empty slice means
    /// no params → Exact V1; non-empty → Exact V2). qk-db constructs
    /// these from the actual driver-bound values.
    pub params: &'a [DigestParam],
    /// Retry token: a previously issued approval id, if any.
    pub approval_id: Option<&'a str>,
    /// Lifetime for newly stored grants.
    pub ttl_ms: u64,
    /// Current time in milliseconds since the Unix epoch.
    pub now_ms: u64,
}

/// How resolution concluded. Carries enough typed information for the later
/// audit layer (requested/granted/denied/unavailable/error/existing) with
/// no sink or IO here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionOutcome {
    /// Evaluation already allowed or denied; provider never contacted.
    NotRequired,
    /// A live stored grant matched (retry id or session grant).
    ExistingGrant,
    /// Provider approved just now.
    ProviderApproved,
    /// Provider denied just now.
    ProviderDenied,
    /// Provider still waiting; `approval_id` names the pending row.
    ProviderWaiting,
    /// No provider configured, or the provider reported unavailable.
    ProviderUnavailable,
    /// Provider call failed.
    ProviderError,
}

/// Final externally visible result. `decision`/`reason_code` follow the
/// frozen contract (`RequireApproval` -> `Allow`/`APPROVAL_GRANTED` after
/// approval). `table`/`column`/`operation` are preserved exactly where the
/// reference preserves them, dropped where it drops them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEvaluation {
    /// Final verdict.
    pub decision: Decision,
    /// Final machine reason.
    pub reason_code: ReasonCode,
    /// Human diagnostic message.
    pub message: String,
    /// Decisive policy path, when the evaluation named one.
    pub matched_policy: Option<String>,
    /// Pending or resolving approval id, when any.
    pub approval_id: Option<ApprovalId>,
    /// Machine-readable path taken.
    pub outcome: ResolutionOutcome,
}

/// Resolve an evaluation into a final result. Synchronous and side-effect
/// free except for explicit `store` writes (grant rows); deterministic
/// given its inputs. One implementation serves every `ApprovalStore`
/// backend; store failures fail closed (never `Allow`).
pub fn resolve(
    request: &ResolveRequest<'_>,
    store: &dyn ApprovalStore,
    provider: Option<&dyn ApprovalProvider>,
) -> ResolvedEvaluation {
    let evaluation = request.evaluation;
    if evaluation.decision != Decision::RequireApproval {
        return ResolvedEvaluation {
            decision: evaluation.decision,
            reason_code: evaluation.reason_code,
            message: evaluation.message.clone(),
            matched_policy: evaluation.matched_policy.clone(),
            approval_id: None,
            outcome: ResolutionOutcome::NotRequired,
        };
    }

    // Both identities, computed locally from trusted inputs (dialect comes
    // from the evaluation call, SQL from the request): a compromised
    // provider can never weaken the binding because providers never mint
    // identities, only verdicts under caller-stored bindings.
    // Version strategy (INV-041): no bound params produce Exact V1
    // (preserving existing approvals); any bound params produce Exact
    // V2 over dialect, SQL, and ordered values.
    let shape = sql_fingerprint(request.sql);
    let exact = if request.params.is_empty() {
        ExactDigest::V1(exact_request_digest(request.dialect, request.sql))
    } else {
        ExactDigest::V2(exact_request_digest_v2(
            request.dialect,
            request.sql,
            request.params,
        ))
    };
    let scope = scope_of(request.context);

    // Retry path: a live grant with matching EXACT digest and scope
    // resolves without contacting the provider (single-approval retry).
    // Literal changes alter the digest, so the same token cannot authorize
    // them. Unknown, mismatched, or waiting ids fall through (waiting stays
    // pending on the same id; anything else proceeds as a fresh request).
    // Store failures here fail closed; unknown or corrupt ids behave as
    // fresh (provider re-ask, never a grant).
    if let Some(id) = request.approval_id {
        match retry_outcome(request, store, id, &shape, &exact, &scope) {
            Retry::Settled(resolved) => return resolved,
            Retry::Pending(resolved) => return resolved,
            Retry::Fresh => {}
            Retry::StoreFailed(resolved) => return resolved,
        }
    }

    // Session path: a live session-scoped grant for this query SHAPE and
    // scope authorizes without contacting the provider. Shape matching is
    // explicitly broader than token matching (literal variants share a
    // session grant by frozen design); scope dimensions still bind fully.
    // Store failures fail closed.
    if let Some(session_id) = &request.context.session_id {
        match store.find_session_grant(session_id, &shape, &scope, request.now_ms) {
            Ok(Some(grant)) => {
                if let Some(resolved) = verify_session_grant(request, &grant, &scope, &shape) {
                    return resolved;
                }
            }
            Ok(None) => {}
            Err(_) => {
                return store_failure(request, "session lookup failed");
            }
        }
    }

    let Some(provider) = provider else {
        return ResolvedEvaluation {
            decision: Decision::Deny,
            reason_code: ReasonCode::ApprovalUnavailable,
            message: "approval required but no approval provider is configured; failing closed"
                .to_owned(),
            matched_policy: evaluation.matched_policy.clone(),
            approval_id: None,
            outcome: ResolutionOutcome::ProviderUnavailable,
        };
    };

    let approval_request = ApprovalRequest {
        fingerprint: shape.clone(),
        scope: scope.clone(),
        reason_code: evaluation.reason_code,
        message: evaluation.message.clone(),
        matched_policy: evaluation.matched_policy.clone(),
        table: evaluation.table.clone(),
        column: evaluation.column.clone(),
        operation: evaluation.operation.clone(),
        // Exact execution identity for providers that persist
        // remotely (daemon verify path). Human/provider code never
        // validates hashes; the daemon compares opaquely.
        exact,
    };
    match provider.request(&approval_request) {
        Ok(response) => {
            let stored = StoredGrant {
                id: response.id.clone(),
                shape: shape.clone(),
                binding: match exact {
                    ExactDigest::V1(digest) => ApprovalBinding::ExactV1(digest),
                    ExactDigest::V2(digest) => ApprovalBinding::ExactV2(digest),
                },
                scope,
                status: match response.decision {
                    ProviderDecision::Approved => GrantStatus::Approved,
                    ProviderDecision::Denied => GrantStatus::Denied,
                    ProviderDecision::Waiting => GrantStatus::Waiting,
                },
                reuse: Scope::Once,
                expires_at_ms: request.now_ms.saturating_add(request.ttl_ms),
                reason_code: evaluation.reason_code,
                message: evaluation.message.clone(),
                risk: String::new(),
                operation_summary: String::new(),
                schema_ddl: None,
                schema_diff: None,
                matched_policy: evaluation.matched_policy.clone(),
                decided_at_ms: None,
                decided_by: None,
            };
            // A verdict the store cannot durably record must not become an
            // executable or pending result: without durable state, retries
            // and audits cannot observe it. Fail closed instead.
            if store.insert_grant(stored).is_err() {
                return store_failure(request, "grant persistence failed");
            }
            match response.decision {
                ProviderDecision::Approved => ResolvedEvaluation {
                    decision: Decision::Allow,
                    reason_code: ReasonCode::ApprovalGranted,
                    message: format!("approved via approval {}", response.id.as_str()),
                    matched_policy: evaluation.matched_policy.clone(),
                    approval_id: Some(response.id.clone()),
                    outcome: ResolutionOutcome::ProviderApproved,
                },
                ProviderDecision::Denied => ResolvedEvaluation {
                    decision: Decision::Deny,
                    reason_code: ReasonCode::ApprovalDenied,
                    message: format!("denied via approval {}", response.id.as_str()),
                    matched_policy: evaluation.matched_policy.clone(),
                    approval_id: Some(response.id.clone()),
                    outcome: ResolutionOutcome::ProviderDenied,
                },
                ProviderDecision::Waiting => ResolvedEvaluation {
                    decision: Decision::RequireApproval,
                    reason_code: evaluation.reason_code,
                    message: evaluation.message.clone(),
                    matched_policy: evaluation.matched_policy.clone(),
                    approval_id: Some(response.id.clone()),
                    outcome: ResolutionOutcome::ProviderWaiting,
                },
            }
        }
        Err(ProviderError::Unavailable) => ResolvedEvaluation {
            decision: Decision::Deny,
            reason_code: ReasonCode::ApprovalUnavailable,
            message: "approval required but no approval provider is configured; failing closed"
                .to_owned(),
            matched_policy: evaluation.matched_policy.clone(),
            approval_id: None,
            outcome: ResolutionOutcome::ProviderUnavailable,
        },
        Err(ProviderError::Transport(detail)) => ResolvedEvaluation {
            decision: Decision::Deny,
            reason_code: ReasonCode::ApprovalError,
            message: format!(
                "approval provider failed closed: {}",
                detail
                    .chars()
                    .take(MAX_PROVIDER_DETAIL_CHARS)
                    .collect::<String>()
            ),
            matched_policy: evaluation.matched_policy.clone(),
            approval_id: None,
            outcome: ResolutionOutcome::ProviderError,
        },
    }
}

fn scope_of(context: &ExecutionContext) -> ApprovalScope {
    ApprovalScope {
        session_id: context.session_id.clone(),
        integration: context.integration.clone(),
        environment: context.environment.clone(),
        database: context.database_key().to_owned(),
        agent_id: context.agent_key().to_owned(),
        tool: context.tool_key().to_owned(),
    }
}

enum Retry {
    Settled(ResolvedEvaluation),
    Pending(ResolvedEvaluation),
    Fresh,
    StoreFailed(ResolvedEvaluation),
}

/// Fail-closed mapping for store failures during resolution. The machine
/// value stays `APPROVAL_ERROR`; the human message carries bounded detail.
fn store_failure(request: &ResolveRequest<'_>, detail: &str) -> ResolvedEvaluation {
    ResolvedEvaluation {
        decision: Decision::Deny,
        reason_code: ReasonCode::ApprovalError,
        message: format!("approval store failed closed: {detail}"),
        matched_policy: request.evaluation.matched_policy.clone(),
        approval_id: None,
        outcome: ResolutionOutcome::ProviderError,
    }
}

fn retry_outcome(
    request: &ResolveRequest<'_>,
    store: &dyn ApprovalStore,
    id: &str,
    shape: &QueryShapeFingerprint,
    exact: &ExactDigest,
    scope: &ApprovalScope,
) -> Retry {
    let evaluation = request.evaluation;
    let grant = match store.get_grant(&ApprovalId::new(id.to_owned())) {
        Ok(Some(grant)) => grant,
        // Unknown ids behave as fresh (provider re-ask, never a grant).
        // Corrupt rows behave as unknown: they can never match, and
        // blocking new approvals on one bad row would be a wider denial.
        Ok(None) => return Retry::Fresh,
        Err(ApprovalStoreError::CorruptState(_)) => return Retry::Fresh,
        Err(_) => return Retry::StoreFailed(store_failure(request, "grant lookup failed")),
    };
    // Token binding: exact grants require VERSION plus digest
    // equality (any literal, param, dialect, or whitespace change
    // alters it; V1 rows never satisfy V2 requests and vice versa —
    // old parameterized V1 rows cannot authorize new V2 requests);
    // `Shape` grants (daemon flow, which never sees SQL) require shape
    // equality instead. Scope must match fully either way, and legacy
    // bindings never qualify. The reference mints a new approval row
    // on mismatch; we proceed as a fresh request the same way.
    let bound = match (&grant.binding, &exact) {
        (ApprovalBinding::ExactV1(digest), ExactDigest::V1(want)) => digest == want,
        (ApprovalBinding::ExactV2(digest), ExactDigest::V2(want)) => digest == want,
        (ApprovalBinding::ShapeV1, _) => grant.shape == *shape,
        _ => false,
    };
    if !bound || !grant.scope.matches(scope) {
        return Retry::Fresh;
    }
    if request.now_ms >= grant.expires_at_ms {
        // Expired approvals deny (the reference maps expiry to denial, not
        // to a fresh request).
        return Retry::Settled(ResolvedEvaluation {
            decision: Decision::Deny,
            reason_code: ReasonCode::ApprovalDenied,
            message: format!("denied via approval {id}"),
            matched_policy: evaluation.matched_policy.clone(),
            approval_id: Some(ApprovalId::new(id.to_owned())),
            outcome: ResolutionOutcome::ProviderDenied,
        });
    }
    match grant.status {
        GrantStatus::Approved => Retry::Settled(granted(request, &ApprovalId::new(id.to_owned()))),
        GrantStatus::Denied => Retry::Settled(ResolvedEvaluation {
            decision: Decision::Deny,
            reason_code: ReasonCode::ApprovalDenied,
            message: format!("denied via approval {id}"),
            matched_policy: evaluation.matched_policy.clone(),
            approval_id: Some(ApprovalId::new(id.to_owned())),
            outcome: ResolutionOutcome::ProviderDenied,
        }),
        GrantStatus::Waiting => Retry::Pending(ResolvedEvaluation {
            decision: Decision::RequireApproval,
            reason_code: evaluation.reason_code,
            message: evaluation.message.clone(),
            matched_policy: evaluation.matched_policy.clone(),
            approval_id: Some(ApprovalId::new(id.to_owned())),
            outcome: ResolutionOutcome::ProviderWaiting,
        }),
    }
}

/// Re-verify a store-returned session candidate before authorizing: the
/// store narrows, but authorization semantics stay here. Defense in depth
/// against a persistence implementation that filters loosely.
fn verify_session_grant(
    request: &ResolveRequest<'_>,
    grant: &StoredGrant,
    scope: &ApprovalScope,
    shape: &QueryShapeFingerprint,
) -> Option<ResolvedEvaluation> {
    if !grant.binding.authorizable()
        || grant.status != GrantStatus::Approved
        || grant.reuse != Scope::Session
        || grant.shape != *shape
        || grant.scope.session_id.as_deref() != request.context.session_id.as_deref()
        || !grant.scope.matches(scope)
        || request.now_ms >= grant.expires_at_ms
    {
        return None;
    }
    Some(granted(request, &grant.id))
}

fn granted(request: &ResolveRequest<'_>, id: &ApprovalId) -> ResolvedEvaluation {
    ResolvedEvaluation {
        decision: Decision::Allow,
        reason_code: ReasonCode::ApprovalGranted,
        message: format!("approved via approval {id}"),
        matched_policy: request.evaluation.matched_policy.clone(),
        approval_id: Some(id.clone()),
        outcome: ResolutionOutcome::ExistingGrant,
    }
}
