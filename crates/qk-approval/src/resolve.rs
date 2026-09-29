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
    exact_request_digest, sql_fingerprint, Decision, EvaluationResult, ExactRequestDigest,
    ExecutionContext, ReasonCode,
};
use qk_sql::SqlDialect;

use crate::id::ApprovalId;
use crate::provider::{ApprovalProvider, ApprovalRequest, ProviderDecision, ProviderError};
use crate::scope::{ApprovalScope, Scope};
use crate::store::{ApprovalBinding, ApprovalStore, GrantStatus, StoredGrant};

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
/// given its inputs.
pub fn resolve(
    request: &ResolveRequest<'_>,
    store: &mut dyn ApprovalStore,
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
    let shape = sql_fingerprint(request.sql);
    let exact = exact_request_digest(request.dialect, request.sql);
    let scope = scope_of(request.context);

    // Retry path: a live grant with matching EXACT digest and scope
    // resolves without contacting the provider (single-approval retry).
    // Literal changes alter the digest, so the same token cannot authorize
    // them. Unknown, mismatched, or waiting ids fall through (waiting stays
    // pending on the same id; anything else proceeds as a fresh request).
    if let Some(id) = request.approval_id {
        match retry_outcome(request, store, id, &exact, &scope) {
            Retry::Settled(resolved) => return resolved,
            Retry::Pending(resolved) => return resolved,
            Retry::Fresh => {}
        }
    }

    // Session path: a live session-scoped grant for this query SHAPE and
    // scope authorizes without contacting the provider. Shape matching is
    // explicitly broader than token matching (literal variants share a
    // session grant by frozen design); scope dimensions still bind fully.
    if let Some(session_id) = &request.context.session_id {
        // Clone the id out first: `store` is borrowed mutably below.
        let session_grant = store
            .find_session_grant(session_id, &shape, &scope, request.now_ms)
            .map(|grant| grant.id.clone());
        if let Some(id) = session_grant {
            return granted(request, &id);
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
    };
    match provider.request(&approval_request) {
        Ok(response) => {
            let stored = StoredGrant {
                id: response.id.clone(),
                shape: shape.clone(),
                exact,
                binding: ApprovalBinding::ExactV1,
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
                matched_policy: evaluation.matched_policy.clone(),
                decided_at_ms: None,
                decided_by: None,
            };
            store.insert(stored);
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
}

fn retry_outcome(
    request: &ResolveRequest<'_>,
    store: &dyn ApprovalStore,
    id: &str,
    exact: &ExactRequestDigest,
    scope: &ApprovalScope,
) -> Retry {
    let evaluation = request.evaluation;
    let Some(grant) = store.get(id) else {
        return Retry::Fresh;
    };
    // Exact-request binding: the grant must be fully bound, and any
    // literal (or dialect, or scope) change alters the digest or scope, so
    // the token cannot be reused for it. The reference mints a new
    // approval row in this case; we proceed as a fresh request the same
    // way.
    if grant.binding != ApprovalBinding::ExactV1
        || grant.exact != *exact
        || !grant.scope.matches(scope)
    {
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
