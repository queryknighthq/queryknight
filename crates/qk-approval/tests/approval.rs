//! Approval resolution security: replay protection, scope binding, expiry,
//! fail-closed providers, and the structural guarantee that approvals only
//! ever transition `RequireApproval` (INV-024).

use qk_approval::{
    resolve, ApprovalIdGenerator, ApprovalProvider, ApprovalRequest, ApprovalStore,
    CountingIdGenerator, DenyByDefaultProvider, ErrorProvider, GrantStatus, InMemoryApprovalStore,
    ProviderDecision, ProviderError, ProviderResponse, ResolutionOutcome, ResolveRequest, Scope,
    StoredGrant, TestProvider, UnavailableProvider, DEFAULT_APPROVAL_TTL_MS,
};
use qk_core::{
    evaluate, parse_policy, Decision, EvaluateOptions, EvaluationRequest, EvaluationResult,
    ExecutionContext, PolicyFile, ReasonCode,
};

const POLICY: &str = "version: 1\ndefaults:\n  decision: deny\nenvironments:\n  production:\n    databases:\n      main:\n        allow:\n          - operations: [select]\n        approval_required:\n          - operations: [delete]\n        sensitive:\n          columns: [users.password_hash]\n";

const SQL: &str = "DELETE FROM customers WHERE id = 42";
const NOW: u64 = 1_000_000;

fn policy() -> PolicyFile {
    parse_policy(POLICY).expect("policy")
}

fn context() -> ExecutionContext {
    ExecutionContext {
        integration: "mcp".to_owned(),
        environment: "production".to_owned(),
        database: Some("main".to_owned()),
        agent_id: Some("agent-1".to_owned()),
        tool: Some("db_query".to_owned()),
        session_id: Some("session-1".to_owned()),
    }
}

fn require_approval() -> (EvaluationResult, ExecutionContext, PolicyFile) {
    let policy = policy();
    let context = context();
    let result = evaluate(
        &EvaluationRequest {
            context: &context,
            dialect: "postgres".parse().expect("dialect"),
            sql: SQL,
            policy: &policy,
        },
        &EvaluateOptions::default(),
    );
    assert_eq!(result.decision, Decision::RequireApproval);
    (result, context, policy)
}

fn resolve_with(
    evaluation: &EvaluationResult,
    context: &ExecutionContext,
    sql: &str,
    approval_id: Option<&str>,
    store: &mut dyn ApprovalStore,
    provider: Option<&dyn ApprovalProvider>,
) -> qk_approval::ResolvedEvaluation {
    resolve(
        &ResolveRequest {
            evaluation,
            context,
            dialect: qk_sql::SqlDialect::PostgreSql,
            sql,
            approval_id,
            ttl_ms: DEFAULT_APPROVAL_TTL_MS,
            now_ms: NOW,
        },
        store,
        provider,
    )
}

struct PanickingProvider;

impl ApprovalProvider for PanickingProvider {
    fn request(&self, _request: &ApprovalRequest) -> Result<ProviderResponse, ProviderError> {
        panic!("provider must never be contacted");
    }
}

// ---------------------------------------------------------------------------
// §23/§24: non-approval results and hard denials are untouchable.
// ---------------------------------------------------------------------------

#[test]
fn allow_and_deny_never_contact_provider() {
    let policy = policy();
    let context = context();
    for (sql, decision) in [
        ("SELECT 1", Decision::Allow),
        ("DROP TABLE t", Decision::Deny),
        ("DELETE FROM t", Decision::Deny),
        ("FROBNICATE !!", Decision::Deny),
    ] {
        let evaluation = evaluate(
            &EvaluationRequest {
                context: &context,
                dialect: "postgres".parse().expect("dialect"),
                sql,
                policy: &policy,
            },
            &EvaluateOptions::default(),
        );
        assert_eq!(evaluation.decision, decision, "{sql:?}");
        let mut store = InMemoryApprovalStore::new();
        let resolved = resolve_with(
            &evaluation,
            &context,
            sql,
            None,
            &mut store,
            Some(&PanickingProvider),
        );
        assert_eq!(resolved.decision, decision, "{sql:?}");
        assert_eq!(resolved.outcome, ResolutionOutcome::NotRequired);
        assert!(resolved.approval_id.is_none(), "{sql:?}");
    }
}

#[test]
fn approval_cannot_override_hard_denials() {
    // A live approved grant for the exact fingerprint still cannot move any
    // hard denial: resolve() has no grant path for non-approval results.
    let policy = policy();
    let context = context();
    let denials = [
        "DROP TABLE t",
        "DELETE FROM t",
        "UPDATE t SET a = 1",
        "SELECT password_hash FROM users",
        "FROBNICATE !!",
        "CALL p()",
    ];
    for sql in denials {
        let evaluation = evaluate(
            &EvaluationRequest {
                context: &context,
                dialect: "postgres".parse().expect("dialect"),
                sql,
                policy: &policy,
            },
            &EvaluateOptions::default(),
        );
        assert_eq!(evaluation.decision, Decision::Deny, "{sql:?}");
        let mut store = InMemoryApprovalStore::new();
        store.insert(StoredGrant {
            id: qk_approval::ApprovalId::new("qka-live".to_owned()),
            shape: qk_core::sql_fingerprint(sql),
            exact: qk_core::exact_request_digest(qk_sql::SqlDialect::PostgreSql, sql),
            scope: qk_approval::ApprovalScope {
                session_id: Some("session-1".to_owned()),
                integration: "mcp".to_owned(),
                environment: "production".to_owned(),
                database: "main".to_owned(),
                agent_id: "agent-1".to_owned(),
                tool: "db_query".to_owned(),
            },
            status: GrantStatus::Approved,
            reuse: Scope::Session,
            expires_at_ms: NOW + 60_000,
            reason_code: ReasonCode::RequireApproval,
            message: "m".to_owned(),
            matched_policy: None,
            decided_at_ms: Some(NOW),
            decided_by: None,
        });
        let resolved = resolve_with(
            &evaluation,
            &context,
            sql,
            Some("qka-live"),
            &mut store,
            Some(&PanickingProvider),
        );
        assert_eq!(resolved.decision, Decision::Deny, "{sql:?}");
        assert_eq!(resolved.outcome, ResolutionOutcome::NotRequired);
    }
}

// ---------------------------------------------------------------------------
// Provider outcomes and fail-closed mapping.
// ---------------------------------------------------------------------------

#[test]
fn provider_outcome_mapping() {
    let (evaluation, context, _) = require_approval();
    // Granted.
    let mut store = InMemoryApprovalStore::new();
    let granted = TestProvider::new(vec![ProviderDecision::Approved]);
    let resolved = resolve_with(&evaluation, &context, SQL, None, &mut store, Some(&granted));
    assert_eq!(resolved.decision, Decision::Allow);
    assert_eq!(resolved.reason_code, ReasonCode::ApprovalGranted);
    assert_eq!(
        resolved.message,
        format!(
            "approved via approval {}",
            resolved.approval_id.clone().expect("id")
        )
    );
    assert_eq!(resolved.outcome, ResolutionOutcome::ProviderApproved);
    // Denied.
    let mut store = InMemoryApprovalStore::new();
    let denied = TestProvider::new(vec![ProviderDecision::Denied]);
    let resolved = resolve_with(&evaluation, &context, SQL, None, &mut store, Some(&denied));
    assert_eq!(resolved.decision, Decision::Deny);
    assert_eq!(resolved.reason_code, ReasonCode::ApprovalDenied);
    assert_eq!(resolved.outcome, ResolutionOutcome::ProviderDenied);
    // Waiting stays pending on the provider id.
    let mut store = InMemoryApprovalStore::new();
    let waiting = TestProvider::new(vec![ProviderDecision::Waiting]);
    let resolved = resolve_with(&evaluation, &context, SQL, None, &mut store, Some(&waiting));
    assert_eq!(resolved.decision, Decision::RequireApproval);
    assert_eq!(resolved.reason_code, ReasonCode::RequireApproval);
    assert!(resolved.approval_id.is_some());
    assert_eq!(resolved.outcome, ResolutionOutcome::ProviderWaiting);
    // Missing provider.
    let mut store = InMemoryApprovalStore::new();
    let resolved = resolve_with(&evaluation, &context, SQL, None, &mut store, None);
    assert_eq!(resolved.decision, Decision::Deny);
    assert_eq!(resolved.reason_code, ReasonCode::ApprovalUnavailable);
    assert_eq!(resolved.outcome, ResolutionOutcome::ProviderUnavailable);
    // Unavailable provider.
    let mut store = InMemoryApprovalStore::new();
    let resolved = resolve_with(
        &evaluation,
        &context,
        SQL,
        None,
        &mut store,
        Some(&UnavailableProvider),
    );
    assert_eq!(
        (resolved.decision, resolved.reason_code),
        (Decision::Deny, ReasonCode::ApprovalUnavailable)
    );
    // Failing provider.
    let mut store = InMemoryApprovalStore::new();
    let failing = ErrorProvider::new("paged human, got voicemail");
    let resolved = resolve_with(&evaluation, &context, SQL, None, &mut store, Some(&failing));
    assert_eq!(resolved.decision, Decision::Deny);
    assert_eq!(resolved.reason_code, ReasonCode::ApprovalError);
    assert!(resolved.message.contains("paged human, got voicemail"));
    // Default-deny provider.
    let mut store = InMemoryApprovalStore::new();
    let resolved = resolve_with(
        &evaluation,
        &context,
        SQL,
        None,
        &mut store,
        Some(&DenyByDefaultProvider),
    );
    assert_eq!(
        (resolved.decision, resolved.reason_code),
        (Decision::Deny, ReasonCode::ApprovalDenied)
    );
}

// ---------------------------------------------------------------------------
// Retry, session grants, replay protection, expiry.
// ---------------------------------------------------------------------------

#[test]
fn retry_resolves_without_reasking() {
    let (evaluation, context, _) = require_approval();
    let mut store = InMemoryApprovalStore::new();
    let provider = TestProvider::new(vec![ProviderDecision::Approved]);
    let first = resolve_with(
        &evaluation,
        &context,
        SQL,
        None,
        &mut store,
        Some(&provider),
    );
    assert_eq!(first.outcome, ResolutionOutcome::ProviderApproved);
    let id = first.approval_id.clone().expect("id");
    assert_eq!(provider.calls(), 1);
    // Retry with the id: grant path, provider untouched.
    let second = resolve_with(
        &evaluation,
        &context,
        SQL,
        Some(id.as_str()),
        &mut store,
        Some(&provider),
    );
    assert_eq!(second.decision, Decision::Allow);
    assert_eq!(second.reason_code, ReasonCode::ApprovalGranted);
    assert_eq!(second.outcome, ResolutionOutcome::ExistingGrant);
    assert_eq!(provider.calls(), 1);
}

#[test]
fn session_grant_flow() {
    let (evaluation, context, _) = require_approval();
    let mut store = InMemoryApprovalStore::new();
    let provider = TestProvider::new(vec![ProviderDecision::Waiting]);
    let pending = resolve_with(
        &evaluation,
        &context,
        SQL,
        None,
        &mut store,
        Some(&provider),
    );
    let id = pending.approval_id.clone().expect("pending id");
    // Human approves for the session out of band.
    store
        .decide(
            id.as_str(),
            GrantStatus::Approved,
            Scope::Session,
            qk_approval::DecisionSource::Cli,
            NOW,
        )
        .expect("decide");
    // Same request without an id now resolves via the session grant.
    let resolved = resolve_with(
        &evaluation,
        &context,
        SQL,
        None,
        &mut store,
        Some(&provider),
    );
    assert_eq!(resolved.decision, Decision::Allow);
    assert_eq!(resolved.outcome, ResolutionOutcome::ExistingGrant);
    assert_eq!(provider.calls(), 1, "session grant must not re-ask");
}

#[test]
fn replay_across_dimensions_fails() {
    let (evaluation, context, _) = require_approval();
    let mut store = InMemoryApprovalStore::new();
    let provider = TestProvider::new(vec![ProviderDecision::Approved]);
    let first = resolve_with(
        &evaluation,
        &context,
        SQL,
        None,
        &mut store,
        Some(&provider),
    );
    let id = first.approval_id.clone().expect("id");
    // Structurally changed SQL (different fingerprint): must not replay.
    let other_sql = "DELETE FROM orders WHERE id = 42";
    let other_eval = evaluate(
        &EvaluationRequest {
            context: &context,
            dialect: "postgres".parse().expect("dialect"),
            sql: other_sql,
            policy: &policy(),
        },
        &EvaluateOptions::default(),
    );
    assert_eq!(other_eval.decision, Decision::RequireApproval);
    let waiting = TestProvider::new(vec![ProviderDecision::Waiting]);
    let replayed = resolve_with(
        &other_eval,
        &context,
        other_sql,
        Some(id.as_str()),
        &mut store,
        Some(&waiting),
    );
    assert_ne!(replayed.outcome, ResolutionOutcome::ExistingGrant);
    assert_eq!(
        waiting.calls(),
        1,
        "mismatch falls through to a fresh request"
    );
    // Changed database / environment / agent / tool / session.
    let changed = context.clone();
    for mutate in [
        (|c: &mut ExecutionContext| c.database = Some("other".to_owned()))
            as fn(&mut ExecutionContext),
        |c| c.environment = "staging".to_owned(),
        |c| c.agent_id = Some("agent-2".to_owned()),
        |c| c.tool = Some("other-tool".to_owned()),
        |c| c.session_id = Some("session-2".to_owned()),
        |c| c.integration = "cli".to_owned(),
    ] {
        let mut altered = changed.clone();
        mutate(&mut altered);
        let probe = TestProvider::new(vec![ProviderDecision::Waiting]);
        let out = resolve_with(
            &evaluation,
            &altered,
            SQL,
            Some(id.as_str()),
            &mut store,
            Some(&probe),
        );
        assert_ne!(
            out.outcome,
            ResolutionOutcome::ExistingGrant,
            "dimension replay"
        );
    }
    let _ = changed;
}

#[test]
fn exact_token_rejects_literal_change() {
    // An exact (Once) approval token binds the precise request bytes:
    // `id = 43` must not reuse the token minted for `id = 42`. The
    // mismatch proceeds as a fresh request instead.
    let (evaluation, context, _) = require_approval();
    let mut store = InMemoryApprovalStore::new();
    let provider = TestProvider::new(vec![ProviderDecision::Approved]);
    let first = resolve_with(
        &evaluation,
        &context,
        SQL,
        None,
        &mut store,
        Some(&provider),
    );
    let id = first.approval_id.clone().expect("id");
    let variant_sql = "DELETE FROM customers WHERE id = 43";
    let variant_eval = evaluate(
        &EvaluationRequest {
            context: &context,
            dialect: "postgres".parse().expect("dialect"),
            sql: variant_sql,
            policy: &policy(),
        },
        &EvaluateOptions::default(),
    );
    assert_eq!(variant_eval.decision, Decision::RequireApproval);
    let idle = TestProvider::new(vec![ProviderDecision::Waiting]);
    let replayed = resolve_with(
        &variant_eval,
        &context,
        variant_sql,
        Some(id.as_str()),
        &mut store,
        Some(&idle),
    );
    assert_eq!(replayed.outcome, ResolutionOutcome::ProviderWaiting);
    assert_eq!(idle.calls(), 1, "literal change mints a fresh request");
}

#[test]
fn session_shape_accepts_literal_variant() {
    // Session scope explicitly means shape scope: after a session-scoped
    // approval, literal variants reuse the grant without re-asking, while
    // scope dimensions and the normalized shape still bind fully.
    let (evaluation, context, _) = require_approval();
    let mut store = InMemoryApprovalStore::new();
    let provider = TestProvider::new(vec![ProviderDecision::Waiting]);
    let pending = resolve_with(
        &evaluation,
        &context,
        SQL,
        None,
        &mut store,
        Some(&provider),
    );
    let id = pending.approval_id.clone().expect("id");
    store
        .decide(
            id.as_str(),
            GrantStatus::Approved,
            Scope::Session,
            qk_approval::DecisionSource::Cli,
            NOW,
        )
        .expect("decide");
    let variant_sql = "DELETE FROM customers WHERE id = 43";
    let variant_eval = evaluate(
        &EvaluationRequest {
            context: &context,
            dialect: "postgres".parse().expect("dialect"),
            sql: variant_sql,
            policy: &policy(),
        },
        &EvaluateOptions::default(),
    );
    let idle = TestProvider::new(vec![ProviderDecision::Waiting]);
    let reused = resolve_with(
        &variant_eval,
        &context,
        variant_sql,
        None,
        &mut store,
        Some(&idle),
    );
    assert_eq!(reused.decision, Decision::Allow);
    assert_eq!(reused.outcome, ResolutionOutcome::ExistingGrant);
    assert_eq!(idle.calls(), 0, "session shape must not re-ask");
    // A different shape under the same session does not reuse.
    let other_sql = "DELETE FROM orders WHERE id = 43";
    let other_eval = evaluate(
        &EvaluationRequest {
            context: &context,
            dialect: "postgres".parse().expect("dialect"),
            sql: other_sql,
            policy: &policy(),
        },
        &EvaluateOptions::default(),
    );
    let probe = TestProvider::new(vec![ProviderDecision::Waiting]);
    let other = resolve_with(
        &other_eval,
        &context,
        other_sql,
        None,
        &mut store,
        Some(&probe),
    );
    assert_eq!(other.outcome, ResolutionOutcome::ProviderWaiting);
    assert_eq!(probe.calls(), 1);
}

#[test]
fn expiry_and_unknown_ids() {
    let (evaluation, context, _) = require_approval();
    let mut store = InMemoryApprovalStore::new();
    let provider = TestProvider::new(vec![ProviderDecision::Approved]);
    let first = resolve_with(
        &evaluation,
        &context,
        SQL,
        None,
        &mut store,
        Some(&provider),
    );
    let id = first.approval_id.clone().expect("id");
    // Unknown id proceeds as a fresh request (never grants).
    let fresh = TestProvider::new(vec![ProviderDecision::Waiting]);
    let out = resolve_with(
        &evaluation,
        &context,
        SQL,
        Some("qka-nope"),
        &mut store,
        Some(&fresh),
    );
    assert_eq!(out.outcome, ResolutionOutcome::ProviderWaiting);
    assert_eq!(fresh.calls(), 1, "unknown id mints a fresh request");
    // Expired grant denies rather than grants.
    let expired_at = NOW + DEFAULT_APPROVAL_TTL_MS;
    let late = qk_approval::resolve(
        &qk_approval::ResolveRequest {
            evaluation: &evaluation,
            context: &context,
            dialect: qk_sql::SqlDialect::PostgreSql,
            sql: SQL,
            approval_id: Some(id.as_str()),
            ttl_ms: DEFAULT_APPROVAL_TTL_MS,
            now_ms: expired_at,
        },
        &mut store,
        Some(&PanickingProvider),
    );
    assert_eq!(late.decision, Decision::Deny);
    assert_eq!(late.reason_code, ReasonCode::ApprovalDenied);
}

#[test]
fn waiting_retry_stays_pending_without_reasking() {
    let (evaluation, context, _) = require_approval();
    let mut store = InMemoryApprovalStore::new();
    let provider = TestProvider::new(vec![ProviderDecision::Waiting]);
    let pending = resolve_with(
        &evaluation,
        &context,
        SQL,
        None,
        &mut store,
        Some(&provider),
    );
    let id = pending.approval_id.clone().expect("id");
    assert_eq!(provider.calls(), 1);
    let again = resolve_with(
        &evaluation,
        &context,
        SQL,
        Some(id.as_str()),
        &mut store,
        Some(&provider),
    );
    assert_eq!(again.decision, Decision::RequireApproval);
    assert_eq!(
        again.approval_id.as_ref().map(|id| id.as_str()),
        Some(id.as_str())
    );
    assert_eq!(
        provider.calls(),
        1,
        "waiting retry must not create a new request"
    );
}

#[test]
fn dialect_change_breaks_exact_binding() {
    // Same SQL bytes under another dialect: different exact digest, so the
    // token cannot be reused — even though the shape fingerprint (which
    // ignores dialect, frozen behavior) is identical.
    let (evaluation, context, _) = require_approval();
    let mut store = InMemoryApprovalStore::new();
    let provider = TestProvider::new(vec![ProviderDecision::Approved]);
    let first = resolve_with(
        &evaluation,
        &context,
        SQL,
        None,
        &mut store,
        Some(&provider),
    );
    let id = first.approval_id.clone().expect("id");
    // Shape identity takes no dialect (frozen); exact identity does.
    let mysql_eval = evaluate(
        &EvaluationRequest {
            context: &context,
            dialect: qk_sql::SqlDialect::MySql,
            sql: SQL,
            policy: &policy(),
        },
        &EvaluateOptions::default(),
    );
    assert_eq!(mysql_eval.decision, Decision::RequireApproval);
    let fresh = TestProvider::new(vec![ProviderDecision::Waiting]);
    let out = qk_approval::resolve(
        &qk_approval::ResolveRequest {
            evaluation: &mysql_eval,
            context: &context,
            dialect: qk_sql::SqlDialect::MySql,
            sql: SQL,
            approval_id: Some(id.as_str()),
            ttl_ms: DEFAULT_APPROVAL_TTL_MS,
            now_ms: NOW,
        },
        &mut store,
        Some(&fresh),
    );
    assert_eq!(out.outcome, ResolutionOutcome::ProviderWaiting);
    assert_eq!(fresh.calls(), 1, "dialect change mints a fresh request");
}

#[test]
fn id_generator_injectable() {
    let gen = CountingIdGenerator::new("qka_test");
    assert_eq!(gen.generate(), "qka_test-1");
    assert_eq!(gen.generate(), "qka_test-2");
}
