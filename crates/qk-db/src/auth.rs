//! Guarded authorization plane: evaluate + approval resolution with
//! ZERO database contact, issuing an opaque [`ExecutionPermit`] for
//! exactly one concrete executable request.
//!
//! Direct execution (`execute_guarded`) and session-pinned protocol
//! adapters (currently the PostgreSQL Simple Query proxy) share this code:
//! they authorize first; execution/forwarding then requires that permit.
//! policy/approval implementation.

use qk_approval::{ApprovalId, ApprovalScope, ResolveRequest};
use qk_core::{
    evaluate, Decision, EvaluateOptions, EvaluationRequest, ExactDigest, ExecutionContext,
    PolicyFile, QueryShapeFingerprint, ReasonCode,
};
use qk_sql::SqlDialect;

use crate::budget::MAX_PARAMS;
use crate::config::DbConfig;
use crate::cursor::CursorStore;
use crate::error::{DbError, DbErrorKind};
use crate::service::{ApprovalSetup, BlockedReason, PendingApproval, TrustedContext};

/// Authorization-only call surface: everything EXCEPT the adapter.
/// The absence of any adapter handle is structural proof that
/// authorization cannot contact the database.
pub struct GuardedAuthorizationCall<'a, 'b> {
    /// Trusted connection configuration (dialect source).
    pub config: &'a DbConfig,
    /// Password-stripped connection key (cursor binding).
    pub connection_key: &'a str,
    /// Trusted policy context.
    pub auth: &'a TrustedContext,
    /// Approval store + provider plumbing. Required in
    /// `ResolveApprovals` mode; unused in `EvaluateOnly` (no provider
    /// contact, so explain can authorize without approval wiring).
    pub approval: Option<&'a ApprovalSetup<'b>>,
    /// Validated policy file.
    pub policy: &'a PolicyFile,
}

/// Authorization input: the executable request under review. Row caps
/// and cursor IDs ride along because they materially shape the
/// executed statement (LIMIT/OFFSET); result formatting never enters
/// authorization identity.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    /// SQL under authorization.
    pub sql: String,
    /// Protocol-neutral ordered execution identity parameters.
    pub params: Vec<qk_core::ExecutionParam>,
    /// Original JSON driver values retained only for qk-db execution.
    pub(crate) driver_params: Vec<serde_json::Value>,
    /// Statement kinds this adapter refuses independently of policy (for
    /// example, protocol operations it cannot safely execute).
    pub reject_operations: Vec<qk_sql::Operation>,
    /// Refuse parse/unknown fallback outcomes even if policy requests approval.
    pub require_supported_analysis: bool,
    /// Retry with a previously issued approval id.
    pub approval_id: Option<String>,
    /// Requested row cap.
    pub max_rows: Option<usize>,
    /// Continuation cursor.
    pub cursor: Option<String>,
}
impl AuthorizationRequest {
    /// Build an authorization-only request from protocol-neutral values.
    /// The caller retains its original executable message for forwarding.
    pub fn new(sql: impl Into<String>, params: Vec<qk_core::ExecutionParam>) -> Self {
        Self {
            sql: sql.into(),
            params,
            driver_params: Vec::new(),
            reject_operations: Vec::new(),
            require_supported_analysis: false,
            approval_id: None,
            max_rows: None,
            cursor: None,
        }
    }

    pub(crate) fn from_json(
        sql: String,
        params: Vec<serde_json::Value>,
        approval_id: Option<String>,
        max_rows: Option<usize>,
        cursor: Option<String>,
    ) -> Result<Self, DbError> {
        validate_json_param_size(&params)?;
        Ok(Self {
            params: execution_identity_params(&params),
            sql,
            driver_params: params,
            reject_operations: Vec::new(),
            require_supported_analysis: false,
            approval_id,
            max_rows,
            cursor,
        })
    }
}

fn validate_json_param_size(params: &[serde_json::Value]) -> Result<(), DbError> {
    use qk_core::{MAX_EXECUTION_PARAMS, MAX_EXECUTION_PARAM_BYTES};
    if params.len() > MAX_EXECUTION_PARAMS {
        return Err(DbError::new(
            DbErrorKind::Query,
            format!("too many query parameters (max {MAX_PARAMS})"),
        ));
    }
    let mut total = 0usize;
    for param in params {
        let size = match param {
            serde_json::Value::String(value) => value.len(),
            serde_json::Value::Null | serde_json::Value::Bool(_) => 0,
            serde_json::Value::Number(value)
                if value.as_i64().is_some()
                    || value.as_u64().is_some()
                    || value.as_f64().is_some() =>
            {
                8
            }
            value => {
                let remaining = MAX_EXECUTION_PARAM_BYTES.saturating_sub(total);
                let mut writer = LimitedCounter {
                    written: 0,
                    limit: remaining,
                };
                if serde_json::to_writer(&mut writer, value).is_err() {
                    return Err(parameter_bytes_error());
                }
                writer.written
            }
        };
        total = total.saturating_add(size);
        if total > MAX_EXECUTION_PARAM_BYTES {
            return Err(parameter_bytes_error());
        }
    }
    Ok(())
}

fn parameter_bytes_error() -> DbError {
    DbError::new(
        DbErrorKind::Query,
        "query parameter identity exceeds the 1 MiB limit",
    )
}

struct LimitedCounter {
    written: usize,
    limit: usize,
}

impl std::io::Write for LimitedCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.written.saturating_add(bytes.len()) > self.limit {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Whether authorization may resolve approvals (contact providers).
/// `explain_guarded` authorizes evaluate-only: approval-gated SQL
/// pends without provider contact or row creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveMode {
    /// Full flow: evaluate + approval resolution.
    ResolveApprovals,
    /// Evaluate only: Allow → permit, RequireApproval → pending,
    /// Deny → blocked. No provider contact, no rows created.
    EvaluateOnly,
}

/// Authorization verdict: a permit, a refusal, a pending approval,
/// or an input fault. `Permitted` is the ONLY executable state;
/// everything else must never reach an adapter. `Failed` covers
/// cursor/param faults that prevent evaluation (fail-closed, never a
/// policy decision) — preserved from the pre-refactor behavior.
pub enum AuthorizationOutcome {
    /// This exact current request passed authorization (boxed: a
    /// move-only capability that dwarfs the other verdicts).
    Permitted(Box<ExecutionPermit>),
    /// Refused without database contact.
    Blocked(BlockedReason),
    /// Waiting on a human; retry out-of-band.
    PendingApproval(PendingApproval),
    /// Malformed authorization input (unknown cursor, param overflow).
    Failed(DbError),
}

/// Opaque execution capability for exactly one concrete request.
/// Process-local authority: no public constructor, no `Clone`, no
/// `Default`, no serde impls — only [`authorize_guarded`] mints it,
/// and execution consumes it by move. The accessors below expose only
/// read-only identity metadata (never the bound SQL or params), which
/// is what a protocol adapter legitimately needs to check a retry or
/// an existing grant; construction stays impossible from outside.
pub struct ExecutionPermit {
    pub(crate) dialect: SqlDialect,
    pub(crate) shape: QueryShapeFingerprint,
    pub(crate) exact: ExactDigest,
    pub(crate) scope: ApprovalScope,
    pub(crate) reason_code: ReasonCode,
    pub(crate) matched_policy: Option<String>,
    pub(crate) approval_id: Option<ApprovalId>,
    pub(crate) sql: String,
    pub(crate) params: Vec<serde_json::Value>,
    pub(crate) offset: u64,
    pub(crate) max_rows: Option<usize>,
    pub(crate) connection_key: String,
    pub(crate) operations: String,
}

impl ExecutionPermit {
    /// Trusted dialect of the authorized statement.
    pub fn dialect(&self) -> SqlDialect {
        self.dialect
    }

    /// Structural fingerprint (statement shape) the permit covers.
    pub fn shape(&self) -> &QueryShapeFingerprint {
        &self.shape
    }

    /// Exact request identity (V1/V2-tagged) the permit covers.
    pub fn exact(&self) -> &ExactDigest {
        &self.exact
    }

    /// Full trusted scope the permit is bound to.
    pub fn scope(&self) -> &ApprovalScope {
        &self.scope
    }

    /// Policy reason code that produced this permit.
    pub fn reason_code(&self) -> &ReasonCode {
        &self.reason_code
    }

    /// Matched policy id, when a policy rule was responsible.
    pub fn matched_policy(&self) -> Option<&str> {
        self.matched_policy.as_deref()
    }

    /// Approval that carried this permit, when one was used.
    pub fn approval_id(&self) -> Option<&ApprovalId> {
        self.approval_id.as_ref()
    }
    /// Whether the authorized request contains this evaluator-classified
    /// top-level statement operation.
    pub fn includes_operation(&self, operation: &qk_sql::Operation) -> bool {
        self.operations
            .split(',')
            .any(|name| name == operation.name())
    }
}

/// Authorize one executable request with zero database contact.
/// Returns a permit for exactly one concrete request, a refusal, or
/// a pending approval. Pure policy/approval flow over trusted
/// inputs; cursor state is the only I/O (in-memory).
pub fn authorize_guarded(
    cursors: &CursorStore,
    call: &GuardedAuthorizationCall<'_, '_>,
    request: &AuthorizationRequest,
    mode: ResolveMode,
) -> AuthorizationOutcome {
    if let Err(error) = call.config.validate_supported_transport() {
        return AuthorizationOutcome::Blocked(BlockedReason {
            decision: Decision::Deny,
            code: ReasonCode::PolicyError.as_str().to_owned(),
            message: error.to_string(),
            matched_policy: None,
        });
    }
    // Cursor paging reuses stored SQL; the resolved text is what gets
    // evaluated (never trust the cursor blindly).
    let (sql, driver_params, identity_params, offset) =
        match resolve_cursor(cursors, request, call.connection_key) {
            Ok(resolved) => resolved,
            Err(error) => return AuthorizationOutcome::Failed(error),
        };
    if let Err(error) = qk_core::validate_execution_params(&identity_params) {
        let message = match error {
            qk_core::ExecutionIdentityError::TooManyParameters => {
                format!("too many query parameters (max {MAX_PARAMS})")
            }
            qk_core::ExecutionIdentityError::ParametersTooLarge => {
                "query parameter identity exceeds the 1 MiB limit".to_owned()
            }
        };
        return AuthorizationOutcome::Failed(DbError::new(DbErrorKind::Query, message));
    }
    let context = call.auth.execution_context();
    let evaluation = evaluate(
        &EvaluationRequest {
            context: &context,
            dialect: call.config.dialect(),
            sql: &sql,
            policy: call.policy,
        },
        &EvaluateOptions::default(),
    );
    if request.require_supported_analysis
        && matches!(
            evaluation.reason_code,
            qk_core::ReasonCode::DenyParseError | qk_core::ReasonCode::DenyUnknownStatement
        )
    {
        return AuthorizationOutcome::Blocked(BlockedReason {
            decision: Decision::Deny,
            code: "UNSUPPORTED_SQL_ANALYSIS".to_owned(),
            message: "SQL could not be fully analyzed for this adapter".to_owned(),
            matched_policy: None,
        });
    }
    if evaluation.decision != Decision::Deny
        && request
            .reject_operations
            .iter()
            .any(|operation| evaluation.includes_operation(operation))
    {
        return AuthorizationOutcome::Blocked(BlockedReason {
            decision: Decision::Deny,
            code: "UNSUPPORTED_OPERATION".to_owned(),
            message: "statement operation is not supported by this adapter".to_owned(),
            matched_policy: None,
        });
    }
    if evaluation.decision != Decision::Allow && evaluation.decision != Decision::RequireApproval {
        return AuthorizationOutcome::Blocked(BlockedReason {
            decision: Decision::Deny,
            code: evaluation.reason_code.as_str().to_owned(),
            message: evaluation.message.clone(),
            matched_policy: evaluation.matched_policy.clone(),
        });
    }
    if evaluation.decision == Decision::RequireApproval {
        if mode == ResolveMode::EvaluateOnly {
            return AuthorizationOutcome::PendingApproval(PendingApproval {
                approval_id: String::new(),
                reason_code: evaluation.reason_code.as_str().to_owned(),
                estimated_rows: None,
            });
        }
        match resolve_approval(
            call,
            &evaluation,
            &sql,
            &identity_params,
            request.approval_id.as_deref(),
        ) {
            Resolve::Executable(resolved) => {
                return permit_for(
                    call,
                    &sql,
                    &identity_params,
                    &driver_params,
                    offset,
                    request,
                    resolved.approval_id,
                    resolved.reason_code,
                    resolved.matched_policy,
                    evaluation.operation.as_deref().unwrap_or_default(),
                );
            }
            Resolve::Outcome(outcome) => return *outcome,
        }
    }
    // Direct allow: facts come from the evaluation itself.
    permit_for(
        call,
        &sql,
        &identity_params,
        &driver_params,
        offset,
        request,
        None,
        evaluation.reason_code,
        evaluation.matched_policy.clone(),
        evaluation.operation.as_deref().unwrap_or_default(),
    )
}

/// Mint the permit for an explicitly authorized request.
#[allow(clippy::too_many_arguments)]
fn permit_for(
    call: &GuardedAuthorizationCall<'_, '_>,
    sql: &str,
    identity_params: &[qk_core::ExecutionParam],
    driver_params: &[serde_json::Value],
    offset: u64,
    request: &AuthorizationRequest,
    approval_id: Option<qk_approval::ApprovalId>,
    reason_code: ReasonCode,
    matched_policy: Option<String>,
    operations: &str,
) -> AuthorizationOutcome {
    let exact = if identity_params.is_empty() {
        qk_core::ExactDigest::V1(qk_core::exact_request_digest(call.config.dialect(), sql))
    } else {
        match qk_core::exact_request_digest_v2(call.config.dialect(), sql, identity_params) {
            Ok(digest) => qk_core::ExactDigest::V2(digest),
            Err(_) => {
                return AuthorizationOutcome::Failed(DbError::new(
                    DbErrorKind::Query,
                    "query parameter identity exceeds supported limits",
                ))
            }
        }
    };
    AuthorizationOutcome::Permitted(Box::new(ExecutionPermit {
        dialect: call.config.dialect(),
        shape: qk_core::sql_fingerprint(sql),
        exact,
        scope: scope_of(&call.auth.execution_context()),
        reason_code,
        matched_policy,
        approval_id,
        sql: sql.to_owned(),
        params: driver_params.to_vec(),
        offset,
        max_rows: request.max_rows,
        connection_key: call.connection_key.to_owned(),
        operations: operations.to_owned(),
    }))
}

/// Convert existing qk-db JSON parameters into shared identity values.
/// The original JSON values remain the driver-binding source.
pub(crate) fn execution_identity_params(
    params: &[serde_json::Value],
) -> Vec<qk_core::ExecutionParam> {
    params.iter().map(param_to_digest).collect()
}

fn param_to_digest(value: &serde_json::Value) -> qk_core::ExecutionParam {
    use qk_core::ExecutionParam as P;
    match value {
        serde_json::Value::Null => P::Null,
        serde_json::Value::Bool(value) => P::Bool(*value),
        serde_json::Value::Number(value) => {
            if let Some(int) = value.as_i64() {
                P::Int(int)
            } else if let Some(uint) = value.as_u64() {
                P::UInt(uint)
            } else if let Some(float) = value.as_f64() {
                P::FloatBits(float.to_bits())
            } else {
                P::Text(value.to_string())
            }
        }
        serde_json::Value::String(text) => P::Text(text.clone()),
        other => P::Text(other.to_string()),
    }
}

fn scope_of(context: &ExecutionContext) -> ApprovalScope {
    ApprovalScope {
        session_id: context.session_id.clone(),
        integration: context.integration.clone(),
        environment: context.environment.clone(),
        database: context.database.clone().unwrap_or_default(),
        agent_id: context.agent_id.clone().unwrap_or_default(),
        tool: context.tool.clone().unwrap_or_default(),
    }
}

/// Resolve cursor-or-direct input into SQL, driver values, identity values,
/// and offset, mirroring the frozen `input.cursor && !sql` branch.
fn resolve_cursor(
    cursors: &CursorStore,
    request: &AuthorizationRequest,
    connection_key: &str,
) -> Result<
    (
        String,
        Vec<serde_json::Value>,
        Vec<qk_core::ExecutionParam>,
        u64,
    ),
    DbError,
> {
    if let Some(cursor_id) = request.cursor.as_deref() {
        if request.sql.trim().is_empty() {
            let stored = cursors.read(cursor_id, connection_key)?;
            let identities = execution_identity_params(&stored.params);
            return Ok((stored.sql, stored.params, identities, stored.offset));
        }
    }
    Ok((
        request.sql.clone(),
        request.driver_params.clone(),
        request.params.clone(),
        0,
    ))
}

/// Internal resolution verdict: executable (with facts) or a final
/// non-executable outcome.
enum Resolve {
    Executable(qk_approval::ResolvedEvaluation),
    Outcome(Box<AuthorizationOutcome>),
}

fn resolve_approval(
    call: &GuardedAuthorizationCall<'_, '_>,
    evaluation: &qk_core::EvaluationResult,
    sql: &str,
    params: &[qk_core::ExecutionParam],
    approval_id: Option<&str>,
) -> Resolve {
    let Some(setup) = call.approval else {
        return Resolve::Outcome(Box::new(AuthorizationOutcome::Failed(DbError::new(
            DbErrorKind::Query,
            "approval resolution requires approval plumbing",
        ))));
    };
    let context = call.auth.execution_context();
    let resolved = qk_approval::resolve(
        &ResolveRequest {
            evaluation,
            context: &context,
            dialect: call.config.dialect(),
            sql,
            params,
            approval_id,
            ttl_ms: setup.ttl_ms,
            now_ms: setup.now_ms,
        },
        setup.store,
        setup.provider,
    );
    use qk_approval::ResolutionOutcome;
    let blocked = || {
        AuthorizationOutcome::Blocked(BlockedReason {
            decision: Decision::Deny,
            code: resolved.reason_code.as_str().to_owned(),
            message: resolved.message.clone(),
            matched_policy: resolved.matched_policy.clone(),
        })
    };
    match resolved.outcome {
        ResolutionOutcome::ExistingGrant | ResolutionOutcome::ProviderApproved => {
            if resolved.decision == Decision::Allow {
                Resolve::Executable(resolved)
            } else {
                Resolve::Outcome(Box::new(blocked()))
            }
        }
        ResolutionOutcome::ProviderWaiting => Resolve::Outcome(Box::new(
            AuthorizationOutcome::PendingApproval(PendingApproval {
                approval_id: resolved
                    .approval_id
                    .map(|id| id.as_str().to_owned())
                    .unwrap_or_default(),
                reason_code: resolved.reason_code.as_str().to_owned(),
                estimated_rows: None,
            }),
        )),
        ResolutionOutcome::ProviderDenied
        | ResolutionOutcome::ProviderUnavailable
        | ResolutionOutcome::ProviderError
        | ResolutionOutcome::NotRequired => Resolve::Outcome(Box::new(blocked())),
    }
}

#[cfg(test)]
mod identity_tests {
    use super::{execution_identity_params, validate_json_param_size};
    use qk_core::{exact_request_digest_v2, ExecutionParam, MAX_EXECUTION_PARAM_BYTES};

    #[test]
    fn json_parameter_identity_preserves_old_logical_v2_bytes() {
        let params = execution_identity_params(&[serde_json::json!(42)]);
        assert_eq!(params, [ExecutionParam::Int(42)]);
        assert_eq!(
            exact_request_digest_v2(
                qk_sql::SqlDialect::PostgreSql,
                "DELETE FROM customers WHERE id = ?",
                &params,
            )
            .expect("bounded"),
            qk_core::ExactRequestDigestV2::from_bytes([
                0xd6, 0x4c, 0xe1, 0xe2, 0x4d, 0x23, 0xea, 0xce, 0x00, 0x75, 0x08, 0xbe, 0x10, 0x9f,
                0x22, 0xb3, 0x99, 0x72, 0xd9, 0x06, 0xeb, 0x6e, 0xe9, 0x80, 0xfc, 0x36, 0xfa, 0xc0,
                0x51, 0x7e, 0x27, 0x9b,
            ])
        );
    }

    #[test]
    fn json_input_budget_rejects_before_identity_copy() {
        let secret = "x".repeat(MAX_EXECUTION_PARAM_BYTES + 1);
        let error = validate_json_param_size(&[serde_json::Value::String(secret)]).unwrap_err();
        assert_eq!(
            error.message(),
            "query parameter identity exceeds the 1 MiB limit"
        );
    }
}
