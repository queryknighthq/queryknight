use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::auth::{
    CallerKind, RequestBudget, RequestCancellationGuard, VerifiedExtensionClaims,
    DESCRIBE_ALLOWED_CALLERS, EVALUATE_HTTP_REQUEST_ALLOWED_CALLERS,
    EVALUATE_WEB_SOCKET_SESSION_ALLOWED_CALLERS, VALIDATE_CONFIG_ALLOWED_CALLERS,
};
use async_stream::try_stream;
use prost::Message;
use qk_approval::{InMemoryApprovalStore, DEFAULT_APPROVAL_TTL_MS};
use qk_control_plane::{ControlPlaneClient, DaemonApprovalProvider};
use qk_core::{parse_policy, PolicyFile};
use qk_db::{
    authorize_guarded, ApprovalSetup, AuthorizationOutcome, AuthorizationRequest, BlockedReason,
    CursorStore, DbConfig, GuardedAuthorizationCall, ResolveMode, TrustedContext,
};
use tonic::{Request, Response, Status};

use crate::extension_proto;
use crate::extract::{extract_candidates, Candidate, ExtractError};
use crate::proto::supervisor_middleware_server::SupervisorMiddleware;
use crate::proto::{
    web_socket_message, web_socket_session_event, web_socket_session_event_result, Decision,
    HttpRequestEvaluation, HttpRequestResult, MiddlewareBinding, MiddlewareDescribeRequest,
    MiddlewareManifest, RequestContext, SupervisorMiddlewareOperation, SupervisorMiddlewarePhase,
    ValidateConfigRequest, ValidateConfigResponse, WebSocketMessageResult,
    WebSocketPreflightAction, WebSocketPreflightDecision, WebSocketSessionEvent,
    WebSocketSessionEventResult,
};
use crate::MAX_PAYLOAD_BYTES;

const MAX_CONFIG_BYTES: usize = 64 * 1024;
const MAX_CONFIGS: usize = 64;
const MAX_MIDDLEWARE_NAME_BYTES: usize = 128;
const MAX_CONTEXT_BYTES: usize = 4 * 1024;
const MAX_TARGET_BYTES: usize = 32 * 1024;
const MAX_HEADER_COUNT: usize = 128;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_SQL_BYTES: usize = 200_000;
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_millis(400);
const MIN_REQUEST_TIMEOUT: Duration = Duration::from_millis(10);
const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_WEBSOCKET_PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(1);
const AUTHORIZATION_SAFETY_MARGIN: Duration = Duration::from_millis(25);
const EXTENSION_CONTRACT_CAPABILITY: &str = "openshell.supervisor-middleware.contract";

/// Trusted runtime inputs for one OpenShell authorization service.
///
/// `DbConfig` selects the SQL dialect and password-redacted approval identity;
/// it is never used to open a database connection.
pub struct OpenShellServiceConfig {
    db_config: DbConfig,
    control_plane: Option<ControlPlaneClient>,
    observer: qk_audit::Observer,
    sql_log_level: qk_audit::SqlLogLevel,
    expected_audience: Option<String>,
    request_timeout: Duration,
}

impl OpenShellServiceConfig {
    /// Build a service configuration from a trusted database URL.
    pub fn new(db_config: DbConfig) -> Self {
        Self {
            db_config,
            control_plane: None,
            observer: qk_audit::Observer::default(),
            sql_log_level: qk_audit::SqlLogLevel::Fingerprint,
            expected_audience: None,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }

    /// Require the exact audience used by the authenticated network listener.
    #[must_use]
    pub fn with_expected_audience(mut self, audience: impl Into<String>) -> Self {
        self.expected_audience = Some(audience.into());
        self
    }

    /// Bound unary requests and each WebSocket message operation. The same
    /// duration is advertised in the v0.1.2 binding manifest.
    #[must_use]
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }
    /// Use the shared QueryKnight daemon for approvals. If omitted, approval-required decisions fail closed as unavailable.
    #[must_use]
    pub fn with_control_plane(mut self, client: ControlPlaneClient) -> Self {
        self.control_plane = Some(client);
        self
    }

    /// Use a caller-owned canonical audit observer and metrics registry.
    #[must_use]
    pub fn with_observer(mut self, observer: qk_audit::Observer) -> Self {
        self.observer = observer;
        self
    }

    /// Set the canonical SQL audit level. The default is fingerprint-only.
    #[must_use]
    pub fn with_sql_log_level(mut self, level: qk_audit::SqlLogLevel) -> Self {
        self.sql_log_level = level;
        self
    }
}

struct ValidatedConfig {
    input: prost_types::Struct,
    policy: PolicyFile,
    database: String,
    environment: String,
    max_sql_bytes: usize,
}

struct ServiceState {
    db_config: DbConfig,
    connection_key: String,
    control_plane: Option<ControlPlaneClient>,
    observer: qk_audit::Observer,
    sql_log_level: qk_audit::SqlLogLevel,
    expected_audience: Option<String>,
    request_timeout: Duration,
    configs: RwLock<HashMap<String, Arc<ValidatedConfig>>>,
    cursors: CursorStore,
}

/// Shared OpenShell gRPC handler implementation.
#[derive(Clone)]
pub struct OpenShellService {
    state: Arc<ServiceState>,
}

impl OpenShellService {
    /// Create the RPC implementation. The connection key is derived only from
    /// the trusted, password-redacted database URL.
    pub fn new(config: OpenShellServiceConfig) -> Self {
        let connection_key = config.db_config.redacted_url();
        Self {
            state: Arc::new(ServiceState {
                db_config: config.db_config,
                connection_key,
                control_plane: config.control_plane,
                observer: config.observer,
                sql_log_level: config.sql_log_level,
                expected_audience: config.expected_audience,
                request_timeout: config.request_timeout,
                configs: RwLock::new(HashMap::new()),
                cursors: CursorStore::new(),
            }),
        }
    }
    /// Shared observer used for audit events and frozen metrics.
    #[must_use]
    pub fn observer(&self) -> &qk_audit::Observer {
        &self.state.observer
    }
    pub(crate) fn expected_audience(&self) -> Option<&str> {
        self.state.expected_audience.as_deref()
    }

    pub(crate) fn request_timeout(&self) -> Duration {
        self.state.request_timeout
    }

    pub(crate) fn validate_server_configuration(&self) -> Result<(), ()> {
        if !(MIN_REQUEST_TIMEOUT..=MAX_REQUEST_TIMEOUT).contains(&self.state.request_timeout)
            || self
                .state
                .expected_audience
                .as_deref()
                .is_some_and(|value| {
                    value.is_empty()
                        || value.len() > 512
                        || value.trim() != value
                        || value.chars().any(char::is_control)
                })
        {
            return Err(());
        }
        Ok(())
    }
    fn rpc_budget<T>(&self, request: &Request<T>, stream: bool) -> RequestBudget {
        request
            .extensions()
            .get::<RequestBudget>()
            .cloned()
            .unwrap_or_else(|| {
                RequestBudget::new(if stream {
                    None
                } else {
                    Instant::now().checked_add(self.state.request_timeout)
                })
            })
    }

    fn verify_rpc_caller<T>(
        &self,
        request: &Request<T>,
        expected_callers: &[CallerKind],
    ) -> Result<Option<VerifiedExtensionClaims>, Status> {
        if self.state.expected_audience.is_none() {
            return Ok(None);
        }
        let claims = request
            .extensions()
            .get::<VerifiedExtensionClaims>()
            .cloned()
            .ok_or_else(|| {
                Status::unauthenticated("OpenShell extension authentication is required")
            })?;
        if !expected_callers.contains(&claims.caller_kind()) {
            return Err(Status::permission_denied(
                "OpenShell caller is not permitted for this RPC",
            ));
        }
        Ok(Some(claims))
    }

    fn verified_sandbox_id(
        &self,
        claims: Option<&VerifiedExtensionClaims>,
        context: Option<&RequestContext>,
        rpc: &'static str,
    ) -> Result<Option<String>, Status> {
        if self.state.expected_audience.is_none() {
            return Ok(context
                .filter(|context| !context.sandbox_id.is_empty())
                .map(|context| context.sandbox_id.clone()));
        }
        let Some(context) = context else {
            log_auth_failure(rpc, "sandbox_context_missing");
            return Err(Status::invalid_argument(
                "OpenShell request context is required",
            ));
        };
        if context.encoded_len() > MAX_CONTEXT_BYTES {
            log_auth_failure(rpc, "sandbox_context_over_capacity");
            return Err(Status::invalid_argument(
                "OpenShell request context exceeds its limit",
            ));
        }
        let Some(claims) = claims else {
            log_auth_failure(rpc, "sandbox_claim_missing");
            return Err(Status::unauthenticated(
                "OpenShell supervisor identity is unavailable",
            ));
        };
        if claims.sandbox_id() != Some(context.sandbox_id.as_str()) {
            log_auth_failure(rpc, "sandbox_binding_mismatch");
            return Err(Status::permission_denied(
                "OpenShell token and request sandbox identities differ",
            ));
        }
        log_auth_success(rpc, CallerKind::Supervisor);
        Ok(claims.sandbox_id().map(str::to_owned))
    }

    fn validate_config_value(
        &self,
        name: &str,
        input: prost_types::Struct,
    ) -> Result<ValidatedConfig, &'static str> {
        if name.is_empty() || name.len() > MAX_MIDDLEWARE_NAME_BYTES {
            return Err("invalid_middleware_name");
        }
        if input.encoded_len() > MAX_CONFIG_BYTES {
            return Err("config_too_large");
        }
        let fields = &input.fields;
        for key in fields.keys() {
            if !matches!(
                key.as_str(),
                "policy_yaml"
                    | "dialect"
                    | "database"
                    | "environment"
                    | "approval_action"
                    | "maxSqlBytes"
            ) {
                return Err("unknown_config_field");
            }
        }
        let policy_yaml = optional_string(fields.get("policy_yaml"), "policy_yaml_must_be_string")?
            .filter(|value| !value.trim().is_empty())
            .ok_or("policy_yaml_required")?;
        let policy = parse_policy(policy_yaml).map_err(|_| "invalid_policy")?;
        let dialect =
            optional_string(fields.get("dialect"), "dialect_must_be_string")?.unwrap_or("postgres");
        let parsed_dialect = dialect
            .parse::<qk_sql::SqlDialect>()
            .map_err(|_| "invalid_dialect")?;
        if parsed_dialect != self.state.db_config.dialect() {
            return Err("dialect_mismatch");
        }
        let database =
            optional_string(fields.get("database"), "database_must_be_string")?.unwrap_or("main");
        if database.is_empty() || database.len() > 128 {
            return Err("invalid_database");
        }
        let database = database.to_owned();
        let environment = optional_string(fields.get("environment"), "environment_must_be_string")?
            .unwrap_or("production");
        if !matches!(
            environment,
            "development" | "staging" | "production" | "unknown"
        ) {
            return Err("invalid_environment");
        }
        let environment = environment.to_owned();
        if let Some(action) = optional_string(
            fields.get("approval_action"),
            "approval_action_must_be_string",
        )? {
            match action {
                "deny" => {}
                "allow_with_findings" => return Err("unsafe_approval_action"),
                _ => return Err("invalid_approval_action"),
            }
        }
        let max_sql_bytes = match fields.get("maxSqlBytes") {
            None => MAX_SQL_BYTES,
            Some(value) => {
                let Some(bytes) = value_number(value) else {
                    return Err("max_sql_bytes_must_be_number");
                };
                if !bytes.is_finite()
                    || bytes < 1.0
                    || bytes > MAX_SQL_BYTES as f64
                    || bytes.fract() != 0.0
                {
                    return Err("invalid_max_sql_bytes");
                }
                bytes as usize
            }
        };

        Ok(ValidatedConfig {
            input,
            policy,
            database,
            environment,
            max_sql_bytes,
        })
    }

    fn store_validated(
        &self,
        name: &str,
        validated: ValidatedConfig,
        budget: &RequestBudget,
    ) -> Result<(), &'static str> {
        let mut configs = self
            .state
            .configs
            .write()
            .map_err(|_| "config_registry_unavailable")?;
        if !configs.contains_key(name) && configs.len() >= MAX_CONFIGS {
            return Err("config_registry_full");
        }
        if budget.is_cancelled() {
            return Err("request_deadline_exceeded");
        }
        configs.insert(name.to_owned(), Arc::new(validated));
        Ok(())
    }
    fn validated_config(
        &self,
        name: &str,
        input: Option<&prost_types::Struct>,
    ) -> Result<Arc<ValidatedConfig>, &'static str> {
        if name.is_empty() || name.len() > MAX_MIDDLEWARE_NAME_BYTES {
            return Err("invalid_middleware_name");
        }
        let input = input.ok_or("config_required")?;
        if input.encoded_len() > MAX_CONFIG_BYTES {
            return Err("config_too_large");
        }
        let config = self
            .state
            .configs
            .read()
            .map_err(|_| "config_registry_unavailable")?
            .get(name)
            .cloned()
            .ok_or("config_not_validated")?;
        if config.input != *input {
            return Err("config_changed_after_validation");
        }
        Ok(config)
    }

    async fn evaluate_candidates(
        &self,
        config: Arc<ValidatedConfig>,
        request_id: Option<String>,
        sandbox_id: Option<String>,
        candidates: Vec<Candidate>,
        budget: RequestBudget,
    ) -> Result<GateResult, Status> {
        if budget.is_cancelled() {
            return Err(deadline_exceeded());
        }
        if candidates.is_empty() {
            return Ok(GateResult::allow());
        }
        if budget
            .remaining()
            .is_some_and(|remaining| remaining <= Duration::from_millis(10))
        {
            return Err(deadline_exceeded());
        }
        let deadline = budget.deadline().ok_or_else(deadline_exceeded)?;
        let approval_deadline = deadline
            .checked_sub(AUTHORIZATION_SAFETY_MARGIN)
            .filter(|value| *value > Instant::now())
            .ok_or_else(deadline_exceeded)?;
        let cancellation = budget.cancelled();
        let task_budget = budget.clone();
        let state = Arc::clone(&self.state);
        match tokio::task::spawn_blocking(move || {
            let mut final_result = GateResult::allow();
            for candidate in candidates {
                if task_budget.is_cancelled() {
                    return Err(deadline_exceeded());
                }
                let started = Instant::now();
                let safety_failure = if candidate.sql.len() > config.max_sql_bytes {
                    Some((qk_core::ReasonCode::QueryTooLarge, "query_too_large"))
                } else if candidate.params.is_empty() && !candidate.sql.trim().is_empty() {
                    match qk_sql::analyze::has_parameter_markers(
                        &candidate.sql,
                        state.db_config.dialect(),
                        qk_sql::analyze::AnalyzeOptions {
                            max_bytes: config.max_sql_bytes,
                        },
                    ) {
                        Ok(true) => Some((qk_core::ReasonCode::PolicyError, "unbound_parameters")),
                        Ok(false) => None,
                        Err(_) => Some((
                            qk_core::ReasonCode::DenyParseError,
                            "unsupported_sql_analysis",
                        )),
                    }
                } else {
                    None
                };

                let (outcome, sql, response_reason) = if let Some((reason, response_reason)) =
                    safety_failure
                {
                    (
                        blocked_authorization(reason),
                        candidate.sql,
                        Some(response_reason),
                    )
                } else {
                    let mut request = AuthorizationRequest::new(candidate.sql, candidate.params);
                    request.require_supported_analysis = true;
                    let auth = TrustedContext {
                        integration: "openshell".to_owned(),
                        environment: config.environment.clone(),
                        database: config.database.clone(),
                        tool: String::new(),
                        session_id: sandbox_id.clone(),
                    };
                    let provider = state.control_plane.as_ref().map(|client| {
                        DaemonApprovalProvider::new(
                            client.clone(),
                            sandbox_id.clone(),
                            state.connection_key.clone(),
                            None,
                        )
                        .with_exact_lookup_retry()
                        .with_request_budget(approval_deadline, Arc::clone(&cancellation))
                    });
                    // The daemon is the durable authority. A request-local store
                    // holds only the resolver's temporary verdict; keeping it
                    // across calls would collide on exact no-id retries.
                    let approval_store = InMemoryApprovalStore::new();
                    let approval = ApprovalSetup {
                        store: &approval_store,
                        provider: provider
                            .as_ref()
                            .map(|value| value as &dyn qk_approval::ApprovalProvider),
                        ttl_ms: DEFAULT_APPROVAL_TTL_MS,
                        now_ms: now_ms(),
                    };
                    let call = GuardedAuthorizationCall {
                        config: &state.db_config,
                        connection_key: &state.connection_key,
                        auth: &auth,
                        approval: Some(&approval),
                        policy: &config.policy,
                    };
                    let outcome = authorize_guarded(
                        &state.cursors,
                        &call,
                        &request,
                        ResolveMode::ResolveApprovals,
                    );
                    (outcome, request.sql, None)
                };
                if task_budget.is_cancelled() {
                    drop(outcome);
                    return Err(deadline_exceeded());
                }
                let approval_failed = matches!(
                    &outcome,
                    AuthorizationOutcome::Blocked(reason)
                        if reason.code == qk_core::ReasonCode::ApprovalError.as_str()
                            || reason.code == qk_core::ReasonCode::ApprovalUnavailable.as_str()
                );
                let gate = match &outcome {
                    AuthorizationOutcome::Permitted(_) => GateResult::allow(),
                    AuthorizationOutcome::Blocked(reason) => {
                        GateResult::deny(response_reason.unwrap_or(&reason.code))
                    }
                    AuthorizationOutcome::PendingApproval(pending) => {
                        GateResult::deny(response_reason.unwrap_or(&pending.reason_code))
                    }
                    AuthorizationOutcome::Failed(_) => {
                        GateResult::deny(response_reason.unwrap_or("policy_error"))
                    }
                };
                let duration_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                let observation = qk_audit::Observation::from_authorization_outcome(
                    qk_audit::new_event_id(),
                    now_ms(),
                    duration_ms,
                    Some(duration_ms),
                    request_id.clone(),
                    "openshell".to_owned(),
                    config.environment.clone(),
                    Some(config.database.clone()),
                    None,
                    sandbox_id.clone(),
                    None,
                    None,
                    state.db_config.dialect(),
                    sql,
                    &outcome,
                );
                // Drop any process-local permit before calling user-owned sinks.
                drop(outcome);
                for failure in state.observer.observe(&observation, state.sql_log_level) {
                    let _ = std::io::Write::write_fmt(
                        &mut std::io::stderr().lock(),
                        format_args!("audit sink failed: {failure}\n"),
                    );
                }
                if task_budget.is_cancelled() {
                    return Err(deadline_exceeded());
                }
                if approval_failed {
                    return Err(Status::unavailable("OpenShell approval resolution failed"));
                }
                if gate.decision == Decision::Deny {
                    return Ok(gate);
                }
                final_result = gate;
            }
            if task_budget.is_cancelled() {
                Err(deadline_exceeded())
            } else {
                Ok(final_result)
            }
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err(Status::internal("OpenShell authorization task failed")),
        }
    }

    async fn evaluate_body(
        &self,
        config: Arc<ValidatedConfig>,
        context: Option<&RequestContext>,
        trusted_sandbox_id: Option<String>,
        body: Vec<u8>,
        max_payload_bytes: usize,
        budget: RequestBudget,
    ) -> Result<GateResult, Status> {
        if body.len() > max_payload_bytes.min(MAX_PAYLOAD_BYTES) {
            return Ok(GateResult::deny("payload_too_large"));
        }
        if budget.is_cancelled()
            || budget
                .remaining()
                .is_some_and(|remaining| remaining <= Duration::from_millis(10))
        {
            return Err(deadline_exceeded());
        }
        let request_id = context
            .filter(|context| !context.request_id.is_empty())
            .map(|context| context.request_id.clone());
        let parse_budget = budget.clone();
        let parsed = tokio::task::spawn_blocking(move || {
            if parse_budget.is_cancelled() {
                return Err(deadline_exceeded());
            }
            let candidates = match std::str::from_utf8(&body) {
                Ok(text) => extract_candidates(text).map_err(extract_error_code),
                Err(_) => Err("invalid_utf8"),
            };
            Ok(candidates)
        })
        .await
        .map_err(|_| Status::internal("OpenShell request parsing task failed"))?;
        if budget.is_cancelled() {
            return Err(deadline_exceeded());
        }
        let candidates = match parsed {
            Err(status) => return Err(status),
            Ok(Err(reason)) => return Ok(GateResult::deny(reason)),
            Ok(Ok(candidates)) => candidates,
        };
        self.evaluate_candidates(config, request_id, trusted_sandbox_id, candidates, budget)
            .await
    }
}

#[tonic::async_trait]
impl SupervisorMiddleware for OpenShellService {
    async fn describe(
        &self,
        request: Request<MiddlewareDescribeRequest>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        let _caller = self.verify_rpc_caller(&request, DESCRIBE_ALLOWED_CALLERS)?;
        if let Some(caller) = &_caller {
            log_auth_success("Describe", caller.caller_kind());
        }
        let budget = self
            .rpc_budget(&request, false)
            .operation(self.state.request_timeout);
        let _cancellation = RequestCancellationGuard::new(budget.clone());
        ensure_budget(&budget)?;
        validate_gateway_metadata(request.get_ref().gateway.as_ref())?;
        ensure_budget(&budget)?;
        let binding = |operation, phase| MiddlewareBinding {
            operation: operation as i32,
            phase: phase as i32,
            max_payload_bytes: MAX_PAYLOAD_BYTES as u64,
            request_timeout: Some(proto_duration(self.state.request_timeout)),
        };
        Ok(Response::new(MiddlewareManifest {
            name: "queryknight".to_owned(),
            service_version: env!("CARGO_PKG_VERSION").to_owned(),
            bindings: vec![
                binding(
                    SupervisorMiddlewareOperation::HttpRequest,
                    SupervisorMiddlewarePhase::PreCredentials,
                ),
                binding(
                    SupervisorMiddlewareOperation::WebsocketMessage,
                    SupervisorMiddlewarePhase::PreCredentials,
                ),
            ],
            expected_audience: self.state.expected_audience.clone().unwrap_or_default(),
            extension: Some(extension_proto::PeerMetadata {
                protocol_version: Some(extension_proto::ProtocolVersion { major: 1, minor: 0 }),
                implementation_name: "queryknight".to_owned(),
                implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
                supported_capabilities: vec![EXTENSION_CONTRACT_CAPABILITY.to_owned()],
                required_capabilities: vec![EXTENSION_CONTRACT_CAPABILITY.to_owned()],
            }),
        }))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        let _caller = self.verify_rpc_caller(&request, VALIDATE_CONFIG_ALLOWED_CALLERS)?;
        if let Some(caller) = &_caller {
            log_auth_success("ValidateConfig", caller.caller_kind());
        }
        let budget = self
            .rpc_budget(&request, false)
            .operation(self.state.request_timeout);
        let _cancellation = RequestCancellationGuard::new(budget.clone());
        ensure_budget(&budget)?;
        let request = request.into_inner();
        let (valid, reason) = match request.config {
            Some(input) => {
                let name = request.middleware_name;
                let parse_name = name.clone();
                let parse_service = self.clone();
                let validated = tokio::task::spawn_blocking(move || {
                    parse_service.validate_config_value(&parse_name, input)
                })
                .await
                .map_err(|_| Status::internal("OpenShell config validation task failed"))?;
                ensure_budget(&budget)?;
                match validated {
                    Ok(validated) => match self.store_validated(&name, validated, &budget) {
                        Ok(()) => (true, ""),
                        Err("request_deadline_exceeded") => return Err(deadline_exceeded()),
                        Err(reason) => (false, config_validation_reason(reason)),
                    },
                    Err(reason) => (false, config_validation_reason(reason)),
                }
            }
            None => (false, "invalid_or_unsupported_queryknight_configuration"),
        };
        ensure_budget(&budget)?;
        Ok(Response::new(ValidateConfigResponse {
            valid,
            reason: reason.to_owned(),
        }))
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        let caller = self.verify_rpc_caller(&request, EVALUATE_HTTP_REQUEST_ALLOWED_CALLERS)?;
        let budget = self
            .rpc_budget(&request, false)
            .operation(self.state.request_timeout);
        let _cancellation = RequestCancellationGuard::new(budget.clone());
        ensure_budget(&budget)?;
        let trusted_sandbox_id = self.verified_sandbox_id(
            caller.as_ref(),
            request.get_ref().context.as_ref(),
            "EvaluateHttpRequest",
        )?;
        let request = request.into_inner();
        let config = self.validated_config(&request.middleware_name, request.config.as_ref());
        let result = match config {
            Err(reason) => GateResult::deny(reason),
            Ok(config) => {
                let phase = SupervisorMiddlewarePhase::try_from(request.phase).ok();
                if phase != Some(SupervisorMiddlewarePhase::PreCredentials) {
                    GateResult::deny("unsupported_phase")
                } else if request
                    .context
                    .as_ref()
                    .is_none_or(|context| context.encoded_len() > MAX_CONTEXT_BYTES)
                {
                    GateResult::deny("invalid_request_context")
                } else if request
                    .target
                    .as_ref()
                    .is_none_or(|target| target.encoded_len() > MAX_TARGET_BYTES)
                {
                    GateResult::deny("invalid_request_target")
                } else if request.headers.len() > MAX_HEADER_COUNT
                    || request
                        .headers
                        .iter()
                        .map(|header| header.encoded_len())
                        .sum::<usize>()
                        > MAX_HEADER_BYTES
                {
                    GateResult::deny("headers_too_large")
                } else {
                    self.evaluate_body(
                        config,
                        request.context.as_ref(),
                        trusted_sandbox_id,
                        request.body,
                        MAX_PAYLOAD_BYTES,
                        budget.clone(),
                    )
                    .await?
                }
            }
        };
        ensure_budget(&budget)?;
        log_authorization_result("http_request", &result);
        Ok(Response::new(HttpRequestResult {
            decision: result.decision as i32,
            reason: String::new(),
            body: Vec::new(),
            has_body: false,
            header_mutations: Vec::new(),
            findings: Vec::new(),
            metadata: HashMap::new(),
            reason_code: result.reason_code,
        }))
    }

    type EvaluateWebSocketSessionStream = std::pin::Pin<
        Box<
            dyn futures_core::Stream<Item = Result<WebSocketSessionEventResult, Status>>
                + Send
                + 'static,
        >,
    >;

    async fn evaluate_web_socket_session(
        &self,
        request: Request<tonic::Streaming<WebSocketSessionEvent>>,
    ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        let caller =
            self.verify_rpc_caller(&request, EVALUATE_WEB_SOCKET_SESSION_ALLOWED_CALLERS)?;
        let stream_budget = self.rpc_budget(&request, true);
        let mut inbound = request.into_inner();
        let service = self.clone();
        let request_timeout = self.state.request_timeout;
        let output = try_stream! {
            let _cancellation = RequestCancellationGuard::new(stream_budget.clone());
            let first = inbound
                .message()
                .await?
                .ok_or_else(|| Status::invalid_argument("WebSocket stream must start with preflight"))?;
            let Some(web_socket_session_event::Event::Preflight(preflight)) = first.event else {
                Err(Status::invalid_argument("WebSocket stream must start with preflight"))?
            };
            let trusted_sandbox_id =
                service.verified_sandbox_id(
                    caller.as_ref(),
                    preflight.context.as_ref(),
                    "EvaluateWebSocketSession",
                )?;
            let preflight_budget = stream_budget
                .operation(request_timeout.min(MAX_WEBSOCKET_PREFLIGHT_TIMEOUT));
            ensure_budget(&preflight_budget)?;
            let validated = service.validated_config(
                &preflight.middleware_name,
                preflight.config.as_ref(),
            );
            let (validated, failure) = match validated {
                Err(reason) => (None, Some(reason)),
                Ok(config) => {
                    let phase_ok = SupervisorMiddlewarePhase::try_from(preflight.phase).ok()
                        == Some(SupervisorMiddlewarePhase::PreCredentials);
                    let target_ok = preflight.target.as_ref().is_some_and(|target| {
                        target.encoded_len() <= MAX_TARGET_BYTES
                    });
                    let failure = if !phase_ok {
                        Some("unsupported_phase")
                    } else if preflight
                        .context
                        .as_ref()
                        .is_none_or(|context| context.encoded_len() > MAX_CONTEXT_BYTES)
                    {
                        Some("invalid_request_context")
                    } else if !target_ok {
                        Some("invalid_request_target")
                    } else {
                        None
                    };
                    (failure.is_none().then_some(config), failure)
                }
            };
            ensure_budget(&preflight_budget)?;
            let action = if validated.is_some() {
                WebSocketPreflightAction::Inspect
            } else {
                WebSocketPreflightAction::Deny
            };
            yield WebSocketSessionEventResult {
                result: Some(web_socket_session_event_result::Result::PreflightDecision(
                    WebSocketPreflightDecision {
                        action: action as i32,
                        reason: String::new(),
                        reason_code: failure.map_or_else(String::new, reason_code),
                        findings: Vec::new(),
                        metadata: HashMap::new(),
                    },
                )),
            };
            let Some(validated) = validated else {
                return;
            };
            let mut session_started = false;
            let mut previous_sequence = 0u64;
            while let Some(event) = inbound.message().await? {
                match event.event {
                    Some(web_socket_session_event::Event::SessionStart(_)) => {
                        if session_started {
                            Err(Status::invalid_argument(
                                "WebSocket session_start may occur only once",
                            ))?;
                        }
                        session_started = true;
                    }
                    Some(web_socket_session_event::Event::Message(message)) => {
                        if !session_started {
                            Err(Status::invalid_argument(
                                "WebSocket messages require session_start",
                            ))?;
                        }
                        if message.sequence == 0 || message.sequence <= previous_sequence {
                            Err(Status::invalid_argument(
                                "WebSocket message sequence must increase",
                            ))?;
                        }
                        previous_sequence = message.sequence;
                        let budget = stream_budget.operation(request_timeout);
                        ensure_budget(&budget)?;
                        let gate = match message.payload {
                            Some(web_socket_message::Payload::Text(text)) => {
                                if text.len() > MAX_PAYLOAD_BYTES {
                                    GateResult::deny("payload_too_large")
                                } else {
                                    service
                                        .evaluate_body(
                                            Arc::clone(&validated),
                                            preflight.context.as_ref(),
                                            trusted_sandbox_id.clone(),
                                            text.into_bytes(),
                                            MAX_PAYLOAD_BYTES,
                                            budget.clone(),
                                        )
                                        .await?
                                }
                            }
                            Some(web_socket_message::Payload::Binary(_)) | None => {
                                GateResult::deny("unsupported_websocket_payload")
                            }
                        };
                        ensure_budget(&budget)?;
                        log_authorization_result("websocket_message", &gate);
                        yield WebSocketSessionEventResult {
                            result: Some(
                                web_socket_session_event_result::Result::MessageResult(
                                    WebSocketMessageResult {
                                        sequence: message.sequence,
                                        decision: gate.decision as i32,
                                        replacement: None,
                                        reason: String::new(),
                                        reason_code: gate.reason_code,
                                        findings: Vec::new(),
                                        metadata: HashMap::new(),
                                    },
                                ),
                            ),
                        };
                    }
                    Some(web_socket_session_event::Event::SessionEnd(_)) => return,
                    Some(web_socket_session_event::Event::Preflight(_)) | None => {
                        Err(Status::invalid_argument("unexpected WebSocket session event"))?;
                    }
                }
            }
        };
        Ok(Response::new(Box::pin(output)))
    }
}

fn validate_gateway_metadata(
    gateway: Option<&extension_proto::PeerMetadata>,
) -> Result<(), Status> {
    let gateway = gateway
        .ok_or_else(|| Status::failed_precondition("OpenShell peer metadata is required"))?;
    let version = gateway
        .protocol_version
        .as_ref()
        .ok_or_else(|| Status::failed_precondition("OpenShell protocol version is required"))?;
    if version.major != 1 {
        return Err(Status::failed_precondition(
            "unsupported OpenShell protocol major version",
        ));
    }
    if !valid_peer_text(&gateway.implementation_name)
        || !valid_peer_text(&gateway.implementation_version)
    {
        return Err(Status::failed_precondition(
            "OpenShell implementation metadata is invalid",
        ));
    }
    let supported = peer_capabilities(&gateway.supported_capabilities)?;
    let required = peer_capabilities(&gateway.required_capabilities)?;
    if required
        .iter()
        .any(|capability| capability != EXTENSION_CONTRACT_CAPABILITY)
    {
        return Err(Status::failed_precondition(
            "required OpenShell capability is unsupported",
        ));
    }
    if !supported.contains(EXTENSION_CONTRACT_CAPABILITY) {
        return Err(Status::failed_precondition(
            "OpenShell is missing the middleware contract capability",
        ));
    }
    Ok(())
}

fn valid_peer_text(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

fn peer_capabilities(capabilities: &[String]) -> Result<HashSet<String>, Status> {
    if capabilities.len() > 128 {
        return Err(Status::failed_precondition(
            "OpenShell capability metadata exceeds its limit",
        ));
    }
    let mut normalized = HashSet::with_capacity(capabilities.len());
    for capability in capabilities {
        let valid = capability.len() <= 128
            && capability.starts_with("openshell.")
            && capability.split('.').count() >= 3
            && capability.split('.').all(|segment| {
                !segment.is_empty()
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            });
        if !valid || !normalized.insert(capability.clone()) {
            return Err(Status::failed_precondition(
                "OpenShell capability metadata is invalid",
            ));
        }
    }
    Ok(normalized)
}

fn proto_duration(duration: Duration) -> prost_types::Duration {
    prost_types::Duration {
        seconds: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        nanos: duration.subsec_nanos() as i32,
    }
}

fn ensure_budget(budget: &RequestBudget) -> Result<(), Status> {
    if budget.is_cancelled()
        || budget
            .remaining()
            .is_some_and(|remaining| remaining.is_zero())
    {
        Err(deadline_exceeded())
    } else {
        Ok(())
    }
}

fn deadline_exceeded() -> Status {
    Status::deadline_exceeded("OpenShell middleware request deadline exceeded")
}

fn log_auth_success(rpc: &'static str, caller: CallerKind) {
    let caller = match caller {
        CallerKind::Gateway => "gateway",
        CallerKind::Supervisor => "supervisor",
    };
    eprintln!("openshell_auth_success rpc={rpc} caller_kind={caller}");
}

fn log_auth_failure(rpc: &'static str, class: &'static str) {
    eprintln!("openshell_auth_failure rpc={rpc} class={class}");
}

fn log_authorization_result(operation: &'static str, result: &GateResult) {
    let decision = match result.decision {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
        Decision::Unspecified => "unspecified",
    };
    eprintln!(
        "openshell_authorization operation={operation} decision={decision} reason_code={}",
        result.reason_code
    );
}

#[derive(Clone)]
struct GateResult {
    decision: Decision,
    reason_code: String,
}

impl GateResult {
    fn allow() -> Self {
        Self {
            decision: Decision::Allow,
            reason_code: String::new(),
        }
    }

    fn deny(reason: &str) -> Self {
        Self {
            decision: Decision::Deny,
            reason_code: reason_code(reason),
        }
    }
}

fn blocked_authorization(reason_code: qk_core::ReasonCode) -> AuthorizationOutcome {
    AuthorizationOutcome::Blocked(BlockedReason {
        decision: qk_core::Decision::Deny,
        code: reason_code.as_str().to_owned(),
        message: "OpenShell authorization input failed closed".to_owned(),
        matched_policy: None,
    })
}

fn reason_code(reason: &str) -> String {
    let mut code = String::with_capacity(40);
    code.push_str("queryknight_");
    for byte in reason.bytes().map(|byte| byte.to_ascii_lowercase()) {
        if code.len() >= 64 {
            break;
        }
        code.push(
            if byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' {
                byte as char
            } else {
                '_'
            },
        );
    }
    code
}

fn extract_error_code(error: ExtractError) -> &'static str {
    match error {
        ExtractError::TooManyCandidates => "too_many_sql_candidates",
        ExtractError::SqlTooLarge => "query_too_large",
        ExtractError::UnsupportedParameters => "unsupported_parameters",
        ExtractError::TooDeep => "payload_too_deep",
    }
}

fn optional_string<'a>(
    value: Option<&'a prost_types::Value>,
    invalid_type: &'static str,
) -> Result<Option<&'a str>, &'static str> {
    match value {
        None => Ok(None),
        Some(value) => match value.kind.as_ref() {
            Some(prost_types::value::Kind::StringValue(value)) => Ok(Some(value.as_str())),
            _ => Err(invalid_type),
        },
    }
}

fn config_validation_reason(reason: &str) -> &'static str {
    match reason {
        "policy_yaml_must_be_string" => "policy_yaml must be a string",
        "dialect_must_be_string" => "dialect must be a string",
        "database_must_be_string" => "database must be a string",
        "environment_must_be_string" => "environment must be a string",
        "approval_action_must_be_string" => "approval_action must be a string",
        "max_sql_bytes_must_be_number" => "maxSqlBytes must be a number",
        _ => "invalid_or_unsupported_queryknight_configuration",
    }
}

fn value_number(value: &prost_types::Value) -> Option<f64> {
    match value.kind.as_ref()? {
        prost_types::value::Kind::NumberValue(value) => Some(*value),
        _ => None,
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod reason_code_tests {
    use super::reason_code;

    #[test]
    fn every_outward_reason_code_obeys_openshell_grammar_and_byte_limit() {
        let outward_inputs = [
            "invalid_middleware_name",
            "config_too_large",
            "unknown_config_field",
            "policy_yaml_required",
            "invalid_policy",
            "invalid_dialect",
            "dialect_mismatch",
            "invalid_database",
            "invalid_environment",
            "unsafe_approval_action",
            "invalid_approval_action",
            "invalid_max_sql_bytes",
            "config_registry_unavailable",
            "config_registry_full",
            "config_required",
            "config_not_validated",
            "config_changed_after_validation",
            "unsupported_phase",
            "invalid_request_context",
            "invalid_request_target",
            "headers_too_large",
            "payload_too_large",
            "invalid_utf8",
            "too_many_sql_candidates",
            "query_too_large",
            "unsupported_parameters",
            "payload_too_deep",
            "unbound_parameters",
            "unsupported_sql_analysis",
            "unsupported_websocket_payload",
            "DENY_PARSE_ERROR",
            "DENY_UNKNOWN_STATEMENT",
            "SENSITIVE_COLUMN",
            "DENY_RULE",
            "UNBOUNDED_UPDATE",
            "UNBOUNDED_DELETE",
            "LIMIT_REQUIRED",
            "LIMIT_EXCEEDED",
            "REQUIRE_APPROVAL",
            "ALLOW_RULE",
            "DEFAULT_ALLOW",
            "DEFAULT_APPROVAL",
            "DEFAULT_DENY",
            "EMPTY_QUERY",
            "QUERY_TOO_LARGE",
            "POLICY_ERROR",
            "APPROVAL_UNAVAILABLE",
            "APPROVAL_GRANTED",
            "APPROVAL_DENIED",
            "APPROVAL_ERROR",
        ];
        for input in outward_inputs {
            let code = reason_code(input);
            assert!(code.len() <= 64, "{input} produced an oversized code");
            assert!(
                code.as_bytes().first().is_some_and(u8::is_ascii_lowercase),
                "{input} produced a non-lowercase initial byte"
            );
            assert!(
                code.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
                "{input} produced an invalid OpenShell reason code: {code}"
            );
        }
        assert_eq!(reason_code("APPROVAL_ERROR"), "queryknight_approval_error");
        assert_eq!(
            reason_code("a reason containing a private value"),
            "queryknight_a_reason_containing_a_private_value"
        );
    }
}
