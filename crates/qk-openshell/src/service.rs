use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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

/// Trusted runtime inputs for one OpenShell authorization service.
///
/// `DbConfig` selects the SQL dialect and password-redacted approval identity;
/// it is never used to open a database connection.
pub struct OpenShellServiceConfig {
    db_config: DbConfig,
    control_plane: Option<ControlPlaneClient>,
    observer: qk_audit::Observer,
    sql_log_level: qk_audit::SqlLogLevel,
}

impl OpenShellServiceConfig {
    /// Build a service configuration from a trusted database URL.
    pub fn new(db_config: DbConfig) -> Self {
        Self {
            db_config,
            control_plane: None,
            observer: qk_audit::Observer::default(),
            sql_log_level: qk_audit::SqlLogLevel::Fingerprint,
        }
    }

    /// Use the shared QueryKnight daemon for approvals. If omitted, approval-
    /// required decisions fail closed as unavailable.
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

    fn validate_and_store(
        &self,
        name: &str,
        input: prost_types::Struct,
    ) -> Result<(), &'static str> {
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

        let mut configs = self
            .state
            .configs
            .write()
            .map_err(|_| "config_registry_unavailable")?;
        if !configs.contains_key(name) && configs.len() >= MAX_CONFIGS {
            return Err("config_registry_full");
        }
        configs.insert(
            name.to_owned(),
            Arc::new(ValidatedConfig {
                input,
                policy,
                database,
                environment,
                max_sql_bytes,
            }),
        );
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
    ) -> GateResult {
        if candidates.is_empty() {
            return GateResult::allow();
        }
        let state = Arc::clone(&self.state);
        match tokio::task::spawn_blocking(move || {
            let mut final_result = GateResult::allow();
            for candidate in candidates {
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
                if gate.decision == Decision::Deny {
                    return gate;
                }
                final_result = gate;
            }
            final_result
        })
        .await
        {
            Ok(result) => result,
            Err(_) => GateResult::deny("policy_error"),
        }
    }

    async fn evaluate_body(
        &self,
        config: Arc<ValidatedConfig>,
        context: Option<&RequestContext>,
        body: &[u8],
        max_payload_bytes: usize,
    ) -> GateResult {
        if body.len() > max_payload_bytes.min(MAX_PAYLOAD_BYTES) {
            return GateResult::deny("payload_too_large");
        }
        let text = match std::str::from_utf8(body) {
            Ok(text) => text,
            Err(_) => return GateResult::deny("invalid_utf8"),
        };
        let candidates = match extract_candidates(text) {
            Ok(candidates) => candidates,
            Err(error) => return GateResult::deny(extract_error_code(error)),
        };
        let request_id = context
            .filter(|context| !context.request_id.is_empty())
            .map(|context| context.request_id.clone());
        let sandbox_id = context
            .filter(|context| !context.sandbox_id.is_empty())
            .map(|context| context.sandbox_id.clone());
        self.evaluate_candidates(config, request_id, sandbox_id, candidates)
            .await
    }
}

#[tonic::async_trait]
impl SupervisorMiddleware for OpenShellService {
    async fn describe(
        &self,
        request: Request<MiddlewareDescribeRequest>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        let peer = request
            .into_inner()
            .gateway
            .ok_or_else(|| Status::failed_precondition("OpenShell peer metadata is required"))?;
        let version = peer
            .protocol_version
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("OpenShell protocol version is required"))?;
        if version.major != 1 {
            return Err(Status::failed_precondition(
                "unsupported OpenShell protocol major version",
            ));
        }
        if !peer.required_capabilities.is_empty() {
            return Err(Status::failed_precondition(
                "required OpenShell capability is unsupported",
            ));
        }
        let binding = |operation, phase| MiddlewareBinding {
            operation: operation as i32,
            phase: phase as i32,
            max_payload_bytes: MAX_PAYLOAD_BYTES as u64,
            request_timeout: None,
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
            expected_audience: String::new(),
            extension: Some(extension_proto::PeerMetadata {
                protocol_version: Some(extension_proto::ProtocolVersion { major: 1, minor: 2 }),
                implementation_name: "queryknight".to_owned(),
                implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
                supported_capabilities: Vec::new(),
                required_capabilities: Vec::new(),
            }),
        }))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        let request = request.into_inner();
        let (valid, reason) = match request.config {
            Some(config) => match self.validate_and_store(&request.middleware_name, config) {
                Ok(()) => (true, ""),
                Err(reason) => (false, config_validation_reason(reason)),
            },
            None => (false, "invalid_or_unsupported_queryknight_configuration"),
        };
        Ok(Response::new(ValidateConfigResponse {
            valid,
            reason: reason.to_owned(),
        }))
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        let request = request.into_inner();
        let binding = self.validated_config(&request.middleware_name, request.config.as_ref());
        let result = match binding {
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
                        &request.body,
                        MAX_PAYLOAD_BYTES,
                    )
                    .await
                }
            }
        };
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
        let mut inbound = request.into_inner();
        let service = self.clone();
        let output = try_stream! {
            let first = inbound
                .message()
                .await?
                .ok_or_else(|| Status::invalid_argument("WebSocket stream must start with preflight"))?;
            let Some(web_socket_session_event::Event::Preflight(preflight)) = first.event else {
                Err(Status::invalid_argument("WebSocket stream must start with preflight"))?
            };
            let validated = service.validated_config(
                &preflight.middleware_name,
                preflight.config.as_ref(),
            );
            let (validated, failure) = match validated {
                Err(reason) => (None, Some(reason)),
                Ok(config) => {
                    let phase_ok = SupervisorMiddlewarePhase::try_from(preflight.phase).ok()
                        == Some(SupervisorMiddlewarePhase::PreCredentials);
                    let context_ok = preflight.context.as_ref().is_some_and(|context| {
                        context.encoded_len() <= MAX_CONTEXT_BYTES
                    });
                    let target_ok = preflight.target.as_ref().is_some_and(|target| {
                        target.encoded_len() <= MAX_TARGET_BYTES
                    });
                    let failure = if !phase_ok {
                        Some("unsupported_phase")
                    } else if !context_ok {
                        Some("invalid_request_context")
                    } else if !target_ok {
                        Some("invalid_request_target")
                    } else {
                        None
                    };
                    (failure.is_none().then_some(config), failure)
                }
            };
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
            let request_id = preflight
                .context
                .as_ref()
                .filter(|context| !context.request_id.is_empty())
                .map(|context| context.request_id.clone());
            let sandbox_id = preflight
                .context
                .as_ref()
                .filter(|context| !context.sandbox_id.is_empty())
                .map(|context| context.sandbox_id.clone());
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
                        let gate = match message.payload {
                            Some(web_socket_message::Payload::Text(text)) => {
                                if text.len() > MAX_PAYLOAD_BYTES {
                                    GateResult::deny("payload_too_large")
                                } else {
                                    match extract_candidates(&text) {
                                        Ok(candidates) => {
                                            service
                                                .evaluate_candidates(
                                                    Arc::clone(&validated),
                                                    request_id.clone(),
                                                    sandbox_id.clone(),
                                                    candidates,
                                                )
                                                .await
                                        }
                                        Err(error) => GateResult::deny(extract_error_code(error)),
                                    }
                                }
                            }
                            Some(web_socket_message::Payload::Binary(_)) | None => {
                                GateResult::deny("unsupported_websocket_payload")
                            }
                        };
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
