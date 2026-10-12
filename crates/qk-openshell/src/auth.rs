use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use http::{Request as HttpRequest, Response as HttpResponse};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tonic::Status;
use tower::{Layer, Service};

const EXTENSION_JWT_TYP: &str = "openshell-ext+jwt";
const MAX_JWT_BYTES: usize = 8 * 1024;
const MAX_JWKS_BYTES: usize = 64 * 1024;
const MAX_JWKS_KEYS: usize = 32;
const MAX_KID_BYTES: usize = 128;
const MAX_CLOCK_SKEW_SECS: i64 = 5;
const MAX_EXTENSION_TTL_SECS: i64 = 60 * 60;
const MAX_GRPC_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_GATEWAY_ID_BYTES: usize = 128;
const MAX_AUDIENCE_BYTES: usize = 512;
const MAX_JTI_BYTES: usize = 128;
const MAX_SANDBOX_ID_BYTES: usize = 128;
const MAX_SUBJECT_BYTES: usize = 256;
const MAX_GRPC_METADATA_BYTES: usize = 32 * 1024;

/// Operator-provisioned OpenShell caller trust configuration.
#[derive(Clone)]
pub struct OpenShellJwtConfig {
    gateway_id: String,
    expected_audience: String,
    jwks_file: PathBuf,
}

impl OpenShellJwtConfig {
    /// Configure the exact gateway identity, middleware audience, and trusted
    /// local JWKS file. The file must contain OpenShell Ed25519 signing keys.
    pub fn new(
        gateway_id: impl Into<String>,
        expected_audience: impl Into<String>,
        jwks_file: impl Into<PathBuf>,
    ) -> Result<Self, OpenShellAuthConfigError> {
        let gateway_id = gateway_id.into();
        let expected_audience = expected_audience.into();
        validate_config_text(&gateway_id, MAX_GATEWAY_ID_BYTES)
            .map_err(|_| OpenShellAuthConfigError::InvalidGatewayId)?;
        validate_config_text(&expected_audience, MAX_AUDIENCE_BYTES)
            .map_err(|_| OpenShellAuthConfigError::InvalidAudience)?;
        Ok(Self {
            gateway_id,
            expected_audience,
            jwks_file: jwks_file.into(),
        })
    }

    /// Exact audience this service verifies and returns from Describe.
    #[must_use]
    pub fn expected_audience(&self) -> &str {
        &self.expected_audience
    }
    /// Operator-provisioned OpenShell gateway identity.
    #[must_use]
    pub fn gateway_id(&self) -> &str {
        &self.gateway_id
    }
}

impl fmt::Debug for OpenShellJwtConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenShellJwtConfig")
            .field("gateway_id", &self.gateway_id)
            .field("expected_audience", &self.expected_audience)
            .field("jwks_file", &"<redacted path>")
            .finish()
    }
}

/// Safe error for invalid operator-provisioned extension authentication config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OpenShellAuthConfigError {
    /// Gateway ID is empty, whitespace-padded, or contains controls.
    #[error("OpenShell gateway ID is invalid")]
    InvalidGatewayId,
    /// Audience is empty, whitespace-padded, or contains controls.
    #[error("OpenShell expected audience is invalid")]
    InvalidAudience,
    /// Trusted JWKS file could not be read or exceeded its bound.
    #[error("trusted OpenShell JWKS file is unavailable or too large")]
    JwksFile,
    /// Trusted JWKS did not match the OpenShell Ed25519 contract.
    #[error("trusted OpenShell JWKS is invalid")]
    InvalidJwks,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Jwk {
    kty: String,
    crv: String,
    alg: String,
    #[serde(rename = "use")]
    key_use: String,
    kid: String,
    x: String,
}

/// Caller role emitted by OpenShell v0.1.2.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CallerKind {
    Gateway,
    Supervisor,
}

#[derive(Deserialize)]
struct ExtensionClaims {
    iss: String,
    aud: String,
    sub: String,
    iat: i64,
    exp: i64,
    jti: String,
    caller_kind: CallerKind,
    #[serde(default)]
    sandbox_id: Option<String>,
    #[serde(default)]
    nbf: Option<i64>,
}

/// Verified OpenShell extension identity attached to a decoded gRPC request.
#[derive(Clone)]
pub(crate) struct VerifiedExtensionClaims {
    caller_kind: CallerKind,
    sandbox_id: Option<String>,
}

impl VerifiedExtensionClaims {
    pub(crate) fn caller_kind(&self) -> CallerKind {
        self.caller_kind
    }

    pub(crate) fn sandbox_id(&self) -> Option<&str> {
        self.sandbox_id.as_deref()
    }
}

impl fmt::Debug for VerifiedExtensionClaims {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedExtensionClaims")
            .field("caller_kind", &self.caller_kind)
            .field(
                "sandbox_id",
                &self.sandbox_id.as_deref().map(|_| "<verified>"),
            )
            .finish()
    }
}

/// Bounded trusted key set. Unknown token `kid` values never trigger network I/O.
pub(crate) struct OpenShellAuthenticator {
    issuer: String,
    audience: String,
    keys: HashMap<String, DecodingKey>,
}

impl fmt::Debug for OpenShellAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenShellAuthenticator")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("trusted_key_count", &self.keys.len())
            .finish()
    }
}

impl OpenShellAuthenticator {
    pub(crate) fn load(config: &OpenShellJwtConfig) -> Result<Self, OpenShellAuthConfigError> {
        let file = File::open(&config.jwks_file).map_err(|_| OpenShellAuthConfigError::JwksFile)?;
        let mut bytes = Vec::with_capacity(4096);
        file.take((MAX_JWKS_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| OpenShellAuthConfigError::JwksFile)?;
        if bytes.len() > MAX_JWKS_BYTES {
            return Err(OpenShellAuthConfigError::JwksFile);
        }
        let jwks: Jwks =
            serde_json::from_slice(&bytes).map_err(|_| OpenShellAuthConfigError::InvalidJwks)?;
        if jwks.keys.is_empty() || jwks.keys.len() > MAX_JWKS_KEYS {
            return Err(OpenShellAuthConfigError::InvalidJwks);
        }
        let mut keys = HashMap::with_capacity(jwks.keys.len());
        for jwk in jwks.keys {
            if jwk.kty != "OKP"
                || jwk.crv != "Ed25519"
                || jwk.alg != "EdDSA"
                || jwk.key_use != "sig"
                || jwk.kid.is_empty()
                || jwk.kid.len() > MAX_KID_BYTES
                || jwk.kid.trim() != jwk.kid
                || jwk.kid.chars().any(char::is_control)
            {
                return Err(OpenShellAuthConfigError::InvalidJwks);
            }
            let key = DecodingKey::from_ed_components(&jwk.x)
                .map_err(|_| OpenShellAuthConfigError::InvalidJwks)?;
            if keys.insert(jwk.kid, key).is_some() {
                return Err(OpenShellAuthConfigError::InvalidJwks);
            }
        }
        Ok(Self {
            issuer: format!("openshell-gateway:{}", config.gateway_id),
            audience: config.expected_audience.clone(),
            keys,
        })
    }
    pub(crate) fn trusted_key_count(&self) -> usize {
        self.keys.len()
    }

    fn authenticate(
        &self,
        token: &str,
        expected_callers: &[CallerKind],
    ) -> Result<VerifiedExtensionClaims, AuthFailure> {
        if token.is_empty() || token.len() > MAX_JWT_BYTES {
            return Err(AuthFailure::Unauthenticated);
        }
        let header = decode_header(token).map_err(|_| AuthFailure::Unauthenticated)?;
        if header.alg != Algorithm::EdDSA || header.typ.as_deref() != Some(EXTENSION_JWT_TYP) {
            return Err(AuthFailure::Unauthenticated);
        }
        let kid = header.kid.ok_or(AuthFailure::Unauthenticated)?;
        let key = self.keys.get(&kid).ok_or(AuthFailure::Unauthenticated)?;
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.set_required_spec_claims(&["iss", "aud", "sub", "iat", "exp"]);
        validation.leeway = MAX_CLOCK_SKEW_SECS as u64;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        let claims = decode::<ExtensionClaims>(token, key, &validation)
            .map_err(|_| AuthFailure::Unauthenticated)?
            .claims;
        let now = unix_seconds();
        let lifetime = claims.exp.saturating_sub(claims.iat);
        if claims.iss != self.issuer
            || claims.aud != self.audience
            || claims.sub.len() > MAX_SUBJECT_BYTES
            || claims.iat <= 0
            || claims.iat > now.saturating_add(MAX_CLOCK_SKEW_SECS)
            || claims.exp <= claims.iat
            || lifetime > MAX_EXTENSION_TTL_SECS + MAX_CLOCK_SKEW_SECS
            || claims.exp <= now.saturating_sub(MAX_CLOCK_SKEW_SECS)
            || claims
                .nbf
                .is_some_and(|nbf| nbf > now.saturating_add(MAX_CLOCK_SKEW_SECS))
            || claims.jti.is_empty()
            || claims.jti.len() > MAX_JTI_BYTES
            || claims.jti.chars().any(char::is_control)
        {
            return Err(AuthFailure::Unauthenticated);
        }
        match (claims.caller_kind, claims.sandbox_id.as_deref()) {
            (CallerKind::Gateway, None) if claims.sub == self.issuer => {}
            (CallerKind::Supervisor, Some(sandbox_id))
                if !sandbox_id.is_empty()
                    && sandbox_id.len() <= MAX_SANDBOX_ID_BYTES
                    && sandbox_id.trim() == sandbox_id
                    && !sandbox_id.chars().any(char::is_control)
                    && claims.sub == format!("spiffe://openshell/sandbox/{sandbox_id}") => {}
            _ => return Err(AuthFailure::Unauthenticated),
        }
        if !expected_callers.contains(&claims.caller_kind) {
            return Err(AuthFailure::PermissionDenied);
        }
        Ok(VerifiedExtensionClaims {
            caller_kind: claims.caller_kind,
            sandbox_id: claims.sandbox_id,
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum AuthFailure {
    Unauthenticated,
    PermissionDenied,
}

impl AuthFailure {
    fn status(self) -> Status {
        match self {
            Self::Unauthenticated => {
                Status::unauthenticated("OpenShell extension authentication failed")
            }
            Self::PermissionDenied => {
                Status::permission_denied("OpenShell caller is not permitted for this RPC")
            }
        }
    }
}

/// Deadline/cancellation information carried from the network boundary.
#[derive(Clone)]
pub(crate) struct RequestBudget {
    deadline: Option<Instant>,
    parent_cancelled: Arc<AtomicBool>,
}

impl RequestBudget {
    pub(crate) fn new(deadline: Option<Instant>) -> Self {
        Self {
            deadline,
            parent_cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn operation(&self, timeout: Duration) -> Self {
        let local_deadline = Instant::now().checked_add(timeout);
        let deadline = match (self.deadline, local_deadline) {
            (Some(parent), Some(local)) => Some(parent.min(local)),
            (Some(parent), None) => Some(parent),
            (None, local) => local,
        };
        Self {
            deadline,
            parent_cancelled: Arc::clone(&self.parent_cancelled),
        }
    }

    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub(crate) fn cancelled(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.parent_cancelled)
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.parent_cancelled.load(Ordering::Acquire)
            || self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
    }

    pub(crate) fn remaining(&self) -> Option<Duration> {
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    fn cancel_parent(&self) {
        self.parent_cancelled.store(true, Ordering::Release);
    }
}

/// RAII signal set when the Tonic request future is canceled or completes.
pub(crate) struct RequestCancellationGuard(RequestBudget);

impl RequestCancellationGuard {
    pub(crate) fn new(budget: RequestBudget) -> Self {
        Self(budget)
    }
}

impl Drop for RequestCancellationGuard {
    fn drop(&mut self) {
        self.0.cancel_parent();
    }
}

/// Tower boundary that authenticates before Tonic decodes protobuf payloads.
#[derive(Clone)]
pub(crate) struct OpenShellRequestLayer {
    authenticator: Option<Arc<OpenShellAuthenticator>>,
    unary_timeout: Duration,
}

impl OpenShellRequestLayer {
    pub(crate) fn new(
        authenticator: Option<Arc<OpenShellAuthenticator>>,
        unary_timeout: Duration,
    ) -> Self {
        Self {
            authenticator,
            unary_timeout,
        }
    }
}

impl<S> Layer<S> for OpenShellRequestLayer {
    type Service = OpenShellRequestService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OpenShellRequestService {
            inner,
            authenticator: self.authenticator.clone(),
            unary_timeout: self.unary_timeout,
        }
    }
}

#[derive(Clone)]
pub(crate) struct OpenShellRequestService<S> {
    inner: S,
    authenticator: Option<Arc<OpenShellAuthenticator>>,
    unary_timeout: Duration,
}

impl<S, RequestBody, ResponseBody> Service<HttpRequest<RequestBody>> for OpenShellRequestService<S>
where
    S: Service<HttpRequest<RequestBody>, Response = HttpResponse<ResponseBody>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    RequestBody: Send + 'static,
    ResponseBody: Default + Send + 'static,
{
    type Response = HttpResponse<ResponseBody>;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, mut request: HttpRequest<RequestBody>) -> Self::Future {
        let path = request.uri().path();
        let Some((caller, streaming)) = rpc_contract(path) else {
            let response =
                Status::unimplemented("unsupported OpenShell RPC").into_http::<ResponseBody>();
            return Box::pin(async move { Ok(response) });
        };
        let headers = request.headers();
        let metadata_bytes = headers.iter().fold(0usize, |total, (name, value)| {
            total
                .saturating_add(name.as_str().len())
                .saturating_add(value.as_bytes().len())
        });
        if headers.len() > 128 || metadata_bytes > MAX_GRPC_METADATA_BYTES {
            if self.authenticator.is_some() {
                log_auth_failure(rpc_name(path), "metadata_over_capacity");
            }
            let response =
                Status::resource_exhausted("OpenShell request metadata exceeds its limit")
                    .into_http::<ResponseBody>();
            return Box::pin(async move { Ok(response) });
        }
        if let Some(authenticator) = &self.authenticator {
            let token = match bearer_token(request.headers()) {
                Ok(token) => token,
                Err(failure) => {
                    log_auth_failure(rpc_name(path), "missing_or_invalid_token");
                    let response = failure.status().into_http::<ResponseBody>();
                    return Box::pin(async move { Ok(response) });
                }
            };
            match authenticator.authenticate(token, caller) {
                Ok(claims) => {
                    request.extensions_mut().insert(claims);
                }
                Err(failure) => {
                    log_auth_failure(
                        rpc_name(path),
                        match failure {
                            AuthFailure::Unauthenticated => "token_rejected",
                            AuthFailure::PermissionDenied => "caller_kind_rejected",
                        },
                    );
                    let response = failure.status().into_http::<ResponseBody>();
                    return Box::pin(async move { Ok(response) });
                }
            }
        }
        let client_timeout = match grpc_timeout(request.headers()) {
            Ok(timeout) => timeout,
            Err(status) => {
                let response = status.into_http::<ResponseBody>();
                return Box::pin(async move { Ok(response) });
            }
        };
        let now = Instant::now();
        let deadline = if streaming {
            client_timeout.and_then(|timeout| now.checked_add(timeout.min(MAX_GRPC_TIMEOUT)))
        } else {
            let local = now.checked_add(self.unary_timeout);
            let client =
                client_timeout.and_then(|timeout| now.checked_add(timeout.min(MAX_GRPC_TIMEOUT)));
            match (local, client) {
                (Some(local), Some(client)) => Some(local.min(client)),
                (Some(local), None) => Some(local),
                (None, client) => client,
            }
        };
        request
            .extensions_mut()
            .insert(RequestBudget::new(deadline));
        Box::pin(self.inner.call(request))
    }
}

/// Caller matrix for the supervisor-middleware RPCs in OpenShell v0.1.2
/// (commit `6648bd0c290efbc41ba131ee9831ee45cd431f94`).
///
/// Derived from the tagged source:
///   * `Describe` and `ValidateConfig` are called by the gateway at startup
///     via `MiddlewareRegistry::connect_services` (caller_kind = gateway).
///   * `Describe` is ALSO called by the supervisor during middleware
///     bootstrap via `GrpcMiddlewareService::describe` (caller_kind = supervisor).
///   * `ValidateConfig` is NOT called by the supervisor in any observed v0.1.2
///     code path; keep Gateway-only per least-privilege.
///   * `EvaluateHttpRequest` and `EvaluateWebSocketSession` are called only
///     by the supervisor (caller_kind = supervisor), bound to the sandbox_id.
pub(crate) const DESCRIBE_ALLOWED_CALLERS: &[CallerKind] =
    &[CallerKind::Gateway, CallerKind::Supervisor];
pub(crate) const VALIDATE_CONFIG_ALLOWED_CALLERS: &[CallerKind] = &[CallerKind::Gateway];
pub(crate) const EVALUATE_HTTP_REQUEST_ALLOWED_CALLERS: &[CallerKind] = &[CallerKind::Supervisor];
pub(crate) const EVALUATE_WEB_SOCKET_SESSION_ALLOWED_CALLERS: &[CallerKind] =
    &[CallerKind::Supervisor];

fn rpc_contract(path: &str) -> Option<(&'static [CallerKind], bool)> {
    let (callers, streaming) = match path {
        "/openshell.middleware.v1.SupervisorMiddleware/Describe" => {
            (DESCRIBE_ALLOWED_CALLERS, false)
        }
        "/openshell.middleware.v1.SupervisorMiddleware/ValidateConfig" => {
            (VALIDATE_CONFIG_ALLOWED_CALLERS, false)
        }
        "/openshell.middleware.v1.SupervisorMiddleware/EvaluateHttpRequest" => {
            (EVALUATE_HTTP_REQUEST_ALLOWED_CALLERS, false)
        }
        "/openshell.middleware.v1.SupervisorMiddleware/EvaluateWebSocketSession" => {
            (EVALUATE_WEB_SOCKET_SESSION_ALLOWED_CALLERS, true)
        }
        _ => return None,
    };
    Some((callers, streaming))
}

fn rpc_name(path: &str) -> &'static str {
    match path.rsplit('/').next().unwrap_or_default() {
        "Describe" => "Describe",
        "ValidateConfig" => "ValidateConfig",
        "EvaluateHttpRequest" => "EvaluateHttpRequest",
        "EvaluateWebSocketSession" => "EvaluateWebSocketSession",
        _ => "unknown",
    }
}

fn bearer_token(headers: &http::HeaderMap) -> Result<&str, AuthFailure> {
    let values = headers.get_all(http::header::AUTHORIZATION);
    let mut values = values.iter();
    let value = values.next().ok_or(AuthFailure::Unauthenticated)?;
    if values.next().is_some() {
        return Err(AuthFailure::Unauthenticated);
    }
    let value = value.to_str().map_err(|_| AuthFailure::Unauthenticated)?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or(AuthFailure::Unauthenticated)?;
    if token.is_empty()
        || token.len() > MAX_JWT_BYTES
        || token.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(AuthFailure::Unauthenticated);
    }
    Ok(token)
}

fn grpc_timeout(headers: &http::HeaderMap) -> Result<Option<Duration>, Status> {
    let Some(value) = headers.get("grpc-timeout") else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| Status::invalid_argument("invalid grpc-timeout"))?;
    if value.len() < 2 || value.len() > 9 {
        return Err(Status::invalid_argument("invalid grpc-timeout"));
    }
    let (digits, unit) = value.split_at(value.len() - 1);
    if digits.is_empty() || digits.len() > 8 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Status::invalid_argument("invalid grpc-timeout"));
    }
    let amount = digits
        .parse::<u64>()
        .map_err(|_| Status::invalid_argument("invalid grpc-timeout"))?;
    let duration = match unit.as_bytes()[0] {
        b'H' => Duration::from_secs(amount.saturating_mul(3600)),
        b'M' => Duration::from_secs(amount.saturating_mul(60)),
        b'S' => Duration::from_secs(amount),
        b'm' => Duration::from_millis(amount),
        b'u' => Duration::from_micros(amount),
        b'n' => Duration::from_nanos(amount),
        _ => return Err(Status::invalid_argument("invalid grpc-timeout")),
    };
    Ok(Some(duration))
}

fn validate_config_text(value: &str, max_bytes: usize) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(())
    } else {
        Ok(())
    }
}

fn unix_seconds() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs()),
    )
    .unwrap_or(i64::MAX)
}

fn log_auth_failure(rpc: &str, class: &str) {
    eprintln!("openshell_auth_failure rpc={rpc} class={class}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    #[test]
    fn bearer_metadata_is_bounded_and_unique() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Bearer signed.jwt.value".parse().unwrap(),
        );
        assert_eq!(bearer_token(&headers).unwrap(), "signed.jwt.value");
        headers.append(
            http::header::AUTHORIZATION,
            "Bearer another".parse().unwrap(),
        );
        assert!(bearer_token(&headers).is_err());
        headers.clear();
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Bearer {}", "x".repeat(MAX_JWT_BYTES + 1))
                .parse()
                .unwrap(),
        );
        assert!(bearer_token(&headers).is_err());
    }

    #[test]
    fn grpc_timeout_parser_matches_tonic_units_and_bounds_effective_timeout() {
        for (wire, expected) in [
            ("500m", Duration::from_millis(500)),
            ("2S", Duration::from_secs(2)),
            ("300000u", Duration::from_millis(300)),
        ] {
            let mut headers = http::HeaderMap::new();
            headers.insert("grpc-timeout", wire.parse().unwrap());
            assert_eq!(grpc_timeout(&headers).unwrap(), Some(expected));
        }
        let mut headers = http::HeaderMap::new();
        headers.insert("grpc-timeout", "not-valid".parse().unwrap());
        assert_eq!(
            grpc_timeout(&headers).unwrap_err().code(),
            Code::InvalidArgument
        );
    }
}
