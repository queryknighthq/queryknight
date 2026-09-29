//! Shared authenticated loopback client and approval provider for the
//! QueryKnight daemon control plane. This crate contains no daemon server,
//! database driver, protocol ingress, policy evaluator, or approval resolver.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::fmt::{self, Debug, Display, Formatter};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

use qk_approval::{
    ApprovalId, ApprovalProvider, ApprovalRequest, ProviderDecision, ProviderError,
    ProviderResponse,
};
use qk_core::{ExactDigest, QueryShapeFingerprint};
use serde::{Deserialize, Serialize};

/// Per-operation connect/read/write bound preserved from the MCP client.
pub const CONTROL_PLANE_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum HTTP response bytes read from the daemon (new extraction hardening).
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_HEADER_BYTES: usize = 32 * 1024;

/// Content-free, typed control-plane failure. No variant carries response
/// bodies, bearer tokens, digests, or transport diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlPlaneError {
    /// Shared runtime paths could not be resolved.
    Discovery,
    /// Configured daemon URL was malformed or unsupported.
    InvalidUrl,
    /// Configured target was not an accepted loopback endpoint.
    NonLoopback,
    /// Token file was missing, unreadable, invalid, empty, or oversized.
    Token,
    /// Socket connection failed.
    Connection,
    /// A connect/read/write socket operation timed out.
    Timeout,
    /// Daemon rejected the bearer token.
    Authentication,
    /// Any other non-success HTTP status.
    HttpStatus(u16),
    /// Response was malformed or did not match the typed contract.
    InvalidResponse,
    /// Response exceeded the fixed body/header budget.
    ResponseTooLarge,
    /// Local request serialization or protocol handling failed.
    Protocol,
}

impl Display for ControlPlaneError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discovery => f.write_str("daemon discovery failed"),
            Self::InvalidUrl => f.write_str("daemon URL is invalid"),
            Self::NonLoopback => f.write_str("daemon URL must use loopback"),
            Self::Token => f.write_str("daemon token is unavailable"),
            Self::Connection => f.write_str("daemon connection failed"),
            Self::Timeout => f.write_str("daemon request timed out"),
            Self::Authentication => f.write_str("daemon authentication failed"),
            Self::HttpStatus(code) => write!(f, "daemon returned HTTP {code}"),
            Self::InvalidResponse => f.write_str("daemon response is invalid"),
            Self::ResponseTooLarge => f.write_str("daemon response exceeds size limit"),
            Self::Protocol => f.write_str("daemon protocol request failed"),
        }
    }
}

impl std::error::Error for ControlPlaneError {}

/// Typed approval status. Unknown or missing daemon values are never Approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ApprovalStatus {
    /// Request is waiting for a human decision.
    Waiting,
    /// Request was approved.
    Approved,
    /// Request was denied.
    Denied,
    /// Any unrecognized/missing wire status; fails closed.
    #[default]
    Unknown,
}

impl ApprovalStatus {
    fn parse(value: &str) -> Self {
        match value {
            "waiting" => Self::Waiting,
            "approved" => Self::Approved,
            "denied" => Self::Denied,
            _ => Self::Unknown,
        }
    }
}

/// Typed approval binding kind. Unrecognized values remain Unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ApprovalBindingKind {
    /// SQL-only Exact V1.
    ExactV1,
    /// Parameter-aware Exact V2.
    ExactV2,
    /// Shape-only HTTP-created row.
    ShapeV1,
    /// Migrated legacy row, quarantined from authorization.
    LegacyShape,
    /// Any unrecognized/missing binding kind; fails closed.
    #[default]
    Unknown,
}

impl ApprovalBindingKind {
    fn parse(value: &str) -> Self {
        match value {
            "exact_v1" => Self::ExactV1,
            "exact_v2" => Self::ExactV2,
            "shape_v1" => Self::ShapeV1,
            "legacy_shape" => Self::LegacyShape,
            _ => Self::Unknown,
        }
    }

    fn wire_name(self) -> Option<&'static str> {
        match self {
            Self::ExactV1 => Some("exact_v1"),
            Self::ExactV2 => Some("exact_v2"),
            Self::ShapeV1 => Some("shape_v1"),
            Self::LegacyShape | Self::Unknown => None,
        }
    }
}

/// Requested human approval decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// Approve the waiting request.
    Approved,
    /// Deny the waiting request.
    Denied,
}

impl ApprovalDecision {
    /// Frozen daemon wire value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
        }
    }
}

/// Decision status returned by the daemon. Unknown responses stay Unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ApprovalDecisionStatus {
    /// Approved.
    Approved,
    /// Denied.
    Denied,
    /// Unknown/malformed decision status.
    #[default]
    Unknown,
}

impl ApprovalDecisionStatus {
    /// Frozen daemon wire value, empty for unknown.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Unknown => "",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "approved" => Self::Approved,
            "denied" => Self::Denied,
            _ => Self::Unknown,
        }
    }
}

/// Approval summary needed by the MCP approval-list formatter. Schema
/// snapshots remain open JSON because the daemon contract stores extensible DDL.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ApprovalSummary {
    /// Opaque approval id.
    pub id: String,
    /// Human-facing risk label.
    pub risk: String,
    /// Human-facing operation summary.
    pub operation_summary: String,
    /// Human-facing reason.
    pub reason: String,
    /// Wire status, mapped conservatively to a typed enum.
    #[serde(deserialize_with = "deserialize_status")]
    pub status: ApprovalStatus,
    /// Schema DDL payload retained as open JSON for frozen display semantics.
    pub schema_ddl: Option<serde_json::Value>,
}

impl Default for ApprovalSummary {
    fn default() -> Self {
        Self {
            id: String::new(),
            risk: String::new(),
            operation_summary: String::new(),
            reason: String::new(),
            status: ApprovalStatus::Unknown,
            schema_ddl: None,
        }
    }
}

fn deserialize_status<'de, D>(deserializer: D) -> Result<ApprovalStatus, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let status = String::deserialize(deserializer)?;
    Ok(ApprovalStatus::parse(&status))
}

/// Typed approval row projection used by the reusable provider.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ApprovalRecord {
    /// Opaque approval id.
    pub id: String,
    /// Query-shape fingerprint.
    pub fingerprint: String,
    /// Current status, conservatively mapped.
    #[serde(deserialize_with = "deserialize_status")]
    pub status: ApprovalStatus,
    /// Binding kind, conservatively mapped.
    #[serde(deserialize_with = "deserialize_binding_kind")]
    pub binding_kind: ApprovalBindingKind,
}

impl Default for ApprovalRecord {
    fn default() -> Self {
        Self {
            id: String::new(),
            fingerprint: String::new(),
            status: ApprovalStatus::Unknown,
            binding_kind: ApprovalBindingKind::LegacyShape,
        }
    }
}

fn deserialize_binding_kind<'de, D>(deserializer: D) -> Result<ApprovalBindingKind, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let kind = String::deserialize(deserializer)?;
    Ok(ApprovalBindingKind::parse(&kind))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionRequest<'a> {
    connection_key: &'a str,
    source: &'a str,
}

#[derive(Deserialize)]
struct SessionResponse {
    id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateApprovalRequest<'a> {
    connection_key: &'a str,
    session_id: Option<&'a str>,
    fingerprint: &'a str,
    reason: &'a str,
    risk: &'static str,
    operation_summary: String,
    timeout_ms: u64,
    binding_kind: &'static str,
    exact_digest: String,
    integration: &'a str,
    environment: &'a str,
    database: &'a str,
    agent_id: &'a str,
    tool: &'a str,
}

#[derive(Deserialize)]
struct IdResponse {
    id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyRequest<'a> {
    digest: String,
    version: &'static str,
    session_id: &'a Option<String>,
    integration: &'a str,
    environment: &'a str,
    database: &'a str,
    agent_id: &'a str,
    tool: &'a str,
}

#[derive(Deserialize)]
struct VerifyResponse {
    #[serde(rename = "match")]
    matched: bool,
}

#[derive(Deserialize)]
struct AllowResponse {
    allowed: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DecideRequest<'a> {
    status: &'static str,
    source: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'static str>,
}

#[derive(Deserialize)]
struct DecideResponse {
    status: String,
}

/// Authenticated client bound to one loopback daemon endpoint. Cloning copies
/// immutable endpoint/token configuration; each operation owns its socket.
/// It is `Send + Sync` and contains no per-request mutable state.
#[derive(Clone)]
pub struct ControlPlaneClient {
    addr: SocketAddr,
    token: qk_daemon::AuthToken,
}

impl Debug for ControlPlaneClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlPlaneClient")
            .field("addr", &self.addr)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl ControlPlaneClient {
    /// Discover the daemon using centralized `qk-daemon::runtime` paths,
    /// token, and pid semantics. A configured invalid daemon URL is an error
    /// and is never replaced by another endpoint.
    pub fn discover(home: Option<PathBuf>) -> Result<Self, ControlPlaneError> {
        let configured = std::env::var(qk_daemon::runtime::paths::ENV_DAEMON_URL).ok();
        Self::discover_with_url(home, configured.as_deref())
    }

    fn discover_with_url(
        home: Option<PathBuf>,
        daemon_url: Option<&str>,
    ) -> Result<Self, ControlPlaneError> {
        let source = qk_daemon::runtime::RuntimeSource { home, port: None };
        let resolved = qk_daemon::runtime::paths::resolve(&source)
            .map_err(|_| ControlPlaneError::Discovery)?;

        // Preserve old ordering: token discovery precedes endpoint override
        // validation; no token contents enter error/debug output.
        let token = qk_daemon::runtime::token::read_existing(&resolved.paths)
            .map_err(|_| ControlPlaneError::Token)?
            .ok_or(ControlPlaneError::Token)?;
        let mut port = resolved.port;
        if let Some(url) = daemon_url {
            port = daemon_url_port(url)?;
        } else if let Ok(Some(record)) = qk_daemon::runtime::singleton::read_pid(&resolved.paths) {
            port = record.port;
        }
        Ok(Self {
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
            token,
        })
    }

    fn get(&self, path: &str) -> Result<(u16, Vec<u8>), ControlPlaneError> {
        roundtrip(&self.addr, self.token.as_secret(), "GET", path, None)
    }

    fn post<T: Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<(u16, Vec<u8>), ControlPlaneError> {
        let body = serde_json::to_vec(body).map_err(|_| ControlPlaneError::Protocol)?;
        roundtrip(
            &self.addr,
            self.token.as_secret(),
            "POST",
            path,
            Some(&body),
        )
    }

    fn post_json<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, ControlPlaneError> {
        let (status, raw) = self.post(path, body)?;
        if !(200..300).contains(&status) {
            return Err(http_status_error(status));
        }
        serde_json::from_slice(&raw).map_err(|_| ControlPlaneError::InvalidResponse)
    }

    /// Create a daemon session with the caller's trusted source identity.
    pub fn create_session(
        &self,
        connection_key: &str,
        source: &str,
    ) -> Result<String, ControlPlaneError> {
        let response: SessionResponse = self.post_json(
            "/sessions",
            &SessionRequest {
                connection_key,
                source,
            },
        )?;
        Ok(response.id)
    }

    /// Record one history event. Callers retain best-effort semantics.
    pub fn record_event(&self, event: &serde_json::Value) -> Result<(), ControlPlaneError> {
        let _: serde_json::Value = self.post_json("/events", event)?;
        Ok(())
    }

    /// List typed approval summaries for the MCP presentation layer.
    pub fn list_approvals(&self) -> Result<Vec<ApprovalSummary>, ControlPlaneError> {
        let (status, raw) = self.get("/approvals")?;
        if status != 200 {
            return Err(http_status_error(status));
        }
        serde_json::from_slice(&raw).map_err(|_| ControlPlaneError::InvalidResponse)
    }

    /// Read typed status/fingerprint/binding metadata for an approval id.
    pub fn approval(&self, id: &ApprovalId) -> Result<ApprovalRecord, ControlPlaneError> {
        validate_id(id.as_str())?;
        let path = format!("/approvals/{}", id.as_str());
        let (status, raw) = self.get(&path)?;
        if status != 200 {
            return Err(http_status_error(status));
        }
        serde_json::from_slice(&raw).map_err(|_| ControlPlaneError::InvalidResponse)
    }

    /// Prove an exact retry against the daemon's live typed binding. Only the
    /// opaque digest/version and trusted scope cross the HTTP boundary.
    pub fn verify_approval(
        &self,
        id: &ApprovalId,
        exact: &ExactDigest,
        scope: &qk_approval::ApprovalScope,
    ) -> Result<bool, ControlPlaneError> {
        validate_id(id.as_str())?;
        let body = VerifyRequest {
            digest: exact.to_hex(),
            version: exact.version(),
            session_id: &scope.session_id,
            integration: &scope.integration,
            environment: &scope.environment,
            database: &scope.database,
            agent_id: &scope.agent_id,
            tool: &scope.tool,
        };
        let path = format!("/approvals/{}/verify", id.as_str());
        let response: VerifyResponse = self.post_json(&path, &body)?;
        Ok(response.matched)
    }

    /// Decide a waiting approval with a caller-supplied trusted source and
    /// optional Once/Session reuse scope.
    pub fn decide_approval(
        &self,
        id: &str,
        decision: ApprovalDecision,
        source: qk_approval::DecisionSource,
        scope: Option<qk_approval::Scope>,
    ) -> Result<ApprovalDecisionStatus, ControlPlaneError> {
        validate_id(id)?;
        let path = format!("/approvals/{id}/decide");
        let scope = scope.map(|scope| scope.as_str());
        let response: DecideResponse = self.post_json(
            &path,
            &DecideRequest {
                status: decision.as_str(),
                source: source.as_str(),
                scope,
            },
        )?;
        let status = ApprovalDecisionStatus::parse(&response.status);
        if status == ApprovalDecisionStatus::Unknown {
            return Err(ControlPlaneError::InvalidResponse);
        }
        Ok(status)
    }

    /// Check a fully scoped live session-shape grant.
    pub fn session_allows(
        &self,
        session_id: &str,
        fingerprint: &QueryShapeFingerprint,
        scope: &qk_approval::ApprovalScope,
    ) -> Result<bool, ControlPlaneError> {
        let path = format!(
            "/allows?sessionId={}&fingerprint={}&integration={}&environment={}&database={}&agentId={}&tool={}",
            percent_encode(session_id),
            percent_encode(fingerprint.as_str()),
            percent_encode(&scope.integration),
            percent_encode(&scope.environment),
            percent_encode(&scope.database),
            percent_encode(&scope.agent_id),
            percent_encode(&scope.tool),
        );
        let (status, raw) = self.get(&path)?;
        if status != 200 {
            return Err(http_status_error(status));
        }
        let response: AllowResponse =
            serde_json::from_slice(&raw).map_err(|_| ControlPlaneError::InvalidResponse)?;
        Ok(response.allowed)
    }

    /// Create a new exact-bound waiting approval for qk-approval resolution.
    pub fn create_approval(
        &self,
        input: &ApprovalRequest,
        connection_key: &str,
        session_id: Option<&str>,
    ) -> Result<ApprovalId, ControlPlaneError> {
        let binding_kind = match input.exact {
            ExactDigest::V1(_) => ApprovalBindingKind::ExactV1,
            ExactDigest::V2(_) => ApprovalBindingKind::ExactV2,
        }
        .wire_name()
        .expect("exact digest always has an exact binding kind");
        let body = CreateApprovalRequest {
            connection_key,
            session_id,
            fingerprint: input.fingerprint.as_str(),
            reason: &input.message,
            risk: risk_for(input.reason_code.as_str(), input.operation.as_deref()),
            operation_summary: operation_summary(
                input.operation.as_deref(),
                input.table.as_deref().or(input.column.as_deref()),
            ),
            timeout_ms: 60_000,
            binding_kind,
            exact_digest: input.exact.to_hex(),
            integration: &input.scope.integration,
            environment: &input.scope.environment,
            database: &input.scope.database,
            agent_id: &input.scope.agent_id,
            tool: &input.scope.tool,
        };
        let response: IdResponse = self.post_json("/approvals", &body)?;
        Ok(ApprovalId::new(response.id))
    }
}

impl Debug for ApprovalSummary {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalSummary")
            .field("id", &self.id)
            .field("status", &self.status)
            .field("risk", &self.risk)
            .finish_non_exhaustive()
    }
}

fn http_status_error(status: u16) -> ControlPlaneError {
    if status == 401 {
        ControlPlaneError::Authentication
    } else {
        ControlPlaneError::HttpStatus(status)
    }
}

fn validate_id(id: &str) -> Result<(), ControlPlaneError> {
    if id.is_empty() || id.contains(['/', '?', '#', ' ']) {
        Err(ControlPlaneError::InvalidResponse)
    } else {
        Ok(())
    }
}

fn daemon_url_port(url: &str) -> Result<u16, ControlPlaneError> {
    let authority = url
        .strip_prefix("http://")
        .ok_or(ControlPlaneError::InvalidUrl)?
        .split('/')
        .next()
        .unwrap_or_default();
    let (host, port) = authority
        .split_once(':')
        .ok_or(ControlPlaneError::InvalidUrl)?;
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare != "127.0.0.1" && bare != "localhost" && bare != "::1" {
        return Err(ControlPlaneError::NonLoopback);
    }
    port.parse().map_err(|_| ControlPlaneError::InvalidUrl)
}

fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn roundtrip(
    addr: &SocketAddr,
    token: &str,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>), ControlPlaneError> {
    let mut stream = TcpStream::connect_timeout(addr, CONTROL_PLANE_TIMEOUT).map_err(map_io)?;
    stream
        .set_read_timeout(Some(CONTROL_PLANE_TIMEOUT))
        .map_err(map_io)?;
    stream
        .set_write_timeout(Some(CONTROL_PLANE_TIMEOUT))
        .map_err(map_io)?;
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nAuthorization: Bearer {token}\r\n"
    );
    if let Some(body) = body {
        request.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).map_err(map_io)?;
    if let Some(body) = body {
        stream.write_all(body).map_err(map_io)?;
    }
    // Bound total read even when Content-Length is missing or the peer drips
    // data indefinitely. A small extra allowance admits the response headers.
    let read_limit = (MAX_RESPONSE_BYTES + MAX_HEADER_BYTES + 1) as u64;
    let mut raw = Vec::with_capacity(4096);
    stream
        .take(read_limit)
        .read_to_end(&mut raw)
        .map_err(map_io)?;
    if raw.len() as u64 >= read_limit {
        return Err(ControlPlaneError::ResponseTooLarge);
    }
    parse_response(&raw)
}

fn map_io(error: std::io::Error) -> ControlPlaneError {
    if error.kind() == std::io::ErrorKind::TimedOut
        || error.kind() == std::io::ErrorKind::WouldBlock
    {
        ControlPlaneError::Timeout
    } else {
        ControlPlaneError::Connection
    }
}

fn parse_response(raw: &[u8]) -> Result<(u16, Vec<u8>), ControlPlaneError> {
    let head_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(ControlPlaneError::InvalidResponse)?;
    if head_end > MAX_HEADER_BYTES {
        return Err(ControlPlaneError::ResponseTooLarge);
    }
    let head =
        std::str::from_utf8(&raw[..head_end]).map_err(|_| ControlPlaneError::InvalidResponse)?;
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or(ControlPlaneError::InvalidResponse)?;
    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value
                    .trim()
                    .parse()
                    .map_err(|_| ControlPlaneError::InvalidResponse)?;
            }
        }
    }
    if content_length > MAX_RESPONSE_BYTES {
        return Err(ControlPlaneError::ResponseTooLarge);
    }
    let body = raw
        .get(head_end + 4..)
        .ok_or(ControlPlaneError::InvalidResponse)?;
    if body.len() < content_length {
        return Err(ControlPlaneError::InvalidResponse);
    }
    Ok((status, body[..content_length].to_vec()))
}

/// Daemon-backed `qk-approval::ApprovalProvider`. It contains immutable
/// caller scope/retry data only; no shared mutable cache or token state.
pub struct DaemonApprovalProvider {
    client: ControlPlaneClient,
    session_id: Option<String>,
    connection_key: String,
    approval_id: Option<String>,
}

impl Debug for DaemonApprovalProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("DaemonApprovalProvider")
            .field("client", &self.client)
            .field("session_id", &self.session_id.as_ref().map(|_| "<opaque>"))
            .field(
                "approval_id",
                &self.approval_id.as_ref().map(|_| "<opaque>"),
            )
            .finish_non_exhaustive()
    }
}

impl DaemonApprovalProvider {
    /// Bind one shared client to this authorization attempt's session,
    /// connection key, and optional retry id.
    pub fn new(
        client: ControlPlaneClient,
        session_id: Option<String>,
        connection_key: String,
        approval_id: Option<String>,
    ) -> Self {
        Self {
            client,
            session_id,
            connection_key,
            approval_id,
        }
    }
}

impl ApprovalProvider for DaemonApprovalProvider {
    fn request(&self, input: &ApprovalRequest) -> Result<ProviderResponse, ProviderError> {
        let fingerprint = input.fingerprint.as_str();
        if let Some(id) = self.approval_id.as_deref() {
            let approval_id = ApprovalId::new(id.to_owned());
            if let Ok(row) = self.client.approval(&approval_id) {
                if row.fingerprint == fingerprint
                    && row.binding_kind != ApprovalBindingKind::LegacyShape
                {
                    if row.status == ApprovalStatus::Denied {
                        return Ok(ProviderResponse {
                            id: approval_id,
                            decision: ProviderDecision::Denied,
                        });
                    }
                    let exact_binding = matches!(
                        row.binding_kind,
                        ApprovalBindingKind::ExactV1 | ApprovalBindingKind::ExactV2
                    );
                    if exact_binding
                        && row.status == ApprovalStatus::Approved
                        && self
                            .client
                            .verify_approval(&approval_id, &input.exact, &input.scope)
                            .unwrap_or(false)
                    {
                        return Ok(ProviderResponse {
                            id: approval_id,
                            decision: ProviderDecision::Approved,
                        });
                    }
                }
            }
            return Ok(ProviderResponse {
                id: approval_id,
                decision: ProviderDecision::Waiting,
            });
        }
        if let Some(session_id) = self.session_id.as_deref() {
            if self
                .client
                .session_allows(session_id, &input.fingerprint, &input.scope)
                .unwrap_or(false)
            {
                return Ok(ProviderResponse {
                    id: ApprovalId::new(format!("local-session-{session_id}")),
                    decision: ProviderDecision::Approved,
                });
            }
        }
        match self
            .client
            .create_approval(input, &self.connection_key, self.session_id.as_deref())
        {
            Ok(id) => Ok(ProviderResponse {
                id,
                decision: ProviderDecision::Waiting,
            }),
            Err(_) => Err(ProviderError::Transport(
                "control plane unavailable".to_owned(),
            )),
        }
    }
}

fn risk_for(reason_code: &str, operation: Option<&str>) -> &'static str {
    if reason_code == "SENSITIVE_COLUMN" {
        return "high";
    }
    if operation == Some("drop") || operation == Some("truncate") {
        return "critical";
    }
    if reason_code == "UNBOUNDED_DELETE" {
        return "critical";
    }
    if reason_code == "UNBOUNDED_UPDATE"
        || operation == Some("delete")
        || operation == Some("update")
    {
        return "high";
    }
    "medium"
}

fn operation_summary(operation: Option<&str>, target: Option<&str>) -> String {
    let base = operation.unwrap_or("statement");
    let summary = match target {
        Some(target) if !target.is_empty() => format!("{base} {target}"),
        _ => base.to_owned(),
    };
    summary.chars().take(200).collect()
}

#[cfg(test)]
mod tests;
