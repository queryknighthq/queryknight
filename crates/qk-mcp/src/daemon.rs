//! Minimal sync daemon control-plane client (loopback only): session
//! bootstrap, history events, approval list/decide/get, session
//! allow-checks, plus the sync [`DaemonApprovalProvider`].
//!
//! Deliberately dependency-free HTTP over `std::net::TcpStream`
//! (blocking, bounded timeouts): the provider trait is sync, and this
//! avoids nesting Tokio runtimes inside async tool handlers. Bearer
//! header transport only; the token never appears in URLs, logs, or
//! errors.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use qk_approval::{
    ApprovalId, ApprovalProvider, ApprovalRequest, ProviderDecision, ProviderError,
    ProviderResponse,
};

/// Per-attempt control-plane timeout (loopback; fail fast so tools
/// degrade instead of hanging).
const TIMEOUT: Duration = Duration::from_secs(5);

/// Control-plane failure marker. Deliberately content-free: daemon
/// response bytes must never flow into tool errors or logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaemonFailure;

/// Loopback daemon endpoint with a bearer token. The token lives here
/// only in transit to the `Authorization` header — never logged,
/// never formatted into errors.
#[derive(Debug, Clone)]
pub struct DaemonEndpoint {
    addr: SocketAddr,
    token: String,
}

impl DaemonEndpoint {
    /// Discover the daemon from frozen runtime state: bearer token
    /// file plus pid-file port (`QUERYKNIGHT_DAEMON_URL` override
    /// honored when loopback). `home` overrides `QUERYKNIGHT_HOME`.
    /// `None` means "daemon unavailable" — tools degrade to the
    /// frozen history-less/unavailable behavior, never an error here.
    pub fn discover(home: Option<std::path::PathBuf>) -> Option<Self> {
        let source = qk_daemon::runtime::RuntimeSource { home, port: None };
        let resolved = qk_daemon::runtime::paths::resolve(&source).ok()?;
        let raw = qk_daemon::runtime::token::read_token_raw(&resolved.paths.token).ok()?;
        let token = String::from_utf8(raw).ok()?;
        let token = token.trim().to_owned();
        if token.is_empty() {
            return None;
        }
        // Port: explicit daemon-URL override, else the pid file's
        // recorded port (ephemeral runs), else the resolved default.
        let mut port = resolved.port;
        if let Ok(url) = std::env::var("QUERYKNIGHT_DAEMON_URL") {
            port = daemon_url_port(&url)?;
        } else if let Ok(Some(record)) = qk_daemon::runtime::singleton::read_pid(&resolved.paths) {
            port = record.port;
        }
        Some(Self {
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
            token,
        })
    }

    fn get(&self, path: &str) -> Result<(u16, Vec<u8>), DaemonFailure> {
        roundtrip(&self.addr, Some(&self.token), "GET", path, None)
    }

    fn post(&self, path: &str, body: &str) -> Result<(u16, Vec<u8>), DaemonFailure> {
        roundtrip(&self.addr, Some(&self.token), "POST", path, Some(body))
    }

    fn post_json(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, DaemonFailure> {
        let (code, raw) = self.post(path, &body.to_string())?;
        if code / 100 != 2 {
            return Err(DaemonFailure);
        }
        serde_json::from_slice(&raw).map_err(|_| DaemonFailure)
    }

    /// `POST /sessions {connectionKey, source: "mcp"}` → session id.
    pub fn start_session(&self, connection_key: &str) -> Option<String> {
        let body = self
            .post_json(
                "/sessions",
                &serde_json::json!({"connectionKey": connection_key, "source": "mcp"}),
            )
            .ok()?;
        body.get("id")?.as_str().map(str::to_owned)
    }

    /// `POST /events` (best-effort by contract; callers ignore errors).
    pub fn record_event(&self, event: &serde_json::Value) {
        let _ = self.post_json("/events", event);
    }

    /// `GET /approvals` → raw views (callers filter/format).
    pub fn list_approvals(&self) -> Result<Vec<serde_json::Value>, DaemonFailure> {
        let (code, raw) = self.get("/approvals")?;
        if code != 200 {
            return Err(DaemonFailure);
        }
        let value: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| DaemonFailure)?;
        value.as_array().cloned().ok_or(DaemonFailure)
    }

    /// `GET /approvals/{id}` → status, fingerprint, binding kind,
    /// and scope dimensions (digest values never cross: exact proof
    /// goes through [`DaemonEndpoint::verify_approval`]).
    pub fn get_approval(&self, id: &str) -> Option<ApprovalRow> {
        if id.contains(['/', '?', '#', ' ']) {
            return None;
        }
        let (code, raw) = self.get(&format!("/approvals/{id}")).ok()?;
        if code != 200 {
            return None;
        }
        let value: serde_json::Value = serde_json::from_slice(&raw).ok()?;
        let text = |key: &str| {
            value
                .get(key)
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_owned()
        };
        Some(ApprovalRow {
            status: text("status"),
            fingerprint: text("fingerprint"),
            binding_kind: value
                .get("bindingKind")
                .and_then(|kind| kind.as_str())
                .unwrap_or("legacy_shape")
                .to_owned(),
            session_id: value
                .get("sessionId")
                .and_then(|value| value.as_str())
                .map(str::to_owned),
            integration: text("integration"),
            environment: text("environment"),
            database: text("database"),
            agent_id: text("agentId"),
            tool: text("tool"),
        })
    }

    /// `POST /approvals/{id}/verify {digest, version, scope...}` →
    /// whether the row authorizes the exact request. Digest travels
    /// in the POST body only (never URLs, logs, or views).
    pub fn verify_approval(
        &self,
        id: &str,
        digest_hex: &str,
        version: &str,
        scope: &qk_approval::ApprovalScope,
    ) -> bool {
        if id.contains(['/', '?', '#', ' ']) {
            return false;
        }
        let value = match self.post_json(
            &format!("/approvals/{id}/verify"),
            &serde_json::json!({
                "digest": digest_hex,
                "version": version,
                "sessionId": scope.session_id,
                "integration": scope.integration,
                "environment": scope.environment,
                "database": scope.database,
                "agentId": scope.agent_id,
                "tool": scope.tool,
            }),
        ) {
            Ok(value) => value,
            Err(_) => return false,
        };
        value
            .get("match")
            .and_then(|value| value.as_bool())
            .unwrap_or(false)
    }

    /// `POST /approvals/{id}/decide {status, source: "mcp"}`.
    pub fn decide(&self, id: &str, status: &str) -> Result<String, DaemonFailure> {
        if id.contains(['/', '?', '#', ' ']) {
            return Err(DaemonFailure);
        }
        let value = self.post_json(
            &format!("/approvals/{id}/decide"),
            &serde_json::json!({"status": status, "source": "mcp"}),
        )?;
        value
            .get("status")
            .and_then(|status| status.as_str())
            .map(str::to_owned)
            .ok_or(DaemonFailure)
    }

    /// `GET /allows` session-shape check with full scope dims (absent
    /// dims would only match dimension-less rows).
    pub fn session_allows(
        &self,
        session_id: &str,
        fingerprint: &str,
        scope: &qk_approval::ApprovalScope,
    ) -> bool {
        let (code, raw) = match self.get(&format!(
            "/allows?sessionId={}&fingerprint={}&integration={}&environment={}&database={}&agentId={}&tool={}",
            percent_encode(session_id),
            percent_encode(fingerprint),
            percent_encode(&scope.integration),
            percent_encode(&scope.environment),
            percent_encode(&scope.database),
            percent_encode(&scope.agent_id),
            percent_encode(&scope.tool),
        )) {
            Ok(response) => response,
            Err(DaemonFailure) => return false,
        };
        if code != 200 {
            return false;
        }
        serde_json::from_slice::<serde_json::Value>(&raw)
            .ok()
            .and_then(|value| value.get("allowed")?.as_bool())
            .unwrap_or(false)
    }

    /// Create a waiting approval row (`wait:false` flow — the daemon
    /// always stores new rows as waiting).
    pub fn request_approval(&self, body: &serde_json::Value) -> Result<String, DaemonFailure> {
        let value = self.post_json("/approvals", body)?;
        value
            .get("id")
            .and_then(|id| id.as_str())
            .map(str::to_owned)
            .ok_or(DaemonFailure)
    }
}

/// Parse a frozen `QUERYKNIGHT_DAEMON_URL` (`http://<loopback>:<port>`);
/// anything else refuses (`None` → daemon unavailable).
fn daemon_url_port(url: &str) -> Option<u16> {
    let authority = url.strip_prefix("http://")?;
    let authority = authority.split('/').next().unwrap_or(authority);
    let (host, port) = authority.split_once(':')?;
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare != "127.0.0.1" && bare != "localhost" && bare != "::1" {
        return None;
    }
    port.parse().ok()
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
    token: Option<&str>,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<(u16, Vec<u8>), DaemonFailure> {
    let mut stream = TcpStream::connect_timeout(addr, TIMEOUT).map_err(|_| DaemonFailure)?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|_| DaemonFailure)?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|_| DaemonFailure)?;
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    if let Some(token) = token {
        // Header transport only — the token never touches the URL.
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if let Some(body) = body {
        request.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|_| DaemonFailure)?;
    if let Some(body) = body {
        stream
            .write_all(body.as_bytes())
            .map_err(|_| DaemonFailure)?;
    }
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|_| DaemonFailure)?;
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> Result<(u16, Vec<u8>), DaemonFailure> {
    let head_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(DaemonFailure)?;
    let head = std::str::from_utf8(&raw[..head_end]).map_err(|_| DaemonFailure)?;
    let mut lines = head.lines();
    let code: u16 = lines
        .next()
        .ok_or(DaemonFailure)?
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or(DaemonFailure)?;
    let mut length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().map_err(|_| DaemonFailure)?;
            }
        }
    }
    let body = raw.get(head_end + 4..).ok_or(DaemonFailure)?;
    if body.len() < length {
        return Err(DaemonFailure);
    }
    Ok((code, body[..length].to_vec()))
}

/// Daemon row projection needed for retry validation (status and
/// shape for the verdict gate; scope for the equality check; the
/// digest itself is verified opaquely via `verify_approval`).
#[derive(Debug, Clone)]
pub struct ApprovalRow {
    /// Row status (`waiting`, `approved`, `denied`).
    pub status: String,
    /// Shape fingerprint.
    pub fingerprint: String,
    /// Binding kind (`exact_v1`, `exact_v2`, `shape_v1`, legacy).
    pub binding_kind: String,
    /// Session scope dimension.
    pub session_id: Option<String>,
    /// Integration scope dimension.
    pub integration: String,
    /// Environment scope dimension.
    pub environment: String,
    /// Database scope dimension.
    pub database: String,
    /// Agent scope dimension.
    pub agent_id: String,
    /// Tool scope dimension.
    pub tool: String,
}

/// Daemon-backed approval provider: retry ids resolve against daemon
/// rows with FULL exact validation (approved/live status, shape AND
/// digest-version-digest match via the opaque verify endpoint, full
/// scope equality) — id + fingerprint alone never authorize
/// (INV-041). Fresh requests create daemon rows carrying the exact
/// binding (always waiting — the `wait:false` agent flow), and a
/// session-allow pre-check reuses daemon session grants without
/// minting duplicate rows (mirrors `hasSessionAllow`).
pub struct DaemonApprovalProvider {
    endpoint: DaemonEndpoint,
    session_id: Option<String>,
    connection_key: String,
    approval_id: Option<String>,
}

impl DaemonApprovalProvider {
    /// Bind daemon endpoint, session context, and optional retry id.
    pub fn new(
        endpoint: DaemonEndpoint,
        session_id: Option<String>,
        connection_key: String,
        approval_id: Option<String>,
    ) -> Self {
        Self {
            endpoint,
            session_id,
            connection_key,
            approval_id,
        }
    }
}

impl ApprovalProvider for DaemonApprovalProvider {
    fn request(&self, input: &ApprovalRequest) -> Result<ProviderResponse, ProviderError> {
        let fingerprint = input.fingerprint.as_str().to_owned();
        // Retry path: the daemon row must prove the FULL exact
        // identity (status, shape, binding version, digest bytes,
        // scope, expiry) via the opaque verify endpoint. Shape or
        // status alone never authorize (INV-041); legacy rows read as
        // waiting so the agent seeks a fresh approval (INV-027).
        if let Some(id) = self.approval_id.as_deref() {
            if let Some(row) = self.endpoint.get_approval(id) {
                if row.fingerprint == fingerprint && row.binding_kind != "legacy_shape" {
                    if row.status == "denied" {
                        return Ok(ProviderResponse {
                            id: ApprovalId::new(id.to_owned()),
                            decision: ProviderDecision::Denied,
                        });
                    }
                    if row.status == "approved"
                        && self.endpoint.verify_approval(
                            id,
                            &input.exact.to_hex(),
                            input.exact.version(),
                            &input.scope,
                        )
                    {
                        return Ok(ProviderResponse {
                            id: ApprovalId::new(id.to_owned()),
                            decision: ProviderDecision::Approved,
                        });
                    }
                }
            }
            return Ok(ProviderResponse {
                id: ApprovalId::new(id.to_owned()),
                decision: ProviderDecision::Waiting,
            });
        }
        // Session path: a live daemon session grant authorizes without
        // minting a duplicate row. The id is local-only (never shown
        // to agents); resolution still inserts the exact-bound grant.
        if let Some(session_id) = self.session_id.as_deref() {
            if self
                .endpoint
                .session_allows(session_id, &fingerprint, &input.scope)
            {
                return Ok(ProviderResponse {
                    id: ApprovalId::new(format!("local-session-{session_id}")),
                    decision: ProviderDecision::Approved,
                });
            }
        }
        // Fresh request: create the daemon row carrying the exact
        // binding (always waiting). The digest crosses this trusted
        // internal boundary in the POST body only — never URLs, logs,
        // or views.
        let body = serde_json::json!({
            "connectionKey": self.connection_key,
            "sessionId": self.session_id,
            "fingerprint": fingerprint,
            "reason": input.message,
            "risk": risk_for(input.reason_code.as_str(), input.operation.as_deref()),
            "operationSummary": operation_summary(input.operation.as_deref(), input.table.as_deref().or(input.column.as_deref())),
            "timeoutMs": 60_000,
            "bindingKind": input.exact.version(),
            "exactDigest": input.exact.to_hex(),
            "integration": input.scope.integration,
            "environment": input.scope.environment,
            "database": input.scope.database,
            "agentId": input.scope.agent_id,
            "tool": input.scope.tool,
        });
        match self.endpoint.request_approval(&body) {
            Ok(id) => Ok(ProviderResponse {
                id: ApprovalId::new(id),
                decision: ProviderDecision::Waiting,
            }),
            Err(_) => Err(ProviderError::Transport(
                "control plane unavailable".to_owned(),
            )),
        }
    }
}

/// Frozen `riskFor` mapping (presentation risk for the daemon UI row).
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

/// Frozen `operationSummary` mapping (`base[ target]`, 200 chars).
fn operation_summary(operation: Option<&str>, target: Option<&str>) -> String {
    let base = operation.unwrap_or("statement");
    let summary = match target {
        Some(target) if !target.is_empty() => format!("{base} {target}"),
        _ => base.to_owned(),
    };
    summary.chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing_refuses_offhost() {
        assert_eq!(daemon_url_port("http://127.0.0.1:47821"), Some(47821));
        assert_eq!(daemon_url_port("http://localhost:1"), Some(1));
        assert_eq!(daemon_url_port("https://127.0.0.1:1"), None);
        assert_eq!(daemon_url_port("http://example.com:80"), None);
        assert_eq!(daemon_url_port("not a url"), None);
    }

    #[test]
    fn frozen_risk_mapping() {
        assert_eq!(risk_for("SENSITIVE_COLUMN", None), "high");
        assert_eq!(risk_for("X", Some("drop")), "critical");
        assert_eq!(risk_for("UNBOUNDED_DELETE", None), "critical");
        assert_eq!(risk_for("UNBOUNDED_UPDATE", None), "high");
        assert_eq!(risk_for("X", Some("update")), "high");
        assert_eq!(risk_for("REQUIRE_APPROVAL", None), "medium");
    }

    #[test]
    fn frozen_summary_mapping() {
        assert_eq!(
            operation_summary(Some("delete"), Some("users")),
            "delete users"
        );
        assert_eq!(operation_summary(None, None), "statement");
        assert_eq!(operation_summary(Some("select"), Some("")), "select");
        assert!(operation_summary(Some("update"), None).len() <= 200);
    }
}
