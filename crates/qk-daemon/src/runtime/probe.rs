//! Small loopback-only control-plane probe for lifecycle use
//! (`start` readiness, `stop`/`status` ownership, tests). Not a general
//! HTTP SDK: minimal HTTP/1.1 over `TcpStream` with short timeouts,
//! loopback targets only, and diagnostics that never include the token.

use std::net::IpAddr;
use std::time::Duration;

use crate::auth::AuthToken;

use super::error::{RuntimeError, RuntimeErrorKind};

/// Default per-attempt probe timeout (lifecycle must stay snappy).
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// A loopback probe target derived from the resolved probe URL or an
/// explicit host/port pair. Non-loopback targets are refused: the probe
/// carries the bearer token and must never send it off-host.
#[derive(Debug, Clone)]
pub struct ProbeTarget {
    host: String,
    port: u16,
}

impl ProbeTarget {
    /// Build from an explicit host/port, enforcing loopback.
    pub fn new(host: &str, port: u16) -> Result<Self, RuntimeError> {
        if !is_loopback_host(host) {
            return Err(RuntimeError::new(
                RuntimeErrorKind::Probe,
                "probe target must be loopback",
            ));
        }
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    /// Parse the frozen `QUERYKNIGHT_DAEMON_URL` shape
    /// (`http://<loopback>:<port>`); anything else is refused.
    pub fn from_url(url: &str) -> Result<Self, RuntimeError> {
        let authority = url.strip_prefix("http://").ok_or_else(|| {
            RuntimeError::new(RuntimeErrorKind::Probe, "probe URL must be http://")
        })?;
        let authority = authority.split('/').next().unwrap_or(authority);
        let (host, port) = authority.split_once(':').ok_or_else(|| {
            RuntimeError::new(RuntimeErrorKind::Probe, "probe URL must include a port")
        })?;
        let port: u16 = port.parse().map_err(|_| {
            RuntimeError::new(RuntimeErrorKind::Probe, "probe URL has an invalid port")
        })?;
        Self::new(host, port)
    }

    /// Human form for diagnostics (no secrets involved).
    pub fn display(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }

    /// The loopback host (for deriving same-host alternate-port targets).
    pub fn host(&self) -> &str {
        &self.host
    }
}

fn is_loopback_host(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare == "localhost" {
        return true;
    }
    bare.parse::<IpAddr>().is_ok_and(|addr| addr.is_loopback())
}

/// Parsed `/status` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusProbe {
    /// Daemon process id (ownership evidence for stop/status).
    pub pid: u32,
}

/// Authenticated GET. Returns status code plus raw body.
pub async fn probe_get(
    target: &ProbeTarget,
    path: &str,
    token: Option<&AuthToken>,
    timeout: Duration,
) -> Result<(u16, Vec<u8>), RuntimeError> {
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        target.host
    );
    if let Some(token) = token {
        // Token travels in the header only; never logged, never in errors.
        request.push_str(&format!("Authorization: Bearer {}\r\n", token.as_secret()));
    }
    request.push_str("\r\n");
    exchange(target, request, timeout).await
}

/// Authenticated POST with a JSON body.
pub async fn probe_post(
    target: &ProbeTarget,
    path: &str,
    token: &AuthToken,
    body: &str,
    timeout: Duration,
) -> Result<(u16, Vec<u8>), RuntimeError> {
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAuthorization: Bearer {}\r\n\r\n{body}",
        target.host,
        body.len(),
        token.as_secret(),
    );
    exchange(target, request, timeout).await
}

/// Unauthenticated `/status` probe, parsed into ownership evidence.
pub async fn probe_status(
    target: &ProbeTarget,
    timeout: Duration,
) -> Result<StatusProbe, RuntimeError> {
    let (code, body) = probe_get(target, "/status", None, timeout).await?;
    if code != 200 {
        return Err(RuntimeError::new(
            RuntimeErrorKind::Probe,
            format!("status probe answered {code}"),
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| RuntimeError::new(RuntimeErrorKind::Probe, "status probe body is not JSON"))?;
    if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(RuntimeError::new(
            RuntimeErrorKind::Probe,
            "status probe body is not healthy",
        ));
    }
    let pid = value
        .get("pid")
        .and_then(serde_json::Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok())
        .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::Probe, "status probe has no pid"))?;
    Ok(StatusProbe { pid })
}

async fn exchange(
    target: &ProbeTarget,
    request: String,
    timeout: Duration,
) -> Result<(u16, Vec<u8>), RuntimeError> {
    match tokio::time::timeout(timeout, exchange_inner(target, request)).await {
        Ok(outcome) => outcome,
        Err(_) => Err(RuntimeError::new(
            RuntimeErrorKind::Probe,
            "probe timed out",
        )),
    }
}

async fn exchange_inner(
    target: &ProbeTarget,
    request: String,
) -> Result<(u16, Vec<u8>), RuntimeError> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = tokio::net::TcpStream::connect((target.host.as_str(), target.port))
        .await
        .map_err(|error| {
            RuntimeError::new(
                RuntimeErrorKind::Probe,
                format!("cannot connect to {}", target.display()),
            )
            .with_cause(&error)
        })?;
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| {
            RuntimeError::new(RuntimeErrorKind::Probe, "probe write failed").with_cause(&error)
        })?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.map_err(|error| {
        RuntimeError::new(RuntimeErrorKind::Probe, "probe read failed").with_cause(&error)
    })?;
    parse_response(&raw)
}

/// Minimal HTTP/1.x response parse: status line + Content-Length body.
/// Chunked responses are rejected (the daemon never sends them).
fn parse_response(raw: &[u8]) -> Result<(u16, Vec<u8>), RuntimeError> {
    let invalid = || RuntimeError::new(RuntimeErrorKind::Probe, "probe got an invalid response");
    let head_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(invalid)?;
    let head = std::str::from_utf8(&raw[..head_end]).map_err(|_| invalid())?;
    let mut lines = head.lines();
    let status_line = lines.next().ok_or_else(invalid)?;
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(invalid)?;
    let mut length: usize = 0;
    for line in lines {
        // Header names are case-insensitive (hyper sends lowercase).
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().map_err(|_| invalid())?;
            }
            if name.trim().eq_ignore_ascii_case("transfer-encoding") {
                return Err(invalid());
            }
        }
    }
    let body = raw.get(head_end + 4..).ok_or_else(invalid)?;
    if body.len() < length {
        return Err(invalid());
    }
    Ok((code, body[..length].to_vec()))
}

impl RuntimeError {
    /// Attach a connectivity cause without leaking response content.
    fn with_cause(self, error: &std::io::Error) -> Self {
        Self::new(
            self.kind().clone(),
            format!("{self} ({})", short_io_kind(error)),
        )
    }
}

fn short_io_kind(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::ConnectionRefused => "connection refused",
        std::io::ErrorKind::TimedOut => "timed out",
        _ => "io error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_targets_only() {
        assert!(ProbeTarget::new("127.0.0.1", 1).is_ok());
        assert!(ProbeTarget::new("localhost", 1).is_ok());
        assert!(ProbeTarget::new("::1", 1).is_ok());
        assert!(ProbeTarget::new("example.com", 1).is_err());
        assert!(ProbeTarget::new("192.168.1.1", 1).is_err());
        assert!(ProbeTarget::from_url("http://127.0.0.1:47821").is_ok());
        assert!(ProbeTarget::from_url("https://127.0.0.1:47821").is_err());
        assert!(ProbeTarget::from_url("http://example.com:80").is_err());
    }

    #[test]
    fn parses_plain_response() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}";
        assert_eq!(
            parse_response(raw).expect("parse"),
            (200, b"{\"ok\":true}".to_vec())
        );
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").is_err());
        assert!(parse_response(b"junk").is_err());
    }
}
