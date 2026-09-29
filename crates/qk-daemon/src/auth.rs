//! Local daemon token model. Authentication answers only "may this local
//! client call the API" — never anything about database authorization.
//!
//! Transports (frozen): `Authorization: Bearer <token>`, `?token=`
//! query, or `x-qk-token` header. Missing or wrong token is 401. The
//! token never appears in logs, errors, or `Debug` output. Comparison is
//! length-checked with a single-pass fold rather than short-circuiting
//! equality.

use std::fmt::{self, Display, Formatter};

use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;

/// Opaque local API token. Redacted everywhere by construction.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthToken(String);

impl AuthToken {
    /// Wrap an explicitly supplied token (config/tests/lifecycle layer).
    pub fn new(token: String) -> Self {
        Self(token)
    }

    /// Raw bytes for comparison only. Never logged.
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Raw token text for lifecycle use only (token-file persistence,
    /// loopback probe `Authorization` header). Callers must never log,
    /// format into errors, or serialize this value.
    pub fn as_secret(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "AuthToken(redacted)")
    }
}

impl Display for AuthToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "AuthToken(redacted)")
    }
}

/// Generate a fresh token: 24 random bytes, base64url, no padding
/// (frozen 32-character format). File persistence belongs to the daemon
/// lifecycle layer, not here.
pub fn generate_token() -> AuthToken {
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes).expect("system randomness available");
    AuthToken(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Length-checked constant-fold comparison (no early exit on content).
fn timing_safe_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Extract a candidate token from the three frozen transports.
fn candidate_token(request: &Request) -> Option<String> {
    if let Some(header) = request.headers().get(axum::http::header::AUTHORIZATION) {
        if let Ok(text) = header.to_str() {
            if let Some(token) = text.strip_prefix("Bearer ") {
                if !token.is_empty() {
                    return Some(token.to_owned());
                }
            }
        }
    }
    if let Some(header) = request.headers().get("x-qk-token") {
        if let Ok(token) = header.to_str() {
            if !token.is_empty() {
                return Some(token.to_owned());
            }
        }
    }
    let query = request.uri().query().unwrap_or("");
    for pair in query.split('&') {
        if let Some(token) = pair.strip_prefix("token=") {
            if !token.is_empty() {
                return Some(token.to_owned());
            }
        }
    }
    None
}

/// Validate request authentication. Returns `None` when authorized, or a
/// `401 unauthorized` response (frozen text body) otherwise.
pub fn check_auth(request: &Request, expected: &AuthToken) -> Option<Response> {
    let authorized = candidate_token(request)
        .is_some_and(|candidate| timing_safe_eq(candidate.as_bytes(), expected.as_bytes()));
    if authorized {
        return None;
    }
    Some((StatusCode::UNAUTHORIZED, "unauthorized").into_response())
}

/// True for loopback hosts (frozen set: `127.0.0.1`, `localhost`, `::1`,
/// with optional ports and brackets). Parses brackets correctly, unlike
/// the reference's naive colon split, which rejects bracketed IPv6.
pub fn is_local_host(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return false;
    };
    let name = host_name(host);
    name == "127.0.0.1" || name == "localhost" || name == "::1"
}

fn host_name(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        // `[::1]` or `[::1]:47821`.
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
        return host;
    }
    match host.rsplit_once(':') {
        // `127.0.0.1:47821` but never bare `::1` (colons belong to it).
        Some((name, port))
            if !name.contains(':')
                && !port.is_empty()
                && port.chars().all(|c| c.is_ascii_digit()) =>
        {
            name
        }
        _ => host,
    }
}

/// Validate an `Origin` header value when present (frozen rule: absent is
/// fine, present must be loopback).
pub fn is_local_origin(origin: Option<&str>) -> bool {
    let Some(origin) = origin else {
        return true;
    };
    let host = origin
        .split("://")
        .nth(1)
        .unwrap_or(origin)
        .split('/')
        .next()
        .unwrap_or("");
    is_local_host(Some(host))
}

#[cfg(test)]
mod tests {
    use super::{generate_token, is_local_host, is_local_origin};

    #[test]
    fn token_format() {
        let token = generate_token();
        let other = generate_token();
        assert_eq!(token.0.len(), 32);
        assert_ne!(token.0, other.0);
        assert!(format!("{token:?}").contains("redacted"));
        assert!(!format!("{token:?}").contains(&token.0));
    }

    #[test]
    fn host_classification() {
        assert!(is_local_host(Some("127.0.0.1:47821")));
        assert!(is_local_host(Some("localhost")));
        assert!(is_local_host(Some("[::1]:47821")));
        assert!(is_local_host(Some("::1")));
        assert!(!is_local_host(Some("evil.test")));
        assert!(!is_local_host(Some("evil.test:47821")));
        assert!(!is_local_host(None));
        assert!(!is_local_host(Some("")));
    }

    #[test]
    fn origin_classification() {
        assert!(is_local_origin(None));
        assert!(is_local_origin(Some("http://127.0.0.1:3000")));
        assert!(is_local_origin(Some("http://localhost:3000")));
        assert!(!is_local_origin(Some("http://evil.test")));
        assert!(!is_local_origin(Some("not a url evil.test")));
    }
}
