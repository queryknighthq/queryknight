//! Daemon configuration, resolved before startup. No environment reads
//! inside handlers; no globals.

use std::net::IpAddr;
use std::time::Duration;

use crate::auth::AuthToken;

/// Frozen defaults: loopback-only bind, reference port.
pub const DEFAULT_BIND: &str = "127.0.0.1";
/// Frozen default port.
pub const DEFAULT_PORT: u16 = 47821;
/// Default JSON body limit (no frozen limit exists; approval/history
/// bodies are kilobytes — 1 MiB is generous headroom, not a policy).
pub const DEFAULT_BODY_LIMIT_BYTES: usize = 1024 * 1024;
/// Default per-request timeout. No approval polling route exists (clients
/// poll), so no long operation can legitimately exceed this.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Static daemon configuration.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Bind address. Loopback unless `allow_remote` is set explicitly.
    pub bind: IpAddr,
    /// TCP port.
    pub port: u16,
    /// Opaque local API token.
    pub token: AuthToken,
    /// JSON body limit in bytes.
    pub body_limit_bytes: usize,
    /// Per-request timeout.
    pub request_timeout: Duration,
    /// Explicit opt-in to non-loopback binding. Default denies remote
    /// binding; `serve()` refuses non-loopback binds without it.
    pub allow_remote: bool,
}

impl DaemonConfig {
    /// Loopback configuration with an explicit token (tests and the
    /// future lifecycle layer supply the token; nothing here generates or
    /// persists files).
    pub fn local(token: AuthToken) -> Self {
        Self {
            bind: DEFAULT_BIND.parse().expect("loopback literal parses"),
            port: DEFAULT_PORT,
            token,
            body_limit_bytes: DEFAULT_BODY_LIMIT_BYTES,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            allow_remote: false,
        }
    }
}
