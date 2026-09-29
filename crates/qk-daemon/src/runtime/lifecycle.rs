//! Foreground daemon pipeline plus `stop`/`status` control operations.
//!
//! Canonical startup order (pid is published only after the listener is
//! bound, so "started" always means accepting requests):
//!
//! ```text
//! resolve -> ensure dirs -> logging -> singleton lock -> token
//!   -> open/migrate store -> bind -> write pid -> serve
//!   -> drain -> release store -> remove owned pid/lock
//! ```
//!
//! The lock precedes token creation deliberately: two concurrent first
//! starts must not race the token file (the lock winner's token is the
//! file's token). Any phase failure unwinds only resources owned by this
//! startup. Lifecycle code starts already-tested components and never
//! implements policy, approval, or SQL semantics.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;

use crate::auth::AuthToken;
use crate::config::DaemonConfig;
use crate::state::DaemonState;

use super::error::{RuntimeError, RuntimeErrorKind};
use super::logging::init_logging;
use super::paths::{ensure_dirs, resolve, ResolvedRuntime, RuntimeSource};
use super::probe::{probe_get, probe_post, probe_status, ProbeTarget, PROBE_TIMEOUT};
use super::process::{process_liveness, terminate, Liveness};
use super::singleton::{acquire, read_pid, remove_pid_if_owned, write_pid, PidRecord};
use super::token::load_or_create;

/// How long `stop` waits for the probe to go dark after SIGTERM.
const STOP_WAIT: Duration = Duration::from_secs(5);
/// Probe poll interval for `start` readiness and `stop` waiting.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Fully resolved daemon runtime: paths, ports, and probe target.
#[derive(Debug, Clone)]
pub struct DaemonRuntime {
    /// Resolved paths/ports/URL.
    pub resolved: ResolvedRuntime,
    /// Loopback probe target for this instance.
    pub target: ProbeTarget,
    /// Explicit CLI `--port` (beats the pid-file port for probes).
    cli_port: Option<u16>,
}

impl DaemonRuntime {
    /// Resolve CLI > env > defaults once. No env reads after this.
    pub fn resolve(source: &RuntimeSource) -> Result<Self, RuntimeError> {
        let resolved = resolve(source)?;
        let target = ProbeTarget::from_url(&resolved.probe_url)?;
        Ok(Self {
            resolved,
            target,
            // Port 0 means "ephemeral bind" (tests only), never an
            // explicit probe port.
            cli_port: source.port.filter(|port| *port != 0),
        })
    }

    /// Port for control-plane probes: explicit CLI `--port` first, then
    /// the pid file's recorded port (ephemeral runs), then the resolved
    /// port (env/default/URL).
    fn probe_port(&self, record: Option<PidRecord>) -> u16 {
        self.cli_port
            .or_else(|| record.map(|record| record.port))
            .unwrap_or(self.resolved.port)
    }

    /// Shortcut for tests and the CLI: explicit home plus optional port.
    pub fn with_home(home: std::path::PathBuf, port: Option<u16>) -> Result<Self, RuntimeError> {
        Self::resolve(&RuntimeSource {
            home: Some(home),
            port,
        })
    }
}

/// Run the daemon in the foreground until `shutdown` resolves: the
/// canonical implementation; background mode is a thin launcher around
/// an equivalent entrypoint. `ready` receives the bound address once the
/// listener is held (before serving), so supervisors never report
/// "started" early.
pub async fn run_foreground(
    runtime: &DaemonRuntime,
    ready: Option<oneshot::Sender<std::net::SocketAddr>>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), RuntimeError> {
    let paths = &runtime.resolved.paths;
    ensure_dirs(paths)?;
    let log = init_logging(&paths.log, true)?;
    install_global_dispatcher(log);
    // The lock releases exactly once here (ownership-checked) — a
    // failed startup in a live process must never block its own retry.
    let lock = acquire(paths)?;
    tracing::info!("runtime lock acquired");
    let outcome = run_guarded(runtime, ready, shutdown).await;
    let _ = lock.release();
    outcome
}

/// Install the operational subscriber process-wide (first call wins).
/// A scoped dispatcher cannot work here: `with_default` only covers the
/// synchronous closure body, not the daemon future's awaits across
/// threads. Production starts once per process, so first-wins is exact;
/// in tests the losers still create their own log files (only event
/// routing is shared), and no test asserts cross-run log content.
fn install_global_dispatcher(log: super::logging::OpLog) {
    static INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INSTALLED.get_or_init(|| {
        let _ = tracing::dispatcher::set_global_default(tracing::dispatcher::Dispatch::new(log));
    });
}

async fn run_guarded(
    runtime: &DaemonRuntime,
    ready: Option<oneshot::Sender<std::net::SocketAddr>>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), RuntimeError> {
    let paths = &runtime.resolved.paths;
    tracing::info!(home = %paths.home.display(), "daemon starting");
    // The caller holds the singleton lock: this body owns token
    // creation (no two first-starts can race the token file).
    let token: AuthToken = load_or_create(paths)?;
    let store = open_store(paths)?;
    let mut config = DaemonConfig::local(token);
    config.bind = crate::config::DEFAULT_BIND
        .parse()
        .expect("loopback literal");
    config.port = runtime.resolved.port;
    let state = DaemonState::new(Arc::new(store));
    let listener = crate::server::bind_listener(&config)
        .await
        .map_err(|error| {
            // Unwind owned state: no pid was written yet; the lock releases
            // on drop. Report the bind clearly without touching pid/token.
            RuntimeError::new(RuntimeErrorKind::Bind, daemon_detail(error))
        })?;
    let addr = listener.local_addr().map_err(|error| {
        RuntimeError::new(
            RuntimeErrorKind::Bind,
            format!("cannot read bound address: {error}"),
        )
    })?;
    let pid_record = PidRecord {
        pid: std::process::id(),
        port: addr.port(),
    };
    write_pid(paths, pid_record)?;
    tracing::info!(
        port = addr.port(),
        pid = std::process::id(),
        "daemon listening"
    );
    if let Some(ready) = ready {
        let _ = ready.send(addr);
    }
    let app = crate::server::router(state, config.token.clone());
    let serve_result = crate::server::serve_listener(listener, app, shutdown).await;
    // Graceful unwind, ownership-checked: only remove a pid file that
    // still names this instance (the lock releases in the caller).
    let _ = remove_pid_if_owned(paths, pid_record);
    serve_result
        .map_err(|error| RuntimeError::new(RuntimeErrorKind::Shutdown, daemon_detail(error)))?;
    tracing::info!("daemon stopping; connections drained");
    tracing::info!("daemon stopped");
    Ok(())
}

/// Short operational detail from a server error (bind/serve failures
/// carry OS text, never secrets; safe for CLI output and logs).
fn daemon_detail(error: crate::DaemonError) -> String {
    match error {
        crate::DaemonError::Internal(detail) => detail,
        other => format!("{other:?}"),
    }
}

fn open_store(paths: &super::paths::RuntimePaths) -> Result<qk_store::Store, RuntimeError> {
    qk_store::Store::open(&paths.database)
        .map_err(|error| RuntimeError::new(RuntimeErrorKind::Store, format!("{error}")))
}

/// Outcome of a `stop` attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopOutcome {
    /// No pid file: nothing to stop.
    NotRunning,
    /// Stale pid file reclaimed (dead pid, file removed).
    StaleReclaimed {
        /// The dead pid that was recorded.
        pid: u32,
    },
    /// Verified-own daemon terminated and probe went dark.
    Stopped {
        /// The terminated pid.
        pid: u32,
    },
}

/// Outcome of a `status` query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusOutcome {
    /// Probe answered and agrees with the pid file (or no pid file but
    /// a live probe — e.g. ephemeral-port runs).
    Up {
        /// The live daemon pid.
        pid: u32,
    },
    /// Nothing responds and no pid file claims otherwise.
    Down,
    /// Pid file names a dead process.
    Stale {
        /// The dead recorded pid.
        pid: u32,
    },
    /// A live process holds the pid but the probe is dark (starting up,
    /// wedged, or a foreign process reusing the pid).
    Unresponsive {
        /// The recorded pid.
        pid: u32,
    },
}

impl StatusOutcome {
    /// True when a live daemon answered the probe.
    pub fn is_up(&self) -> bool {
        matches!(self, Self::Up { .. })
    }
}

/// Async status query for callers that already run inside a Tokio
/// runtime (the background-launcher poll loop); the sync [`status_daemon`]
/// wrapper is for one-shot CLI use.
pub async fn status_probed(runtime: &DaemonRuntime) -> bool {
    status_daemon_async(runtime)
        .await
        .is_ok_and(|status| status.is_up())
}

/// Stop the daemon that owns `runtime`'s home: verify ownership (pid
/// alive AND probe reports the same pid), SIGTERM, bounded wait for the
/// probe to go dark, then remove the pid file only if still owned. Never
/// kills a pid it does not own. Runs its own short-lived runtime for
/// the blocking probe waits.
pub fn stop_daemon(runtime: &DaemonRuntime) -> Result<StopOutcome, RuntimeError> {
    let runtime_handle = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            RuntimeError::new(
                RuntimeErrorKind::Shutdown,
                format!("cannot start control runtime: {error}"),
            )
        })?;
    runtime_handle.block_on(stop_daemon_async(runtime))
}

async fn stop_daemon_async(runtime: &DaemonRuntime) -> Result<StopOutcome, RuntimeError> {
    let paths = &runtime.resolved.paths;
    let record = match read_pid(paths)? {
        None => return Ok(StopOutcome::NotRunning),
        Some(record) => record,
    };
    match process_liveness(record.pid) {
        Liveness::Dead => {
            remove_pid_if_owned(paths, record)?;
            return Ok(StopOutcome::StaleReclaimed { pid: record.pid });
        }
        Liveness::Unknown => {
            return Err(RuntimeError::new(
                RuntimeErrorKind::Pid,
                "cannot verify daemon liveness on this platform; refusing to signal",
            ));
        }
        Liveness::Alive => {}
    }
    // Ownership: the control plane must confirm this pid is QueryKnight.
    let target = probe_target_for(&runtime.target, runtime.probe_port(Some(record)));
    match probe_status(&target, PROBE_TIMEOUT).await {
        Ok(probe) if probe.pid == record.pid => {}
        Ok(probe) => {
            return Err(RuntimeError::new(
                RuntimeErrorKind::Pid,
                format!(
                    "pid file names {} but the daemon there reports {}; refusing to signal",
                    record.pid, probe.pid
                ),
            ));
        }
        Err(_) => {
            return Err(RuntimeError::new(
                RuntimeErrorKind::Pid,
                format!(
                    "process {} is alive but the control plane is dark; refusing to signal",
                    record.pid
                ),
            ));
        }
    }
    terminate(record.pid)?;
    // Bounded wait for the probe to go dark; no SIGKILL escalation (a
    // wedged daemon is reported, not force-killed from a script).
    let deadline = tokio::time::Instant::now() + STOP_WAIT;
    loop {
        if probe_status(&target, PROBE_TIMEOUT).await.is_err() {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(RuntimeError::new(
                RuntimeErrorKind::Shutdown,
                format!("process {} ignored SIGTERM; still responding", record.pid),
            ));
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    remove_pid_if_owned(paths, record)?;
    Ok(StopOutcome::Stopped { pid: record.pid })
}

/// Query daemon state from pid-file evidence plus the control-plane
/// probe. Never requires database execution.
pub fn status_daemon(runtime: &DaemonRuntime) -> Result<StatusOutcome, RuntimeError> {
    let runtime_handle = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            RuntimeError::new(
                RuntimeErrorKind::Shutdown,
                format!("cannot start control runtime: {error}"),
            )
        })?;
    runtime_handle.block_on(status_daemon_async(runtime))
}

async fn status_daemon_async(runtime: &DaemonRuntime) -> Result<StatusOutcome, RuntimeError> {
    let record = read_pid(&runtime.resolved.paths)?;
    // Probe first: a live probe is authoritative about "up".
    let target = probe_target_for(&runtime.target, runtime.probe_port(record));
    let probe = probe_status(&target, PROBE_TIMEOUT).await.ok();
    match (record, probe) {
        (Some(record), Some(probe)) if probe.pid == record.pid => {
            Ok(StatusOutcome::Up { pid: record.pid })
        }
        (Some(record), Some(probe)) => {
            // Probe answers but disagrees: the pid file is stale and some
            // (foreign or restarted) daemon answers. Report by probe.
            let _ = record;
            Ok(StatusOutcome::Up { pid: probe.pid })
        }
        (None, Some(probe)) => Ok(StatusOutcome::Up { pid: probe.pid }),
        (Some(record), None) => match process_liveness(record.pid) {
            Liveness::Dead => Ok(StatusOutcome::Stale { pid: record.pid }),
            _ => Ok(StatusOutcome::Unresponsive { pid: record.pid }),
        },
        (None, None) => Ok(StatusOutcome::Down),
    }
}

/// The probe target, but on the pid file's port when one is recorded
/// (ephemeral-port runs): keeps `status`/`stop` working without `--port`.
fn probe_target_for(target: &ProbeTarget, port: u16) -> ProbeTarget {
    ProbeTarget::new(target.host(), port).expect("loopback target stays loopback")
}

/// Authenticated lifecycle helpers for end-to-end tests (thin probe
/// wrappers, not a general SDK).
pub mod probe_api {
    use super::*;

    /// Authenticated GET returning status plus parsed JSON.
    pub async fn get_json(
        target: &ProbeTarget,
        path: &str,
        token: &AuthToken,
    ) -> Result<(u16, serde_json::Value), RuntimeError> {
        let (code, body) = probe_get(target, path, Some(token), PROBE_TIMEOUT).await?;
        let value: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|_| RuntimeError::new(RuntimeErrorKind::Probe, "response is not JSON"))?;
        Ok((code, value))
    }

    /// Authenticated POST of a JSON body, returning status plus parsed JSON.
    pub async fn post_json(
        target: &ProbeTarget,
        path: &str,
        token: &AuthToken,
        body: &serde_json::Value,
    ) -> Result<(u16, serde_json::Value), RuntimeError> {
        let (code, raw) = probe_post(target, path, token, &body.to_string(), PROBE_TIMEOUT).await?;
        let value: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|_| RuntimeError::new(RuntimeErrorKind::Probe, "response is not JSON"))?;
        Ok((code, value))
    }

    /// Read the persisted bearer token (the documented client contract).
    pub fn read_token(
        paths: &crate::runtime::paths::RuntimePaths,
    ) -> Result<AuthToken, RuntimeError> {
        let bytes = crate::runtime::token::read_token_raw(&paths.token)?;
        let text = String::from_utf8(bytes).map_err(|_| {
            RuntimeError::new(RuntimeErrorKind::Token, "token file is not valid UTF-8")
        })?;
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(RuntimeError::new(
                RuntimeErrorKind::Token,
                "token file is empty",
            ));
        }
        Ok(AuthToken::new(trimmed.to_owned()))
    }
}
