//! Runtime directory layout and configuration precedence.
//!
//! Frozen layout (`<home>/` = `QUERYKNIGHT_HOME` or `~/.queryknight`):
//! `queryknight.db`, `session.token`, `daemon.pid`, `daemon.lock`,
//! `daemon.log`. Precedence is CLI flags > environment > defaults,
//! resolved once at startup; handlers never read the environment.

use std::path::PathBuf;

use super::error::{RuntimeError, RuntimeErrorKind};

/// Environment overrides (frozen names).
pub const ENV_HOME: &str = "QUERYKNIGHT_HOME";
/// Environment overrides (frozen names).
pub const ENV_PORT: &str = "QUERYKNIGHT_PORT";
/// Environment overrides (frozen names).
pub const ENV_DAEMON_URL: &str = "QUERYKNIGHT_DAEMON_URL";

/// Frozen filenames inside the state directory.
pub const DATABASE_FILE: &str = "queryknight.db";
/// Frozen filenames inside the state directory.
pub const TOKEN_FILE: &str = "session.token";
/// Frozen filenames inside the state directory.
pub const PID_FILE: &str = "daemon.pid";
/// Singleton ownership file (Rust hardening, see `singleton`).
pub const LOCK_FILE: &str = "daemon.lock";
/// Frozen filenames inside the state directory.
pub const LOG_FILE: &str = "daemon.log";

/// CLI-supplied overrides. `None` means "fall through to env/defaults".
#[derive(Debug, Clone, Default)]
pub struct RuntimeSource {
    /// `--home DIR` override.
    pub home: Option<PathBuf>,
    /// `--port N` override (`0` selects an ephemeral port; tests only).
    pub port: Option<u16>,
}

/// Fully resolved runtime configuration. No further env reads happen
/// after this is built.
#[derive(Debug, Clone)]
pub struct ResolvedRuntime {
    /// State-directory file layout.
    pub paths: RuntimePaths,
    /// TCP port to bind (or probe).
    pub port: u16,
    /// Client probe base URL (frozen `QUERYKNIGHT_DAEMON_URL` semantics).
    pub probe_url: String,
}

/// Centralized state-directory layout. No handler constructs these.
#[derive(Debug, Clone)]
pub struct RuntimePaths {
    /// State directory root.
    pub home: PathBuf,
    /// SQLite store file.
    pub database: PathBuf,
    /// Bearer token file.
    pub token: PathBuf,
    /// Compatibility pid file.
    pub pid: PathBuf,
    /// Singleton lock file.
    pub lock: PathBuf,
    /// Operational log file.
    pub log: PathBuf,
}

impl RuntimePaths {
    /// Derive every runtime path from the state-directory root.
    pub fn new(home: PathBuf) -> Self {
        Self {
            database: home.join(DATABASE_FILE),
            token: home.join(TOKEN_FILE),
            pid: home.join(PID_FILE),
            lock: home.join(LOCK_FILE),
            log: home.join(LOG_FILE),
            home,
        }
    }
}

/// Resolve home, port, and probe URL: CLI > env > defaults.
pub fn resolve(source: &RuntimeSource) -> Result<ResolvedRuntime, RuntimeError> {
    let home = match source.home.clone() {
        Some(home) => home,
        None => match std::env::var_os(ENV_HOME) {
            Some(home) => PathBuf::from(home),
            None => default_home()?,
        },
    };
    let port = match source.port {
        Some(port) => port,
        None => match std::env::var(ENV_PORT) {
            Ok(raw) => raw.parse::<u16>().map_err(|_| {
                RuntimeError::new(
                    RuntimeErrorKind::Config,
                    format!("{ENV_PORT} is not a valid port"),
                )
            })?,
            Err(std::env::VarError::NotPresent) => crate::config::DEFAULT_PORT,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(RuntimeError::new(
                    RuntimeErrorKind::Config,
                    format!("{ENV_PORT} is not valid unicode"),
                ));
            }
        },
    };
    let probe_url = match std::env::var(ENV_DAEMON_URL) {
        Ok(url) => url,
        Err(std::env::VarError::NotPresent) => format!("http://127.0.0.1:{port}"),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(RuntimeError::new(
                RuntimeErrorKind::Config,
                format!("{ENV_DAEMON_URL} is not valid unicode"),
            ));
        }
    };
    Ok(ResolvedRuntime {
        paths: RuntimePaths::new(home),
        port,
        probe_url,
    })
}

fn default_home() -> Result<PathBuf, RuntimeError> {
    // No home-dir crate (dependency discipline): POSIX HOME, Windows
    // USERPROFILE, matching the reference `os.homedir()` behavior closely
    // enough for a state-directory default.
    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home).join(".queryknight"));
    }
    #[cfg(windows)]
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        return Ok(PathBuf::from(profile).join(".queryknight"));
    }
    Err(RuntimeError::new(
        RuntimeErrorKind::Config,
        "cannot determine home directory; set QUERYKNIGHT_HOME or pass --home",
    ))
}

/// Create the state directory with restrictive permissions where the
/// platform supports them. A pre-existing directory is never chmodded:
/// QueryKnight must not weaken or touch user-owned parents — only a
/// directory it just created gets `0700` on Unix.
pub fn ensure_dirs(paths: &RuntimePaths) -> Result<bool, RuntimeError> {
    match std::fs::create_dir(&paths.home) {
        Ok(()) => {
            restrict_dir(&paths.home)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Missing parents (unusual): create the chain, then restrict
            // the leaf, which is guaranteed new in this branch.
            std::fs::create_dir_all(&paths.home).map_err(|error| {
                RuntimeError::new(
                    RuntimeErrorKind::Paths,
                    format!("cannot create state directory: {error}"),
                )
            })?;
            restrict_dir(&paths.home)?;
            Ok(true)
        }
        Err(error) => Err(RuntimeError::new(
            RuntimeErrorKind::Paths,
            format!("cannot create state directory: {error}"),
        )),
    }
}

#[cfg(unix)]
fn restrict_dir(dir: &std::path::Path) -> Result<(), RuntimeError> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|error| {
        RuntimeError::new(
            RuntimeErrorKind::Paths,
            format!("cannot restrict state directory permissions: {error}"),
        )
    })
}

#[cfg(not(unix))]
fn restrict_dir(_dir: &std::path::Path) -> Result<(), RuntimeError> {
    // No POSIX permission bits; documented in daemon-runtime.md.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_dir_gets_restricted_perms() {
        let dir = std::env::temp_dir().join(format!(
            "qk-runtime-paths-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let paths = RuntimePaths::new(dir.clone());
        assert!(ensure_dirs(&paths).expect("create"));
        assert!(!ensure_dirs(&paths).expect("idempotent"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&dir).expect("meta").permissions().mode() & 0o777,
                0o700
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
