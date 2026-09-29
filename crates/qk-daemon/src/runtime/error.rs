//! Typed lifecycle errors. Every startup, status, and stop failure maps
//! to one of these categories with a short secret-free message: no token
//! bytes, no store internals, no raw OS dumps.

use std::fmt::{self, Display, Formatter};

/// Lifecycle failure categories (see `docs/daemon-runtime.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeErrorKind {
    /// CLI/env/default resolution failed.
    Config,
    /// State-directory layout or creation failed.
    Paths,
    /// Token load, validation, generation, or atomic write failed.
    Token,
    /// Another daemon already owns the runtime directory.
    AlreadyRunning,
    /// Singleton lock acquisition or verification failed.
    Lock,
    /// Store open or migration failed.
    Store,
    /// Listener bind failed (including port conflicts).
    Bind,
    /// PID file read, parse, or ownership handling failed.
    Pid,
    /// Log initialization failed.
    Logging,
    /// Shutdown sequencing failed.
    Shutdown,
    /// Control-plane probe failed (connection, timeout, bad body).
    Probe,
    /// Operation unsupported on this platform (e.g. signalling stop).
    Unsupported,
}

/// A lifecycle failure. Never carries secret material: token values stay
/// in [`crate::auth::AuthToken`] (redacted `Debug`) and are never
/// formatted into these messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeError {
    kind: RuntimeErrorKind,
    message: String,
}

impl RuntimeError {
    /// Build an error of the given category.
    pub fn new(kind: RuntimeErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// The failure category.
    pub fn kind(&self) -> &RuntimeErrorKind {
        &self.kind
    }
}

impl Display for RuntimeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let category = match self.kind {
            RuntimeErrorKind::Config => "config",
            RuntimeErrorKind::Paths => "paths",
            RuntimeErrorKind::Token => "token",
            RuntimeErrorKind::AlreadyRunning => "already-running",
            RuntimeErrorKind::Lock => "lock",
            RuntimeErrorKind::Store => "store",
            RuntimeErrorKind::Bind => "bind",
            RuntimeErrorKind::Pid => "pid",
            RuntimeErrorKind::Logging => "logging",
            RuntimeErrorKind::Shutdown => "shutdown",
            RuntimeErrorKind::Probe => "probe",
            RuntimeErrorKind::Unsupported => "unsupported",
        };
        write!(f, "runtime({category}): {}", self.message)
    }
}

impl std::error::Error for RuntimeError {}
