//! Standalone daemon runtime: state directory, bearer-token file,
//! singleton ownership, operational logging, graceful shutdown, and the
//! `stop`/`status` control operations.
//!
//! This layer turns the frozen control-plane router (`crate::server`)
//! into a real process. It never reimplements HTTP/auth semantics and
//! never touches policy, approval, or SQL logic — it starts
//! already-tested components. Contract: `docs/daemon-runtime.md`.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod lifecycle;
pub mod logging;
pub mod paths;
pub mod probe;
pub mod process;
pub mod singleton;
pub mod token;

pub use error::{RuntimeError, RuntimeErrorKind};
pub use lifecycle::{
    probe_api, run_foreground, status_daemon, status_probed, stop_daemon, DaemonRuntime,
    StatusOutcome, StopOutcome,
};
pub use paths::{ensure_dirs, ResolvedRuntime, RuntimePaths, RuntimeSource};
pub use probe::ProbeTarget;
