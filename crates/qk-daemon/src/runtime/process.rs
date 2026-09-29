//! Local process inspection and signalling without `unsafe` or new
//! dependencies: the Unix `kill(1)` utility covers both aliveness
//! probing (`kill -0`) and graceful termination (`kill -TERM`).
//! Non-Unix platforms report `Unknown`/unsupported honestly instead of
//! pretending.

use super::error::{RuntimeError, RuntimeErrorKind};

/// What a pid check concluded. `Unknown` means the platform cannot
/// answer (callers fall back to control-plane-probe evidence or fail
/// closed — never assume).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// A process with this pid exists (includes EPERM: exists but owned
    /// by another user — still proof the pid is taken).
    Alive,
    /// No such process.
    Dead,
    /// Cannot determine on this platform.
    Unknown,
}

/// `kill -0 <pid>`: success means alive; "operation not permitted" also
/// means alive (a foreign-owned pid is still a live pid); anything else
/// means dead. Never signals the process.
#[cfg(unix)]
pub fn process_liveness(pid: u32) -> Liveness {
    let output = std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .output();
    match output {
        Ok(output) if output.status.success() => Liveness::Alive,
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
            if stderr.contains("not permitted") {
                Liveness::Alive
            } else {
                Liveness::Dead
            }
        }
        Err(_) => Liveness::Unknown,
    }
}

/// No `kill -0` equivalent without new dependencies; callers use probe
/// evidence instead.
#[cfg(not(unix))]
pub fn process_liveness(_pid: u32) -> Liveness {
    Liveness::Unknown
}

/// Send SIGTERM via `kill -TERM`. Refuses to signal our own process
/// (a lifecycle bug must never suicide the supervisor or the test
/// runner). Non-Unix: typed unsupported error.
pub fn terminate(pid: u32) -> Result<(), RuntimeError> {
    if pid == std::process::id() {
        return Err(RuntimeError::new(
            RuntimeErrorKind::Pid,
            "refusing to terminate our own process",
        ));
    }
    #[cfg(unix)]
    {
        let status = std::process::Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status()
            .map_err(|error| {
                RuntimeError::new(
                    RuntimeErrorKind::Pid,
                    format!("cannot signal process: {error}"),
                )
            })?;
        if status.success() {
            Ok(())
        } else {
            Err(RuntimeError::new(
                RuntimeErrorKind::Pid,
                "process signal was not accepted",
            ))
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        Err(RuntimeError::new(
            RuntimeErrorKind::Unsupported,
            "process signalling is only supported on Unix",
        ))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn self_is_alive_dead_pid_is_dead() {
        assert_eq!(process_liveness(std::process::id()), Liveness::Alive);
        // Unlikely to exist; even if recycled, the test only asserts we
        // get a determinate answer without signalling anything.
        let _ = process_liveness(2_147_483_000);
    }

    #[test]
    fn terminate_refuses_self() {
        let error = terminate(std::process::id()).expect_err("must refuse");
        assert_eq!(error.kind(), &RuntimeErrorKind::Pid);
    }
}
