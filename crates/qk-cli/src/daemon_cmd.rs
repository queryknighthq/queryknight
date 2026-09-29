//! `start` / `stop` / `status`: standalone daemon lifecycle commands
//! (frozen reference shape: top-level commands, same output texts).
//!
//! `start --foreground` is the canonical implementation; default `start`
//! is a thin launcher that spawns a detached `start --foreground` child
//! with stdio on `daemon.log` and polls the status probe for readiness.
//! Errors are secret-free by construction (the runtime error type never
//! carries token bytes).

use std::path::PathBuf;
use std::process::Stdio;

use qk_daemon::runtime::{
    run_foreground, status_daemon, stop_daemon, DaemonRuntime, StatusOutcome, StopOutcome,
};
use qk_daemon::runtime::{RuntimeError, RuntimeSource};

/// Bounded readiness polling for the background launcher (reference
/// polls 20x50ms; slightly roomier here for slow CI disks).
const START_ATTEMPTS: usize = 40;
/// Lines of log tail shown when the background daemon fails to start.
const LOG_TAIL_LINES: usize = 15;

fn resolve(home: Option<PathBuf>, port: Option<u16>) -> Result<DaemonRuntime, RuntimeError> {
    DaemonRuntime::resolve(&RuntimeSource { home, port })
}

/// `queryknight start [--port N] [--home DIR] [--foreground]`.
pub fn start(home: Option<PathBuf>, port: Option<u16>, foreground: bool) -> i32 {
    let runtime = match resolve(home.clone(), port) {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("cannot start daemon: {error}");
            return 1;
        }
    };
    if foreground {
        return start_foreground(&runtime);
    }
    start_background(&runtime, home, port)
}

fn start_foreground(runtime: &DaemonRuntime) -> i32 {
    let body = async { run_foreground(runtime, None, shutdown_signal()).await };
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(tokio) => match tokio.block_on(body) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("daemon failed: {error}");
                1
            }
        },
        Err(error) => {
            eprintln!("daemon failed: cannot start async runtime: {error}");
            1
        }
    }
}

/// First of Ctrl-C (all platforms) or SIGTERM (Unix) stops the daemon.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    {
        let mut terminate =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(_) => {
                    ctrl_c.await;
                    return;
                }
            };
        tokio::select! {
            () = ctrl_c => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }
}

fn start_background(runtime: &DaemonRuntime, home: Option<PathBuf>, port: Option<u16>) -> i32 {
    // Fast path: a live probe means already running (the lock is
    // authoritative later; this just keeps the message cheap).
    if qk_daemon::runtime::status_daemon(runtime)
        .is_ok_and(|status| matches!(status, StatusOutcome::Up { .. }))
    {
        println!("daemon already running");
        return 0;
    }
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            eprintln!("cannot start daemon: own executable path unavailable: {error}");
            return 1;
        }
    };
    // The state dir may not exist yet on first start; the foreground
    // child would create it, but the log file must open here.
    if let Err(error) = qk_daemon::runtime::ensure_dirs(&runtime.resolved.paths) {
        eprintln!("cannot start daemon: {error}");
        return 1;
    }
    let log = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&runtime.resolved.paths.log)
    {
        Ok(log) => log,
        Err(error) => {
            eprintln!("cannot start daemon: cannot open log file: {error}");
            return 1;
        }
    };
    let mut command = std::process::Command::new(exe);
    let stdout = log
        .try_clone()
        .map(Stdio::from)
        .unwrap_or_else(|_| Stdio::null());
    command
        .arg("start")
        .arg("--foreground")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::from(log));
    if let Some(home) = home {
        command.arg("--home").arg(home);
    }
    if let Some(port) = port {
        command.arg("--port").arg(port.to_string());
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        // DETACHED_PROCESS so the child outlives the launcher console.
        command.creation_flags(0x00000008);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!("cannot start daemon: spawn failed: {error}");
            return 1;
        }
    };
    // Poll readiness: pid file reveals the bound port (ephemeral runs),
    // then the status probe confirms the daemon answers.
    let control = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(control) => control,
        Err(error) => {
            eprintln!("cannot start daemon: control runtime failed: {error}");
            return 1;
        }
    };
    for _ in 0..START_ATTEMPTS {
        if let Ok(Some(exit)) = child.try_wait() {
            eprintln!(
                "daemon failed to start (exited {exit}); last log lines from {}:\n{}",
                runtime.resolved.paths.log.display(),
                log_tail(&runtime.resolved.paths.log),
            );
            return 1;
        }
        let up = control.block_on(qk_daemon::runtime::status_probed(runtime));
        if up {
            println!(
                "daemon started (log: {})",
                runtime.resolved.paths.log.display()
            );
            // The child outlives us (reparented on Unix, detached on
            // Windows); exiting here must not wait on it.
            std::mem::forget(child);
            return 0;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    eprintln!(
        "daemon failed to start; last log lines from {}:\n{}",
        runtime.resolved.paths.log.display(),
        log_tail(&runtime.resolved.paths.log),
    );
    1
}

fn log_tail(path: &std::path::Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().filter(|line| !line.is_empty()).collect();
    let start = lines.len().saturating_sub(LOG_TAIL_LINES);
    lines[start..].join("\n")
}

/// `queryknight stop [--home DIR] [--port N]`.
pub fn stop(home: Option<PathBuf>, port: Option<u16>) -> i32 {
    let runtime = match resolve(home, port) {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("cannot stop daemon: {error}");
            return 1;
        }
    };
    match stop_daemon(&runtime) {
        Ok(StopOutcome::NotRunning) => {
            println!("daemon not running");
            0
        }
        Ok(StopOutcome::StaleReclaimed { .. }) => {
            println!("daemon not running (stale pid file removed)");
            0
        }
        Ok(StopOutcome::Stopped { .. }) => {
            println!("daemon stopped");
            0
        }
        Err(error) => {
            eprintln!("cannot stop daemon: {error}");
            1
        }
    }
}

/// `queryknight status [--home DIR] [--port N]`.
pub fn status(home: Option<PathBuf>, port: Option<u16>) -> i32 {
    let runtime = match resolve(home, port) {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("cannot query daemon status: {error}");
            return 1;
        }
    };
    match status_daemon(&runtime) {
        Ok(StatusOutcome::Up { pid }) => {
            println!("daemon up pid={pid}");
            0
        }
        Ok(StatusOutcome::Down) => {
            println!("daemon down");
            1
        }
        Ok(StatusOutcome::Stale { pid }) => {
            println!("daemon down (stale pid {pid})");
            1
        }
        Ok(StatusOutcome::Unresponsive { pid }) => {
            println!("daemon unresponsive pid={pid}");
            1
        }
        Err(error) => {
            eprintln!("cannot query daemon status: {error}");
            1
        }
    }
}
