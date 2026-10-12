//! Real-binary daemon lifecycle tests: `start` (background launcher),
//! `status`, `stop`, double-start refusal, and stale/malformed pid
//! handling. Each test owns a temp home and a freed ephemeral port.

use std::path::PathBuf;
use std::time::Duration;

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt as _;

static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn temp_home(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "qk-cli-daemon-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("ephemeral")
        .local_addr()
        .expect("addr")
        .port()
}

/// `queryknight <sub> --home H [--port P]` with a hermetic environment.
fn base(sub: &str, home: &PathBuf, port: Option<u16>) -> Command {
    let mut command = Command::cargo_bin("queryknight").expect("binary");
    command.env_remove("QUERYKNIGHT_HOME");
    command.env_remove("QUERYKNIGHT_PORT");
    command.env_remove("QUERYKNIGHT_DAEMON_URL");
    command.arg(sub).arg("--home").arg(home);
    if let Some(port) = port {
        command.arg("--port").arg(port.to_string());
    }
    command.timeout(Duration::from_secs(20));
    command
}

fn start(home: &PathBuf, port: u16) -> Command {
    base("start", home, Some(port))
}

fn wait_for_status(home: &PathBuf, port: u16, expect_up: bool) {
    for _ in 0..100 {
        let output = base("status", home, Some(port))
            .output()
            .expect("status runs");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let up = stdout.contains("daemon up");
        if up == expect_up {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("status did not become up={expect_up}");
}

#[test]
fn background_lifecycle() {
    let home = temp_home("bg");
    let port = free_port();
    // Down before start (exit 1, frozen text).
    base("status", &home, Some(port))
        .assert()
        .failure()
        .stdout(predicates::str::contains("daemon down"));
    // Start in background.
    start(&home, port)
        .assert()
        .success()
        .stdout(predicates::str::contains("daemon started"));
    wait_for_status(&home, port, true);
    // Second start is refused without touching the first instance.
    start(&home, port)
        .assert()
        .success()
        .stdout(predicates::str::contains("daemon already running"));
    // Token file exists with restrictive permissions (Unix).
    let token = std::fs::read_to_string(home.join("session.token")).expect("token file");
    assert_eq!(token.trim().len(), 32);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(home.join("session.token"))
                .expect("meta")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    // Stop terminates the verified daemon and cleans up.
    base("stop", &home, Some(port))
        .assert()
        .success()
        .stdout(predicates::str::contains("daemon stopped"));
    wait_for_status(&home, port, false);
    assert!(!home.join("daemon.pid").exists());
    assert!(!home.join("daemon.lock").exists());
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn stop_without_daemon_is_quiet_success() {
    let home = temp_home("nostop");
    let port = free_port();
    base("stop", &home, Some(port))
        .assert()
        .success()
        .stdout(predicates::str::contains("daemon not running"));
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn stale_pid_reports_down_and_stop_reclaims() {
    let home = temp_home("stale");
    let port = free_port();
    std::fs::create_dir_all(&home).expect("dir");
    std::fs::write(home.join("daemon.pid"), "2147483000\n47821\n").expect("plant");
    base("status", &home, Some(port))
        .assert()
        .failure()
        .stdout(predicates::str::contains("daemon down").and(predicates::str::contains("stale")));
    base("stop", &home, Some(port))
        .assert()
        .success()
        .stdout(predicates::str::contains("stale pid file removed"));
    assert!(!home.join("daemon.pid").exists());
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn malformed_pid_is_an_error() {
    let home = temp_home("badpid");
    let port = free_port();
    std::fs::create_dir_all(&home).expect("dir");
    std::fs::write(home.join("daemon.pid"), "garbage\n").expect("plant");
    base("status", &home, Some(port)).assert().failure();
    base("stop", &home, Some(port)).assert().failure();
    // Nothing was killed, nothing was deleted.
    assert!(home.join("daemon.pid").exists());
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn existing_commands_unchanged() {
    // The lifecycle wiring must not disturb the frozen policy surface.
    Command::cargo_bin("queryknight")
        .expect("binary")
        .arg("version")
        .assert()
        .success()
        .stdout(predicates::str::contains("QueryKnight 0.1.0"));
}
