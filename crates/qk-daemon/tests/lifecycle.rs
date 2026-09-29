//! Runtime lifecycle tests: config precedence, startup-phase failures,
//! singleton semantics, graceful shutdown, and end-to-end restart
//! persistence. Each test owns a unique temp home; env-mutating tests
//! serialize on a mutex (cargo runs tests in one process).

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use qk_daemon::runtime::{
    probe_api, run_foreground, status_daemon, stop_daemon, DaemonRuntime, ProbeTarget,
    RuntimeError, RuntimeErrorKind, StatusOutcome, StopOutcome,
};

static ENV_LOCK: Mutex<()> = Mutex::new(());
static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn temp_home(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "qk-lifecycle-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn runtime(home: PathBuf) -> DaemonRuntime {
    // Serialized against the env-mutating tests: resolution reads the
    // process environment, so every resolve takes the guard (briefly,
    // never across awaits). The env tests hold the same guard for their
    // whole body and resolve directly (the mutex is not reentrant).
    let _guard = ENV_LOCK.lock().expect("env lock");
    // Ephemeral port: pid-file port tracking keeps status/stop working.
    DaemonRuntime::with_home(home, Some(0)).expect("resolve")
}

/// Spawn a foreground daemon in-task; returns (join handle, bound addr).
async fn spawn_daemon(
    runtime: DaemonRuntime,
) -> (
    tokio::task::JoinHandle<Result<(), RuntimeError>>,
    tokio::sync::oneshot::Sender<()>,
    std::net::SocketAddr,
) {
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let shutdown = async move {
        let _ = shutdown_rx.await;
    };
    let handle =
        tokio::spawn(async move { run_foreground(&runtime, Some(ready_tx), shutdown).await });
    let addr = tokio::time::timeout(Duration::from_secs(10), ready_rx)
        .await
        .expect("ready timeout")
        .expect("ready sender alive");
    (handle, shutdown_tx, addr)
}

fn target_for(addr: &std::net::SocketAddr) -> ProbeTarget {
    ProbeTarget::new("127.0.0.1", addr.port()).expect("loopback")
}

// ---------------------------------------------------------------------------
// Config precedence.
// ---------------------------------------------------------------------------

#[test]
fn precedence_cli_env_default() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let home = temp_home("precedence");
    std::env::set_var("QUERYKNIGHT_HOME", "/tmp/qk-env-home");
    std::env::set_var("QUERYKNIGHT_PORT", "47999");
    // CLI beats env.
    let runtime = DaemonRuntime::resolve(&qk_daemon::runtime::RuntimeSource {
        home: Some(home.clone()),
        port: Some(1234),
    })
    .expect("resolve");
    assert_eq!(runtime.resolved.paths.home, home);
    assert_eq!(runtime.resolved.port, 1234);
    // Env beats defaults.
    let runtime = DaemonRuntime::resolve(&qk_daemon::runtime::RuntimeSource {
        home: None,
        port: None,
    })
    .expect("resolve");
    assert_eq!(
        runtime.resolved.paths.home,
        PathBuf::from("/tmp/qk-env-home")
    );
    assert_eq!(runtime.resolved.port, 47999);
    assert_eq!(runtime.resolved.probe_url, "http://127.0.0.1:47999");
    // Invalid port is a typed config error, never a panic or default.
    std::env::set_var("QUERYKNIGHT_PORT", "nope");
    let error = DaemonRuntime::resolve(&qk_daemon::runtime::RuntimeSource {
        home: Some(home.clone()),
        port: None,
    })
    .expect_err("bad port");
    assert_eq!(error.kind(), &RuntimeErrorKind::Config);
    std::env::remove_var("QUERYKNIGHT_HOME");
    std::env::remove_var("QUERYKNIGHT_PORT");
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn probe_url_override_and_loopback_rule() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    std::env::set_var("QUERYKNIGHT_DAEMON_URL", "http://127.0.0.1:47000");
    let runtime = DaemonRuntime::resolve(&qk_daemon::runtime::RuntimeSource {
        home: Some(temp_home("url")),
        port: None,
    })
    .expect("resolve");
    assert_eq!(runtime.resolved.probe_url, "http://127.0.0.1:47000");
    std::env::set_var("QUERYKNIGHT_DAEMON_URL", "http://example.com:80");
    DaemonRuntime::resolve(&qk_daemon::runtime::RuntimeSource {
        home: Some(temp_home("url-bad")),
        port: None,
    })
    .expect_err("off-host probe URL must be refused");
    std::env::remove_var("QUERYKNIGHT_DAEMON_URL");
}

// ---------------------------------------------------------------------------
// Startup-phase failures unwind cleanly.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn port_conflict_fails_without_pid_state() {
    let home = temp_home("conflict");
    // Occupy a port with an unrelated listener.
    let squatter = std::net::TcpListener::bind("127.0.0.1:0").expect("squatter");
    let port = squatter.local_addr().expect("addr").port();
    let runtime = DaemonRuntime::with_home(home.clone(), Some(port)).expect("resolve");
    let error = run_foreground(&runtime, None, async {
        // Never resolves; bind must fail first.
        std::future::pending::<()>().await;
    })
    .await
    .expect_err("bind must fail");
    assert_eq!(error.kind(), &RuntimeErrorKind::Bind, "unexpected: {error}");
    // No misleading "running" state, no token clobbering of others.
    assert!(!runtime.resolved.paths.pid.exists());
    assert!(!runtime.resolved.paths.lock.exists());
    drop(squatter);
    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_start_refused_and_keeps_first_pid() {
    let home = temp_home("double");
    let first = runtime(home.clone());
    let (handle, shutdown_tx, _) = spawn_daemon(first).await;
    // Second startup against the same home fails fast at the lock.
    let second = runtime(home.clone());
    let error = run_foreground(&second, None, async {
        std::future::pending::<()>().await;
    })
    .await
    .expect_err("second must fail");
    assert_eq!(
        error.kind(),
        &RuntimeErrorKind::AlreadyRunning,
        "unexpected: {error}"
    );
    // The winner's pid file is untouched by the loser.
    let pid_text = std::fs::read_to_string(&second.resolved.paths.pid).expect("pid intact");
    assert!(pid_text
        .lines()
        .next()
        .is_some_and(|line| line.trim() == std::process::id().to_string()));
    let _ = shutdown_tx.send(());
    handle.await.expect("join").expect("clean shutdown");
    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// Shutdown preserves state and cleans ownership.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_cleans_pid_and_preserves_pending() {
    let home = temp_home("shutdown");
    let daemon = runtime(home.clone());
    let (handle, shutdown_tx, addr) = spawn_daemon(daemon).await;
    let target = target_for(&addr);
    let daemon = runtime(home.clone());
    let token = probe_api::read_token(&daemon.resolved.paths).expect("token contract");
    // Representative approval state through the real HTTP surface.
    let (code, created) = probe_api::post_json(
        &target,
        "/approvals",
        &token,
        &serde_json::json!({
            "fingerprint": "0d2e6c16b5960f15", "reason": "write/high",
            "risk": "high", "operationSummary": "delete customers",
        }),
    )
    .await
    .expect("create");
    assert_eq!(code, 200);
    let approval_id = created["id"].as_str().expect("id").to_owned();

    let _ = shutdown_tx.send(());
    handle.await.expect("join").expect("clean shutdown");

    // Owned lifecycle state is gone.
    assert!(!daemon.resolved.paths.pid.exists());
    assert!(!daemon.resolved.paths.lock.exists());
    // Token and database survive; the store reopens.
    assert!(daemon.resolved.paths.token.exists());
    let store = qk_store::Store::open(&daemon.resolved.paths.database).expect("reopen");
    let grant = store
        .get_grant(&approval_id)
        .expect("read")
        .expect("row survives");
    assert_eq!(grant.status, qk_approval::GrantStatus::Waiting);
    drop(store);
    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_reuses_token_and_keeps_history() {
    let home = temp_home("restart");
    let daemon = runtime(home.clone());
    let (handle, shutdown_tx, addr) = spawn_daemon(daemon).await;
    let target = target_for(&addr);
    let daemon = runtime(home.clone());
    let first_token = probe_api::read_token(&daemon.resolved.paths).expect("token");
    let (code, _) = probe_api::post_json(
        &target,
        "/sessions",
        &first_token,
        &serde_json::json!({"connectionKey": "mysql://qk@127.0.0.1:3307/qk", "source": "mcp"}),
    )
    .await
    .expect("session");
    assert_eq!(code, 200);
    let _ = shutdown_tx.send(());
    handle.await.expect("join").expect("stop");

    // Restart against the same home: same token, history intact.
    let daemon = runtime(home.clone());
    let (handle, shutdown_tx, addr) = spawn_daemon(daemon).await;
    let target = target_for(&addr);
    let daemon = runtime(home.clone());
    let second_token = probe_api::read_token(&daemon.resolved.paths).expect("token");
    assert_eq!(first_token, second_token);
    let (code, sessions) = probe_api::get_json(&target, "/sessions", &second_token)
        .await
        .expect("sessions");
    assert_eq!(code, 200);
    assert_eq!(sessions.as_array().expect("array").len(), 1);
    let _ = shutdown_tx.send(());
    handle.await.expect("join").expect("stop");
    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_start_stop_is_stable() {
    // Flake detector: five full cycles on one home.
    let home = temp_home("repeat");
    for _ in 0..5 {
        let daemon = runtime(home.clone());
        let (handle, shutdown_tx, addr) = spawn_daemon(daemon).await;
        let daemon = runtime(home.clone());
        let probe = daemon.clone();
        let outcome = tokio::task::spawn_blocking(move || status_daemon(&probe))
            .await
            .expect("status task")
            .expect("status");
        assert!(outcome.is_up(), "unexpected: {outcome:?}");
        let _ = target_for(&addr);
        let _ = shutdown_tx.send(());
        handle.await.expect("join").expect("stop");
        assert!(!daemon.resolved.paths.pid.exists());
    }
    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// Status/stop safety.
// ---------------------------------------------------------------------------

#[test]
fn status_down_on_empty_home() {
    let daemon = runtime(temp_home("down"));
    assert_eq!(status_daemon(&daemon).expect("status"), StatusOutcome::Down);
}

#[test]
fn status_stale_pid_is_distinguishable() {
    let home = temp_home("stale");
    let daemon = runtime(home.clone());
    std::fs::create_dir_all(&home).expect("dir");
    // Dead pid, dark probe: stale, not up, not down.
    std::fs::write(&daemon.resolved.paths.pid, "2147483000\n47821\n").expect("plant");
    assert_eq!(
        status_daemon(&daemon).expect("status"),
        StatusOutcome::Stale { pid: 2_147_483_000 }
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn stop_refuses_to_kill_self_or_darkreporter() {
    let home = temp_home("selfkill");
    let daemon = runtime(home.clone());
    std::fs::create_dir_all(&home).expect("dir");
    // Pid file names this very test process with a dark probe: stop must
    // refuse (control plane dark) instead of signalling anything.
    std::fs::write(
        &daemon.resolved.paths.pid,
        format!("{}\n47821\n", std::process::id()),
    )
    .expect("plant");
    let error = stop_daemon(&daemon).expect_err("must refuse");
    assert_eq!(error.kind(), &RuntimeErrorKind::Pid, "unexpected: {error}");
    // And the refusal left the file alone.
    assert!(daemon.resolved.paths.pid.exists());
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn stop_reclaims_stale_pid_file() {
    let home = temp_home("reclaim");
    let daemon = runtime(home.clone());
    std::fs::create_dir_all(&home).expect("dir");
    std::fs::write(&daemon.resolved.paths.pid, "2147483000\n47821\n").expect("plant");
    assert_eq!(
        stop_daemon(&daemon).expect("stop"),
        StopOutcome::StaleReclaimed { pid: 2_147_483_000 }
    );
    assert!(!daemon.resolved.paths.pid.exists());
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn malformed_pid_is_typed_error() {
    let home = temp_home("badpid");
    let daemon = runtime(home.clone());
    std::fs::create_dir_all(&home).expect("dir");
    std::fs::write(&daemon.resolved.paths.pid, "hello\n").expect("plant");
    let error = stop_daemon(&daemon).expect_err("malformed");
    assert_eq!(error.kind(), &RuntimeErrorKind::Pid);
    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// Redaction.
// ---------------------------------------------------------------------------

#[test]
fn errors_and_config_never_carry_token_text() {
    let home = temp_home("redact");
    let daemon = runtime(home.clone());
    std::fs::create_dir_all(&home).expect("dir");
    let token = qk_daemon::runtime::token::load_or_create(&daemon.resolved.paths).expect("token");
    let secret = token.as_secret().to_owned();
    assert_eq!(secret.len(), 32);
    // The resolved runtime debug and every error rendering must not
    // contain the token VALUE (field names like `paths.token` are fine).
    assert!(!format!("{:?}", daemon).contains(&secret));
    // Force a token failure with a directory standing in for the file;
    // the error must not echo anything credential-shaped either.
    let home = temp_home("redact-fail");
    let daemon = runtime(home.clone());
    std::fs::create_dir_all(&home).expect("dir");
    std::fs::create_dir_all(&daemon.resolved.paths.token).expect("plant dir");
    let error =
        qk_daemon::runtime::token::load_or_create(&daemon.resolved.paths).expect_err("must fail");
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains(&secret));
    assert!(!rendered.contains("Bearer"));
    let _ = std::fs::remove_dir_all(&home);
}
