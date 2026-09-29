use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::oneshot;

type DaemonTask = tokio::task::JoinHandle<Result<(), qk_daemon::runtime::RuntimeError>>;

struct TestDaemon {
    home: PathBuf,
    addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<DaemonTask>,
}

impl TestDaemon {
    async fn start() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let index = NEXT.fetch_add(1, Ordering::Relaxed);
        let home =
            std::env::temp_dir().join(format!("qk-control-plane-{}-{index}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).expect("create daemon home");
        let runtime =
            qk_daemon::runtime::DaemonRuntime::with_home(home.clone(), Some(0)).expect("runtime");
        let (ready_tx, ready_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            qk_daemon::runtime::run_foreground(&runtime, Some(ready_tx), async move {
                let _ = shutdown_rx.await;
            })
            .await
        });
        let addr = tokio::time::timeout(Duration::from_secs(10), ready_rx)
            .await
            .expect("daemon readiness timeout")
            .expect("daemon address");
        Self {
            home,
            addr,
            shutdown: Some(shutdown_tx),
            task: Some(task),
        }
    }

    fn client(&self) -> ControlPlaneClient {
        ControlPlaneClient::discover_with_url(Some(self.home.clone()), None)
            .expect("discover isolated daemon")
    }

    async fn stop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.await.expect("daemon task").expect("clean daemon stop");
        }
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn scope(session_id: Option<String>) -> qk_approval::ApprovalScope {
    qk_approval::ApprovalScope {
        session_id,
        integration: "proxy_pg".to_owned(),
        environment: "production".to_owned(),
        database: "main".to_owned(),
        agent_id: String::new(),
        tool: "db_query".to_owned(),
    }
}

fn approval_request(sql: &str, session_id: Option<String>, value: &[u8]) -> ApprovalRequest {
    let exact = qk_core::exact_request_digest_v2(
        qk_sql::SqlDialect::PostgreSql,
        sql,
        &[qk_core::ExecutionParam::Wire {
            representation: qk_core::ParamRepresentation::Binary,
            type_hint: Some(23),
            bytes: value.to_vec(),
        }],
    )
    .expect("bounded exact request");
    ApprovalRequest {
        fingerprint: qk_core::sql_fingerprint(sql),
        scope: scope(session_id),
        reason_code: qk_core::ReasonCode::RequireApproval,
        message: "approval required".to_owned(),
        matched_policy: None,
        table: Some("customers".to_owned()),
        column: None,
        operation: Some("delete".to_owned()),
        exact: ExactDigest::V2(exact),
    }
}

#[test]
fn url_and_debug_fail_closed_without_exposing_token() {
    assert_eq!(daemon_url_port("http://127.0.0.1:47821"), Ok(47821));
    assert_eq!(daemon_url_port("http://localhost:1"), Ok(1));
    assert_eq!(
        daemon_url_port("http://192.168.1.2:4"),
        Err(ControlPlaneError::NonLoopback)
    );
    assert_eq!(
        daemon_url_port("http://example.com:4"),
        Err(ControlPlaneError::NonLoopback)
    );
    assert_eq!(
        daemon_url_port("https://127.0.0.1:4"),
        Err(ControlPlaneError::InvalidUrl)
    );
    let client = ControlPlaneClient {
        addr: SocketAddr::from(([127, 0, 0, 1], 1)),
        token: qk_daemon::AuthToken::new("DAEMON_CONTROL_SECRET_12345".to_owned()),
    };
    assert!(!format!("{client:?}").contains("DAEMON_CONTROL_SECRET_12345"));
    let provider = DaemonApprovalProvider::new(client, None, "connection".to_owned(), None);
    assert!(!format!("{provider:?}").contains("DAEMON_CONTROL_SECRET_12345"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn separate_runtime_homes_do_not_share_client_state() {
    let mut first = TestDaemon::start().await;
    let mut second = TestDaemon::start().await;
    let first_client = first.client();
    let second_client = second.client();
    let first_session = first_client.create_session("db-one", "test").unwrap();
    let second_session = second_client.create_session("db-two", "test").unwrap();
    assert!(!first_session.is_empty());
    assert!(!second_session.is_empty());
    assert_ne!(first_session, second_session);
    let provider =
        DaemonApprovalProvider::new(first_client.clone(), None, "db-one".to_owned(), None);
    let request = approval_request("DELETE FROM t WHERE id = $1", None, b"1");
    assert_eq!(
        provider.request(&request).unwrap().decision,
        ProviderDecision::Waiting
    );
    assert_eq!(first_client.list_approvals().unwrap().len(), 1);
    assert!(second_client.list_approvals().unwrap().is_empty());
    assert_ne!(first.addr.port(), second.addr.port());

    // An invalid explicit target is rejected, never replaced by the pid port.
    assert_eq!(
        ControlPlaneClient::discover_with_url(
            Some(first.home.clone()),
            Some("http://192.168.1.5:47821"),
        )
        .err(),
        Some(ControlPlaneError::NonLoopback)
    );
    first.stop().await;
    second.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_daemon_exact_v2_once_session_and_scope_semantics() {
    let mut daemon = TestDaemon::start().await;
    let client = daemon.client();
    let session_id = client
        .create_session("postgres://user@localhost/db", "proxy_pg")
        .unwrap();
    let sql = "DELETE FROM customers WHERE id = $1";
    let first = approval_request(sql, Some(session_id.clone()), b"42");
    let provider = DaemonApprovalProvider::new(
        client.clone(),
        Some(session_id.clone()),
        "postgres://user@localhost/db".to_owned(),
        None,
    );
    let pending = provider.request(&first).unwrap();
    assert_eq!(pending.decision, ProviderDecision::Waiting);
    let row = client.approval(&pending.id).unwrap();
    assert_eq!(row.status, ApprovalStatus::Waiting);
    assert_eq!(row.binding_kind, ApprovalBindingKind::ExactV2);
    assert_eq!(
        client
            .decide_approval(
                pending.id.as_str(),
                ApprovalDecision::Approved,
                qk_approval::DecisionSource::Ui,
                Some(qk_approval::Scope::Once),
            )
            .unwrap(),
        ApprovalDecisionStatus::Approved
    );

    let retry = DaemonApprovalProvider::new(
        client.clone(),
        Some(session_id.clone()),
        "postgres://user@localhost/db".to_owned(),
        Some(pending.id.as_str().to_owned()),
    );
    assert_eq!(
        retry.request(&first).unwrap().decision,
        ProviderDecision::Approved
    );

    // PostgreSQL Simple Query carries no approvalId field. The shared
    // provider can recover an exact Once retry by candidate shape followed
    // by daemon exact-digest/scope verification, without local caching.
    let wire_provider = DaemonApprovalProvider::new(
        client.clone(),
        Some(session_id.clone()),
        "postgres://user@localhost/db".to_owned(),
        None,
    )
    .with_exact_lookup_retry();
    assert_eq!(
        wire_provider.request(&first).unwrap().decision,
        ProviderDecision::Approved
    );

    // Regression for shape-only approval laundering and candidate ordering:
    // this newer approved digest must not hide the older exact grant.
    let changed = approval_request(sql, Some(session_id.clone()), b"43");
    assert_eq!(
        retry.request(&changed).unwrap().decision,
        ProviderDecision::Waiting
    );
    let changed_pending = wire_provider.request(&changed).unwrap();
    assert_eq!(changed_pending.decision, ProviderDecision::Waiting);
    client
        .decide_approval(
            changed_pending.id.as_str(),
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Once),
        )
        .unwrap();
    assert_eq!(
        wire_provider.request(&first).unwrap().decision,
        ProviderDecision::Approved
    );
    assert_eq!(
        wire_provider.request(&changed).unwrap().decision,
        ProviderDecision::Approved
    );

    // All trusted dimensions are sent to the daemon verifier. A different
    // environment cannot reuse this Once grant.
    let mut wrong_scope = first.clone();
    wrong_scope.scope.environment = "staging".to_owned();
    assert_eq!(
        retry.request(&wrong_scope).unwrap().decision,
        ProviderDecision::Waiting
    );

    // Explicit Session decision authorizes a different ExactV2 request of
    // the same shape; the provider still gives qk-approval a new response.
    let session_sql = "DELETE FROM customers WHERE id = $1";
    let session_first = approval_request(session_sql, Some(session_id.clone()), b"7");
    let session_pending = provider.request(&session_first).unwrap();
    assert_eq!(session_pending.decision, ProviderDecision::Waiting);
    client
        .decide_approval(
            session_pending.id.as_str(),
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Session),
        )
        .unwrap();
    let session_changed = approval_request(session_sql, Some(session_id.clone()), b"8");
    assert_eq!(
        provider.request(&session_changed).unwrap().decision,
        ProviderDecision::Approved
    );

    assert_eq!(client.list_approvals().unwrap().len(), 3);
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_token_and_daemon_down_fail_closed_without_secret_errors() {
    let mut daemon = TestDaemon::start().await;
    let client = daemon.client();
    std::fs::write(
        daemon.home.join("session.token"),
        "DAEMON_CONTROL_SECRET_12345\n",
    )
    .expect("replace token for wrong-token client");
    let wrong = daemon.client();
    let error = wrong.create_session("key", "mcp").unwrap_err();
    assert_eq!(error, ControlPlaneError::Authentication);
    assert!(!format!("{error:?} {error}").contains("DAEMON_CONTROL_SECRET_12345"));
    assert!(!format!("{wrong:?}").contains("DAEMON_CONTROL_SECRET_12345"));

    let request = approval_request("DELETE FROM t WHERE id = $1", None, b"secret-param");
    let provider = DaemonApprovalProvider::new(wrong, None, "db".to_owned(), None);
    assert!(matches!(
        provider.request(&request),
        Err(ProviderError::Transport(message)) if message == "control plane unavailable"
    ));

    daemon.stop().await;
    let down_error = client.list_approvals().unwrap_err();
    assert!(matches!(
        down_error,
        ControlPlaneError::Connection | ControlPlaneError::Timeout
    ));
    assert!(!format!("{down_error:?} {down_error}").contains("DAEMON_CONTROL_SECRET_12345"));
}

#[test]
fn malformed_and_oversized_responses_are_typed_failures() {
    let malformed = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{!}";
    assert!(matches!(parse_response(malformed), Ok((200, _))));
    let too_long = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        MAX_RESPONSE_BYTES + 1
    );
    assert_eq!(
        parse_response(too_long.as_bytes()),
        Err(ControlPlaneError::ResponseTooLarge)
    );
    assert_eq!(
        parse_response(b"not HTTP"),
        Err(ControlPlaneError::InvalidResponse)
    );
}

#[test]
fn unknown_status_and_binding_never_map_to_approval() {
    let record: ApprovalRecord = serde_json::from_str(
        r#"{"id":"qka_x","status":"future_approved","bindingKind":"future_exact"}"#,
    )
    .unwrap();
    assert_eq!(record.status, ApprovalStatus::Unknown);
    assert_eq!(record.binding_kind, ApprovalBindingKind::Unknown);
    assert_ne!(record.status, ApprovalStatus::Approved);
    assert_ne!(record.binding_kind, ApprovalBindingKind::LegacyShape);
    let missing_binding: ApprovalRecord =
        serde_json::from_str(r#"{"id":"qka_legacy","status":"approved"}"#).unwrap();
    assert_eq!(
        missing_binding.binding_kind,
        ApprovalBindingKind::LegacyShape
    );
}

#[test]
fn oversized_http_body_is_bounded_before_json_decode() {
    let (client, task) = fake_http_response(vec![b' '; MAX_RESPONSE_BYTES + 1], 200);
    assert_eq!(
        client.list_approvals().unwrap_err(),
        ControlPlaneError::ResponseTooLarge
    );
    let _ = task.join().expect("fake server");
}
fn fake_http_response(
    response_body: Vec<u8>,
    status: u16,
) -> (ControlPlaneClient, std::thread::JoinHandle<Vec<u8>>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind fake daemon");
    let addr = listener.local_addr().expect("fake address");
    let task = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept client");
        let mut request = Vec::new();
        let mut chunk = [0u8; 2048];
        let body_end = loop {
            let count = stream.read(&mut chunk).expect("read request");
            assert_ne!(count, 0, "request ended before headers");
            request.extend_from_slice(&chunk[..count]);
            if let Some(header_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let header = String::from_utf8_lossy(&request[..header_end]);
                let body_len = header
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .map(|(_, value)| value.trim().parse::<usize>().expect("content length"))
                    .unwrap_or(0);
                let end = header_end + 4 + body_len;
                while request.len() < end {
                    let count = stream.read(&mut chunk).expect("read request body");
                    assert_ne!(count, 0, "request ended before body");
                    request.extend_from_slice(&chunk[..count]);
                }
                break end;
            }
        };
        let response = format!(
            "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response_body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response header");
        stream
            .write_all(&response_body)
            .expect("write response body");
        request[..body_end].to_vec()
    });
    (
        ControlPlaneClient {
            addr,
            token: qk_daemon::AuthToken::new("DAEMON_CONTROL_SECRET_12345".to_owned()),
        },
        task,
    )
}

#[test]
fn provider_sends_only_opaque_digest_and_typed_scope() {
    let (client, task) = fake_http_response(br#"{"id":"qka_fake"}"#.to_vec(), 201);
    let request = approval_request(
        "DELETE FROM customers WHERE id = $1",
        None,
        b"PARAM_WIRE_SECRET_12345",
    );
    let provider = DaemonApprovalProvider::new(
        client,
        None,
        "postgres://user@localhost/db".to_owned(),
        None,
    );
    assert_eq!(
        provider.request(&request).unwrap().decision,
        ProviderDecision::Waiting
    );
    let raw_request = task.join().expect("fake server");
    let request_text = String::from_utf8(raw_request).expect("request utf8");
    let body = request_text.split_once("\r\n\r\n").unwrap().1;
    assert!(request_text.contains("Authorization: Bearer DAEMON_CONTROL_SECRET_12345\r\n"));
    assert!(!body.contains("DAEMON_CONTROL_SECRET_12345"));
    assert!(!body.contains("PARAM_WIRE_SECRET_12345"));
    let body: serde_json::Value = serde_json::from_str(body).expect("request JSON");
    assert!(body
        .get("exactDigest")
        .and_then(|value| value.as_str())
        .is_some());
    assert!(body.get("bindingKind").is_some());
    assert!(body.get("params").is_none());
    assert!(body.get("wireBytes").is_none());
}

#[test]
fn malformed_approval_response_never_authorizes() {
    let (client, task) = fake_http_response(b"{invalid".to_vec(), 200);
    let request = approval_request("DELETE FROM t WHERE id = $1", None, b"42");
    let provider = DaemonApprovalProvider::new(
        client,
        None,
        "db".to_owned(),
        Some("qka_existing".to_owned()),
    );
    assert_eq!(
        provider.request(&request).unwrap().decision,
        ProviderDecision::Waiting
    );
    let _ = task.join().expect("fake server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_daemon_expired_exact_grant_stays_waiting() {
    let mut daemon = TestDaemon::start().await;
    let client = daemon.client();
    let request = approval_request("DELETE FROM t WHERE id = $1", None, b"expired");
    let session_id: Option<&str> = None;
    let body = CreateApprovalRequest {
        connection_key: "db",
        session_id,
        fingerprint: request.fingerprint.as_str(),
        reason: &request.message,
        risk: "high",
        operation_summary: "delete t".to_owned(),
        timeout_ms: 1_000,
        binding_kind: "exact_v2",
        exact_digest: request.exact.to_hex(),
        integration: &request.scope.integration,
        environment: &request.scope.environment,
        database: &request.scope.database,
        agent_id: &request.scope.agent_id,
        tool: &request.scope.tool,
    };
    let created: IdResponse = client.post_json("/approvals", &body).unwrap();
    let id = ApprovalId::new(created.id);
    client
        .decide_approval(
            id.as_str(),
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Once),
        )
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert!(!client
        .verify_approval(&id, &request.exact, &request.scope)
        .unwrap());
    let provider =
        DaemonApprovalProvider::new(client, None, "db".to_owned(), Some(id.as_str().to_owned()));
    assert_eq!(
        provider.request(&request).unwrap().decision,
        ProviderDecision::Waiting
    );
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn waiting_provider_rechecks_daemon_and_verifies_exact_request() {
    let mut daemon = TestDaemon::start().await;
    let client = daemon.client();
    let request = approval_request("DELETE FROM t WHERE id = $1", None, b"42");
    let provider = DaemonApprovalProvider::new(client.clone(), None, "db".to_owned(), None)
        .with_wait_timeout(Duration::from_secs(3));
    let task = tokio::task::spawn_blocking(move || provider.request(&request));

    let row = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(rows) = client.list_approvals() {
                if let Some(row) = rows.first() {
                    if row.status == ApprovalStatus::Waiting {
                        break row.clone();
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("approval creation");
    client
        .decide_approval(
            &row.id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Once),
        )
        .unwrap();
    let response = task.await.expect("provider task").unwrap();
    assert_eq!(response.decision, ProviderDecision::Approved);
    daemon.stop().await;
}
