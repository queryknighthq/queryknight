use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use qk_control_plane::{ApprovalBindingKind, ApprovalDecision, ApprovalStatus, ControlPlaneClient};
use qk_db::DbConfig;
use qk_openshell::proto::supervisor_middleware_client::SupervisorMiddlewareClient;
use qk_openshell::proto::{
    web_socket_message, web_socket_session_event, Decision, HttpRequestEvaluation,
    HttpRequestTarget, MiddlewareDescribeRequest, RequestContext, SupervisorMiddlewarePhase,
    ValidateConfigRequest, WebSocketMessage, WebSocketPreflight, WebSocketSessionEvent,
    WebSocketSessionStart,
};
use qk_openshell::{
    extension_proto, proto, OpenShellServer, OpenShellService, OpenShellServiceConfig,
};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

fn config(policy: &str) -> prost_types::Struct {
    let fields = BTreeMap::from([
        ("policy_yaml".to_owned(), string_value(policy)),
        ("dialect".to_owned(), string_value("postgres")),
        ("database".to_owned(), string_value("main")),
        ("environment".to_owned(), string_value("production")),
    ]);
    prost_types::Struct { fields }
}

fn string_value(value: &str) -> prost_types::Value {
    prost_types::Value {
        kind: Some(prost_types::value::Kind::StringValue(value.to_owned())),
    }
}

fn request(body: Vec<u8>, input: prost_types::Struct, sandbox_id: &str) -> HttpRequestEvaluation {
    HttpRequestEvaluation {
        phase: SupervisorMiddlewarePhase::PreCredentials as i32,
        context: Some(RequestContext {
            request_id: "request-1".to_owned(),
            sandbox_id: sandbox_id.to_owned(),
            originating_process: None,
            sandbox: String::new(),
            workspace: String::new(),
        }),
        config: Some(input),
        target: Some(HttpRequestTarget {
            scheme: "https".to_owned(),
            host: "db-gateway.local".to_owned(),
            port: 443,
            method: "POST".to_owned(),
            path: "/query".to_owned(),
            query: String::new(),
        }),
        headers: Vec::new(),
        body,
        middleware_name: "queryknight".to_owned(),
    }
}

async fn openshell_client(
    service: OpenShellService,
) -> (
    SupervisorMiddlewareClient<tonic::transport::Channel>,
    qk_openshell::OpenShellServerHandle,
) {
    let server = OpenShellServer::bind_tcp(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("loopback address"),
        service,
    )
    .await
    .expect("bind local gRPC server");
    let address = server.local_addr().expect("TCP address");
    let client = SupervisorMiddlewareClient::connect(format!("http://{address}"))
        .await
        .expect("connect generated gRPC client");
    (client, server)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn generated_client_describes_validates_and_evaluates_http_and_websocket() {
    let db = DbConfig::from_url("postgresql://user:secret@127.0.0.1/app").expect("db config");
    let service = OpenShellService::new(OpenShellServiceConfig::new(db));
    let (mut client, server) = openshell_client(service).await;

    let manifest = client
        .describe(MiddlewareDescribeRequest {
            gateway: Some(extension_proto::PeerMetadata {
                protocol_version: Some(extension_proto::ProtocolVersion { major: 1, minor: 2 }),
                implementation_name: "openshell-test".to_owned(),
                implementation_version: "test".to_owned(),
                supported_capabilities: Vec::new(),
                required_capabilities: Vec::new(),
            }),
        })
        .await
        .expect("Describe")
        .into_inner();
    assert_eq!(manifest.bindings.len(), 2);
    assert_eq!(manifest.expected_audience, "");
    assert_eq!(
        manifest
            .extension
            .expect("peer metadata")
            .protocol_version
            .unwrap()
            .major,
        1
    );

    let policy = qk_core::DEMO_POLICY;
    let input = config(policy);
    let validation = client
        .validate_config(ValidateConfigRequest {
            config: Some(input.clone()),
            middleware_name: "queryknight".to_owned(),
        })
        .await
        .expect("ValidateConfig")
        .into_inner();
    assert!(validation.valid, "{}", validation.reason);

    let allow = client
        .evaluate_http_request(request(
            br#"{"method":"tools/call","params":{"name":"db_query","arguments":{"query":"SELECT 1"}}}"#.to_vec(),
            input.clone(),
            "sandbox-one",
        ))
        .await
        .expect("HTTP evaluation")
        .into_inner();
    assert_eq!(allow.decision, Decision::Allow as i32);
    assert!(!allow.has_body);
    assert!(allow.header_mutations.is_empty());

    let deny = client
        .evaluate_http_request(request(
            b"DROP TABLE users".to_vec(),
            input.clone(),
            "sandbox-one",
        ))
        .await
        .expect("HTTP deny")
        .into_inner();
    assert_eq!(deny.decision, Decision::Deny as i32);
    assert_eq!(deny.reason_code, "queryknight_deny_rule");
    let mut allow_client = client.clone();
    let mut deny_client = client.clone();
    let (concurrent_allow, concurrent_deny) = tokio::join!(
        allow_client.evaluate_http_request(request(
            b"SELECT 1".to_vec(),
            input.clone(),
            "sandbox-allow",
        )),
        deny_client.evaluate_http_request(request(
            b"DROP TABLE users".to_vec(),
            input.clone(),
            "sandbox-deny",
        )),
    );
    assert_eq!(
        concurrent_allow
            .expect("concurrent allow RPC")
            .into_inner()
            .decision,
        Decision::Allow as i32
    );
    assert_eq!(
        concurrent_deny
            .expect("concurrent deny RPC")
            .into_inner()
            .decision,
        Decision::Deny as i32
    );

    let invalid_utf8 = client
        .evaluate_http_request(request(vec![0xff], input.clone(), "sandbox-one"))
        .await
        .expect("invalid UTF-8 decision")
        .into_inner();
    assert_eq!(invalid_utf8.decision, Decision::Deny as i32);
    assert_eq!(invalid_utf8.reason_code, "queryknight_invalid_utf8");
    let oversized_body = client
        .evaluate_http_request(request(
            vec![b' '; qk_openshell::MAX_PAYLOAD_BYTES + 1],
            input.clone(),
            "sandbox-one",
        ))
        .await
        .expect("oversized body decision")
        .into_inner();
    assert_eq!(oversized_body.decision, Decision::Deny as i32);
    assert_eq!(oversized_body.reason_code, "queryknight_payload_too_large");
    let unbound = client
        .evaluate_http_request(request(
            br#"{"sql":"SELECT * FROM users WHERE id = $1"}"#.to_vec(),
            input.clone(),
            "sandbox-one",
        ))
        .await
        .expect("unbound parameter decision")
        .into_inner();
    assert_eq!(unbound.decision, Decision::Deny as i32);
    assert_eq!(unbound.reason_code, "queryknight_unbound_parameters");

    let quoted_marker = client
        .evaluate_http_request(request(
            br#"{"sql":"SELECT '$1'"}"#.to_vec(),
            input.clone(),
            "sandbox-one",
        ))
        .await
        .expect("quoted placeholder is not a bind")
        .into_inner();
    assert_eq!(quoted_marker.decision, Decision::Allow as i32);

    let mut unsafe_config = input.clone();
    unsafe_config.fields.insert(
        "approval_action".to_owned(),
        string_value("allow_with_findings"),
    );
    let invalid = client
        .validate_config(ValidateConfigRequest {
            config: Some(unsafe_config),
            middleware_name: "unsafe".to_owned(),
        })
        .await
        .expect("invalid ValidateConfig")
        .into_inner();
    assert!(!invalid.valid);

    let preflight = WebSocketSessionEvent {
        event: Some(web_socket_session_event::Event::Preflight(
            WebSocketPreflight {
                session_id: "ws-1".to_owned(),
                phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                context: Some(RequestContext {
                    request_id: "request-ws".to_owned(),
                    sandbox_id: "sandbox-one".to_owned(),
                    originating_process: None,
                    sandbox: String::new(),
                    workspace: String::new(),
                }),
                target: Some(HttpRequestTarget {
                    scheme: "wss".to_owned(),
                    host: "db-gateway.local".to_owned(),
                    port: 443,
                    method: "GET".to_owned(),
                    path: "/ws".to_owned(),
                    query: String::new(),
                }),
                requested_subprotocols: Vec::new(),
                middleware_name: "queryknight".to_owned(),
                config: Some(input.clone()),
            },
        )),
    };
    let events = vec![
        preflight,
        WebSocketSessionEvent {
            event: Some(web_socket_session_event::Event::SessionStart(
                WebSocketSessionStart {
                    selected_subprotocol: String::new(),
                },
            )),
        },
        WebSocketSessionEvent {
            event: Some(web_socket_session_event::Event::Message(WebSocketMessage {
                sequence: 1,
                payload: Some(web_socket_message::Payload::Text("SELECT 1".to_owned())),
            })),
        },
    ];
    let mut stream = client
        .evaluate_web_socket_session(tokio_stream::iter(events))
        .await
        .expect("WebSocket stream")
        .into_inner();
    let preflight_result = stream.message().await.expect("preflight response").unwrap();
    assert!(matches!(
        preflight_result.result,
        Some(proto::web_socket_session_event_result::Result::PreflightDecision(_))
    ));
    let message_result = stream.message().await.expect("message response").unwrap();
    match message_result.result.expect("message result") {
        proto::web_socket_session_event_result::Result::MessageResult(result) => {
            assert_eq!(result.sequence, 1);
            assert_eq!(result.decision, Decision::Allow as i32);
        }
        _ => panic!("expected WebSocket message result"),
    }

    assert!(OpenShellServer::bind_tcp(
        "0.0.0.0:0".parse().expect("non-loopback address"),
        OpenShellService::new(OpenShellServiceConfig::new(
            DbConfig::from_url("postgresql://localhost/app").expect("db config"),
        )),
    )
    .await
    .is_err());
    server.stop().await.expect("graceful server shutdown");
}

#[cfg(unix)]
#[tokio::test]
async fn unix_socket_is_private_and_removed_after_shutdown() {
    use std::os::unix::fs::PermissionsExt;

    let path = std::env::temp_dir().join(format!("qk-openshell-{}.sock", std::process::id()));
    let server = OpenShellServer::bind_unix(
        &path,
        OpenShellService::new(OpenShellServiceConfig::new(
            DbConfig::from_url("postgresql://localhost/app").expect("db config"),
        )),
    )
    .await
    .expect("bind Unix socket");
    let mode = std::fs::metadata(&path)
        .expect("socket metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    server.stop().await.expect("graceful Unix shutdown");
    assert!(!path.exists());
}

struct TestDaemon {
    home: PathBuf,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), qk_daemon::runtime::RuntimeError>>>,
}

impl TestDaemon {
    async fn start() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let index = NEXT.fetch_add(1, Ordering::Relaxed);
        let home =
            std::env::temp_dir().join(format!("qk-openshell-test-{}-{index}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).expect("create daemon home");
        let runtime = qk_daemon::runtime::DaemonRuntime::with_home(home.clone(), Some(0))
            .expect("daemon runtime");
        let (ready_tx, ready_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            qk_daemon::runtime::run_foreground(&runtime, Some(ready_tx), async move {
                let _ = shutdown_rx.await;
            })
            .await
        });
        tokio::time::timeout(Duration::from_secs(10), ready_rx)
            .await
            .expect("daemon readiness timeout")
            .expect("daemon address");
        Self {
            home,
            shutdown: Some(shutdown_tx),
            task: Some(task),
        }
    }

    fn client(&self) -> ControlPlaneClient {
        ControlPlaneClient::discover_with_url(Some(self.home.clone()), None)
            .expect("discover local daemon")
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approvals_are_daemon_backed_and_exact_v2_binds_json_parameters() {
    let mut daemon = TestDaemon::start().await;
    let control = daemon.client();
    let db = DbConfig::from_url("postgresql://user:secret@127.0.0.1/app").expect("db config");
    let connection_key = db.redacted_url();
    let sandbox_id = control
        .create_session(&connection_key, "openshell")
        .expect("create session for sandbox scope");
    let service =
        OpenShellService::new(OpenShellServiceConfig::new(db).with_control_plane(control.clone()));
    let (mut client, server) = openshell_client(service).await;
    let policy = "version: 1\ndefaults:\n  decision: deny\n  on_parse_error: deny\n  on_unknown: deny\nenvironments:\n  production:\n    databases:\n      main:\n        approval_required:\n          - operations: [delete]\n";
    let input = config(policy);
    let validation = client
        .validate_config(ValidateConfigRequest {
            config: Some(input.clone()),
            middleware_name: "queryknight".to_owned(),
        })
        .await
        .expect("ValidateConfig")
        .into_inner();
    assert!(validation.valid, "{}", validation.reason);

    let body = |value| {
        serde_json::json!({
            "method": "tools/call",
            "params": {
                "name": "db_query",
                "arguments": {
                    "query": "DELETE FROM users WHERE id = $1",
                    "params": [value]
                }
            }
        })
        .to_string()
        .into_bytes()
    };
    let first = client
        .evaluate_http_request(request(body(42), input.clone(), &sandbox_id))
        .await
        .expect("approval-required request")
        .into_inner();
    assert_eq!(first.decision, Decision::Deny as i32);
    assert_eq!(first.reason_code, "queryknight_require_approval");
    let pending = control.list_approvals().expect("list approvals");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].binding_kind, ApprovalBindingKind::ExactV2);
    assert_eq!(pending[0].status, ApprovalStatus::Waiting);
    control
        .decide_approval(
            &pending[0].id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Once),
        )
        .expect("approve exact request");

    let exact_retry = client
        .evaluate_http_request(request(body(42), input.clone(), &sandbox_id))
        .await
        .expect("exact approval retry")
        .into_inner();
    assert_eq!(exact_retry.decision, Decision::Allow as i32);
    let other_sandbox = control
        .create_session(&connection_key, "openshell")
        .expect("create second sandbox session");
    let different_scope = client
        .evaluate_http_request(request(body(42), input.clone(), &other_sandbox))
        .await
        .expect("sandbox scope must not reuse another sandbox approval")
        .into_inner();
    assert_eq!(different_scope.decision, Decision::Deny as i32);

    let missing_scope = client
        .evaluate_http_request(request(body(42), input.clone(), ""))
        .await
        .expect("missing sandbox identity is not a session grant")
        .into_inner();
    assert_eq!(missing_scope.decision, Decision::Deny as i32);

    let changed_parameter = client
        .evaluate_http_request(request(body(43), input, &sandbox_id))
        .await
        .expect("different parameter requires a new approval")
        .into_inner();
    assert_eq!(changed_parameter.decision, Decision::Deny as i32);
    assert_eq!(
        changed_parameter.reason_code,
        "queryknight_require_approval"
    );
    let rows = control.list_approvals().expect("list approvals");
    assert_eq!(rows.len(), 4);
    assert!(rows
        .iter()
        .all(|row| row.binding_kind == ApprovalBindingKind::ExactV2));

    server.stop().await.expect("graceful server shutdown");
    daemon.stop().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unavailable_control_plane_denies_approval_required_sql() {
    let mut daemon = TestDaemon::start().await;
    let control = daemon.client();
    daemon.stop().await;

    let db = DbConfig::from_url("postgresql://user:secret@127.0.0.1/app").expect("db config");
    let service =
        OpenShellService::new(OpenShellServiceConfig::new(db).with_control_plane(control));
    let (mut client, server) = openshell_client(service).await;
    let policy = "version: 1\ndefaults:\n  decision: deny\n  on_parse_error: deny\n  on_unknown: deny\nenvironments:\n  production:\n    databases:\n      main:\n        approval_required:\n          - operations: [delete]\n";
    let input = config(policy);
    let validation = client
        .validate_config(ValidateConfigRequest {
            config: Some(input.clone()),
            middleware_name: "queryknight".to_owned(),
        })
        .await
        .expect("ValidateConfig")
        .into_inner();
    assert!(validation.valid, "{}", validation.reason);

    let result = client
        .evaluate_http_request(request(
            b"DELETE FROM users WHERE id = 42".to_vec(),
            input,
            "",
        ))
        .await
        .expect("approval transport failure is a verdict")
        .into_inner();
    assert_eq!(result.decision, Decision::Deny as i32);
    assert_eq!(result.reason_code, "queryknight_approval_error");
    server.stop().await.expect("graceful server shutdown");
}
