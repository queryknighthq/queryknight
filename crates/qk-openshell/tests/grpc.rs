use std::sync::Arc;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use qk_audit::{AttemptOutcome, AuditDecision, MemorySink, Observer};
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

fn typed_invalid_values() -> Vec<(&'static str, prost_types::Value)> {
    use prost_types::value::Kind;
    vec![
        (
            "number",
            prost_types::Value {
                kind: Some(Kind::NumberValue(7.0)),
            },
        ),
        (
            "boolean",
            prost_types::Value {
                kind: Some(Kind::BoolValue(true)),
            },
        ),
        (
            "array",
            prost_types::Value {
                kind: Some(Kind::ListValue(prost_types::ListValue::default())),
            },
        ),
        (
            "object",
            prost_types::Value {
                kind: Some(Kind::StructValue(prost_types::Struct::default())),
            },
        ),
        (
            "null",
            prost_types::Value {
                kind: Some(Kind::NullValue(0)),
            },
        ),
    ]
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
fn assert_decision_only_response(response: &proto::HttpRequestResult) {
    assert!(response.reason.is_empty());
    assert!(response.body.is_empty());
    assert!(!response.has_body);
    assert!(response.header_mutations.is_empty());
    assert!(response.findings.is_empty());
    assert!(response.metadata.is_empty());
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

async fn validate_config_rpc(
    client: &mut SupervisorMiddlewareClient<tonic::transport::Channel>,
    name: &str,
    config: prost_types::Struct,
) -> bool {
    client
        .validate_config(ValidateConfigRequest {
            config: Some(config),
            middleware_name: name.to_owned(),
        })
        .await
        .expect("ValidateConfig")
        .into_inner()
        .valid
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn generated_client_describes_validates_and_evaluates_http_and_websocket() {
    let db = DbConfig::from_url("postgresql://user:secret@127.0.0.1/app").expect("db config");
    let sink = Arc::new(MemorySink::new());
    let observer = Observer::new(vec![sink.clone()]);
    let service =
        OpenShellService::new(OpenShellServiceConfig::new(db).with_observer(observer.clone()));
    let (mut client, server) = openshell_client(service).await;

    let manifest = client
        .describe(MiddlewareDescribeRequest {
            gateway: Some(extension_proto::PeerMetadata {
                protocol_version: Some(extension_proto::ProtocolVersion { major: 1, minor: 0 }),
                implementation_name: "openshell-test".to_owned(),
                implementation_version: "test".to_owned(),
                supported_capabilities: vec!["openshell.supervisor-middleware.contract".to_owned()],
                required_capabilities: vec!["openshell.supervisor-middleware.contract".to_owned()],
            }),
        })
        .await
        .expect("Describe")
        .into_inner();
    assert_eq!(manifest.bindings.len(), 2);
    assert!(manifest.bindings.iter().all(|binding| {
        binding
            .request_timeout
            .as_ref()
            .is_some_and(|timeout| timeout.seconds == 0 && timeout.nanos == 400_000_000)
    }));
    assert_eq!(manifest.expected_audience, "");
    let extension = manifest.extension.expect("peer metadata");
    let version = extension.protocol_version.expect("protocol version");
    assert_eq!((version.major, version.minor), (1, 0));
    assert_eq!(
        extension.supported_capabilities,
        ["openshell.supervisor-middleware.contract"]
    );
    assert_eq!(
        extension.required_capabilities,
        ["openshell.supervisor-middleware.contract"]
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
    assert!(
        sink.is_empty(),
        "Describe and ValidateConfig are not audited"
    );

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
    let events = sink.events();
    assert_eq!(events.len(), 1);
    let authorization = &events[0];
    assert_eq!(authorization.integration, "openshell");
    assert_eq!(authorization.decision, AuditDecision::Allow);
    assert_eq!(authorization.reason_code, "ALLOW_RULE");
    assert_eq!(authorization.outcome, AttemptOutcome::Authorized);
    assert!(authorization.rows_affected.is_none());
    assert!(authorization.rows_shown.is_none());
    assert!(authorization.truncated.is_none());
    assert!(authorization.sql.is_none());
    assert!(authorization.normalized_sql.is_none());
    assert_eq!(authorization.session_id.as_deref(), Some("sandbox-one"));
    let ocsf = qk_audit::to_ocsf(authorization, "0.1.0-beta.0");
    assert_eq!(ocsf.status, "Unknown");

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
    let events = sink.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].decision, AuditDecision::Deny);
    assert_eq!(events[1].outcome, AttemptOutcome::Blocked);
    assert_eq!(events[1].reason_code, "DENY_RULE");
    assert!(events[1].rows_affected.is_none());
    assert_eq!(
        qk_audit::to_ocsf(&events[1], "0.1.0-beta.0").status,
        "Failure"
    );
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
    let events = sink.events();
    assert_eq!(events.len(), 4);
    assert!(events[2..]
        .iter()
        .any(|event| event.session_id.as_deref() == Some("sandbox-allow")
            && event.decision == AuditDecision::Allow));
    assert!(events[2..]
        .iter()
        .any(|event| event.session_id.as_deref() == Some("sandbox-deny")
            && event.decision == AuditDecision::Deny));

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
    assert_eq!(
        sink.len(),
        4,
        "malformed/oversized bodies never reach SQL audit"
    );
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
    let events = sink.events();
    assert_eq!(events.len(), 5);
    assert_eq!(events[4].decision, AuditDecision::Deny);
    assert_eq!(events[4].reason_code, "POLICY_ERROR");
    assert_eq!(events[4].outcome, AttemptOutcome::Blocked);

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
    let events = sink.events();
    assert_eq!(events.len(), 6);
    assert_eq!(events[5].decision, AuditDecision::Allow);
    assert_eq!(events[5].outcome, AttemptOutcome::Authorized);

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
    assert_eq!(sink.len(), 6, "config validation is not a SQL audit");

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
        WebSocketSessionEvent {
            event: Some(web_socket_session_event::Event::Message(WebSocketMessage {
                sequence: 3,
                payload: Some(web_socket_message::Payload::Text(
                    "DROP TABLE users".to_owned(),
                )),
            })),
        },
        WebSocketSessionEvent {
            event: Some(web_socket_session_event::Event::Message(WebSocketMessage {
                sequence: 4,
                payload: Some(web_socket_message::Payload::Text("hello".to_owned())),
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
    let denied_message = stream
        .message()
        .await
        .expect("second message response")
        .unwrap();
    match denied_message.result.expect("second message result") {
        proto::web_socket_session_event_result::Result::MessageResult(result) => {
            assert_eq!(result.sequence, 3);
            assert_eq!(result.decision, Decision::Deny as i32);
        }
        _ => panic!("expected denied WebSocket message result"),
    }
    let non_sql_message = stream
        .message()
        .await
        .expect("non-SQL message response")
        .unwrap();
    match non_sql_message.result.expect("non-SQL message result") {
        proto::web_socket_session_event_result::Result::MessageResult(result) => {
            assert_eq!(result.sequence, 4);
            assert_eq!(result.decision, Decision::Allow as i32);
        }
        _ => panic!("expected non-SQL WebSocket message result"),
    }
    let events = sink.events();
    assert_eq!(events.len(), 8);
    assert_eq!(events[6].decision, AuditDecision::Allow);
    assert_eq!(events[6].outcome, AttemptOutcome::Authorized);
    assert_eq!(events[6].request_id.as_deref(), Some("request-ws"));
    assert_eq!(events[7].decision, AuditDecision::Deny);
    assert_eq!(events[7].outcome, AttemptOutcome::Blocked);
    assert_eq!(events[7].request_id.as_deref(), Some("request-ws"));
    assert_ne!(events[6].event_id, events[7].event_id);
    let metrics = observer.metrics().render();
    assert!(metrics.contains(
        "queryknight_requests_total{database=\"main\",environment=\"production\",integration=\"openshell\",operation=\"select\"} 5"
    ));
    assert!(metrics.contains(
        "queryknight_decisions_total{database=\"main\",decision=\"allow\",environment=\"production\",integration=\"openshell\",operation=\"select\",reason_code=\"ALLOW_RULE\"} 4"
    ));
    assert!(metrics.contains("queryknight_policy_denials_total{"));
    assert!(metrics.contains("queryknight_evaluation_duration_seconds_count 8"));
    assert!(!metrics.contains("sandbox-one"));
    assert!(!metrics.contains("request-1"));

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn validate_config_distinguishes_missing_and_malformed_typed_fields() {
    let db = DbConfig::from_url("postgresql://localhost/app").expect("db config");
    let service = OpenShellService::new(OpenShellServiceConfig::new(db));
    let (mut client, server) = openshell_client(service).await;
    let valid = config(qk_core::DEMO_POLICY);

    assert!(validate_config_rpc(&mut client, "typed", valid.clone()).await);
    let mut malformed_database = valid.clone();
    malformed_database.fields.insert(
        "database".to_owned(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::NumberValue(123.0)),
        },
    );
    let error = client
        .validate_config(ValidateConfigRequest {
            config: Some(malformed_database),
            middleware_name: "typed".to_owned(),
        })
        .await
        .expect("malformed database type")
        .into_inner();
    assert!(!error.valid);
    assert_eq!(error.reason, "database must be a string");

    for field in [
        "policy_yaml",
        "dialect",
        "database",
        "environment",
        "approval_action",
    ] {
        for (kind, value) in typed_invalid_values() {
            let mut candidate = valid.clone();
            candidate.fields.insert(field.to_owned(), value);
            assert!(
                !validate_config_rpc(&mut client, "typed", candidate).await,
                "{field} with {kind} must be rejected"
            );
        }
    }

    for (field, value) in [
        ("policy_yaml", ""),
        ("dialect", ""),
        ("database", ""),
        ("environment", ""),
        ("approval_action", ""),
    ] {
        let mut candidate = valid.clone();
        candidate
            .fields
            .insert(field.to_owned(), string_value(value));
        assert!(
            !validate_config_rpc(&mut client, "typed", candidate).await,
            "empty {field} must retain its existing invalid semantics"
        );
    }

    for field in ["policy_yaml", "dialect", "environment", "approval_action"] {
        let mut candidate = valid.clone();
        candidate.fields.insert(field.to_owned(), string_value(" "));
        assert!(
            !validate_config_rpc(&mut client, "typed", candidate).await,
            "whitespace {field} must retain exact existing behavior"
        );
    }

    let mut unknown_dialect = valid.clone();
    unknown_dialect
        .fields
        .insert("dialect".to_owned(), string_value("unknown-dialect"));
    assert!(!validate_config_rpc(&mut client, "typed", unknown_dialect).await);

    let mut unknown_field = valid.clone();
    unknown_field
        .fields
        .insert("mode".to_owned(), string_value("observe"));
    assert!(!validate_config_rpc(&mut client, "typed", unknown_field).await);

    for field in [
        "database",
        "environment",
        "dialect",
        "approval_action",
        "maxSqlBytes",
    ] {
        let mut absent = valid.clone();
        absent.fields.remove(field);
        assert!(
            validate_config_rpc(&mut client, "defaults", absent).await,
            "documented default should apply only when {field} is absent"
        );
    }

    let mut missing_policy = valid.clone();
    missing_policy.fields.remove("policy_yaml");
    assert!(!validate_config_rpc(&mut client, "defaults", missing_policy).await);

    let mut whitespace_database = valid.clone();
    whitespace_database
        .fields
        .insert("database".to_owned(), string_value(" "));
    assert!(
        validate_config_rpc(&mut client, "whitespace", whitespace_database).await,
        "database whitespace is preserved rather than silently normalized"
    );

    for (kind, value) in typed_invalid_values()
        .into_iter()
        .filter(|(kind, _)| *kind != "number")
        .chain([("string", string_value("1024"))])
    {
        let mut malformed_max = valid.clone();
        malformed_max.fields.insert("maxSqlBytes".to_owned(), value);
        assert!(
            !validate_config_rpc(&mut client, "max", malformed_max).await,
            "maxSqlBytes with {kind} must be rejected"
        );
    }
    let mut malformed_limit = valid.clone();
    malformed_limit
        .fields
        .insert("maxSqlBytes".to_owned(), string_value("1024"));
    let error = client
        .validate_config(ValidateConfigRequest {
            config: Some(malformed_limit),
            middleware_name: "max".to_owned(),
        })
        .await
        .expect("malformed maxSqlBytes type")
        .into_inner();
    assert!(!error.valid);
    assert_eq!(error.reason, "maxSqlBytes must be a number");
    let mut invalid_limit = valid.clone();
    invalid_limit.fields.insert(
        "maxSqlBytes".to_owned(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::NumberValue(0.0)),
        },
    );
    assert!(!validate_config_rpc(&mut client, "max", invalid_limit).await);
    let mut valid_limit = valid.clone();
    valid_limit.fields.insert(
        "maxSqlBytes".to_owned(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::NumberValue(1024.0)),
        },
    );
    assert!(validate_config_rpc(&mut client, "max", valid_limit).await);
    let mut valid_action = valid.clone();
    valid_action
        .fields
        .insert("approval_action".to_owned(), string_value("deny"));
    assert!(validate_config_rpc(&mut client, "valid-action", valid_action).await);

    let mut alternate_scope = valid.clone();
    alternate_scope
        .fields
        .insert("database".to_owned(), string_value("target"));
    alternate_scope
        .fields
        .insert("environment".to_owned(), string_value("staging"));
    assert!(validate_config_rpc(&mut client, "alternate-scope", alternate_scope).await);

    server.stop().await.expect("graceful server shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_context_replacement_preserves_prior_config_and_fails_closed() {
    let policy = r#"
version: 1
defaults:
  decision: deny
  on_parse_error: deny
  on_unknown: deny
environments:
  production:
    databases:
      main:
        allow:
          - operations: [select]
"#;
    let db = DbConfig::from_url("postgresql://localhost/app").expect("db config");
    let sink = Arc::new(MemorySink::new());
    let service = OpenShellService::new(
        OpenShellServiceConfig::new(db).with_observer(Observer::new(vec![sink.clone()])),
    );
    let (mut client, server) = openshell_client(service).await;
    let valid = config(policy);
    assert!(validate_config_rpc(&mut client, "scope", valid.clone()).await);

    let sql =
        br#"{"method":"tools/call","params":{"name":"db_query","arguments":{"query":"SELECT 1"}}}"#;
    let mut trusted_request = request(sql.to_vec(), valid.clone(), "sandbox");
    trusted_request.middleware_name = "scope".to_owned();
    let allowed = client
        .evaluate_http_request(trusted_request.clone())
        .await
        .expect("baseline authorization")
        .into_inner();
    assert_eq!(allowed.decision, Decision::Allow as i32);
    assert_eq!(sink.len(), 1);
    let mut expected_event_count = 1;

    for (field, bad_value) in [
        (
            "database",
            prost_types::Value {
                kind: Some(prost_types::value::Kind::NumberValue(123.0)),
            },
        ),
        (
            "environment",
            prost_types::Value {
                kind: Some(prost_types::value::Kind::NullValue(0)),
            },
        ),
        (
            "dialect",
            prost_types::Value {
                kind: Some(prost_types::value::Kind::BoolValue(true)),
            },
        ),
    ] {
        let mut malformed = valid.clone();
        malformed.fields.insert(field.to_owned(), bad_value);
        assert!(
            !validate_config_rpc(&mut client, "scope", malformed.clone()).await,
            "{field} must be rejected before replacing stored config"
        );

        let mut malformed_request = request(sql.to_vec(), malformed, "sandbox");
        malformed_request.middleware_name = "scope".to_owned();
        let denied = client
            .evaluate_http_request(malformed_request)
            .await
            .expect("malformed config evaluation")
            .into_inner();
        assert_eq!(denied.decision, Decision::Deny as i32, "{field}");
        assert_eq!(
            sink.len(),
            expected_event_count,
            "malformed config must not become an authorization event"
        );

        let still_allowed = client
            .evaluate_http_request(trusted_request.clone())
            .await
            .expect("previous valid config remains active")
            .into_inner();
        assert_eq!(still_allowed.decision, Decision::Allow as i32);
        expected_event_count += 1;
        assert_eq!(sink.len(), expected_event_count);
    }

    let mut malformed_dialect = valid;
    malformed_dialect.fields.insert(
        "dialect".to_owned(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::NumberValue(1.0)),
        },
    );
    let websocket_preflight = WebSocketSessionEvent {
        event: Some(web_socket_session_event::Event::Preflight(
            WebSocketPreflight {
                session_id: "bad-config-session".to_owned(),
                phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                context: Some(RequestContext {
                    request_id: "bad-config-request".to_owned(),
                    sandbox_id: "sandbox".to_owned(),
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
                middleware_name: "scope".to_owned(),
                config: Some(malformed_dialect),
            },
        )),
    };
    let mut websocket = client
        .evaluate_web_socket_session(tokio_stream::iter([websocket_preflight]))
        .await
        .expect("WebSocket config preflight")
        .into_inner();
    let preflight = websocket
        .message()
        .await
        .expect("preflight response")
        .expect("preflight decision");
    match preflight.result.expect("preflight result") {
        proto::web_socket_session_event_result::Result::PreflightDecision(result) => {
            assert_eq!(result.action, proto::WebSocketPreflightAction::Deny as i32);
        }
        _ => panic!("malformed configuration must deny WebSocket preflight"),
    }
    assert!(websocket
        .message()
        .await
        .expect("closed invalid stream")
        .is_none());
    assert_eq!(sink.len(), expected_event_count);
    server.stop().await.expect("graceful server shutdown");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raw_sql_logging_requires_explicit_full_sql_level_and_never_logs_params() {
    let db = DbConfig::from_url("postgresql://localhost/app").expect("db config");
    let sink = Arc::new(MemorySink::new());
    let observer = Observer::new(vec![sink.clone()]);
    let service = OpenShellService::new(
        OpenShellServiceConfig::new(db)
            .with_observer(observer.clone())
            .with_sql_log_level(qk_audit::SqlLogLevel::FullSql),
    );
    let (mut client, server) = openshell_client(service).await;
    let input = config(qk_core::DEMO_POLICY);
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
            br#"{"sql":"SELECT $1 WHERE note = 'OPENSHELL_SQL_SECRET_12345'","params":["OPENSHELL_PARAM_SECRET_67890"]}"#.to_vec(),
            input,
            "sandbox-full-sql",
        ))
        .await
        .expect("parameterized request")
        .into_inner();
    assert_eq!(result.decision, Decision::Allow as i32);
    let events = sink.events();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert!(event
        .sql
        .as_deref()
        .is_some_and(|sql| sql.contains("OPENSHELL_SQL_SECRET_12345")));
    assert!(!serde_json::to_string(event)
        .expect("full SQL event")
        .contains("OPENSHELL_PARAM_SECRET_67890"));
    assert!(!format!("{event:?}").contains("OPENSHELL_PARAM_SECRET_67890"));
    assert!(!observer
        .metrics()
        .render()
        .contains("OPENSHELL_PARAM_SECRET_67890"));
    let ocsf = qk_audit::to_ocsf(event, "0.1.0-beta.0");
    assert_eq!(ocsf.status, "Unknown");
    assert!(!serde_json::to_string(&ocsf)
        .expect("OCSF event")
        .contains("OPENSHELL_PARAM_SECRET_67890"));
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
    let sink = Arc::new(MemorySink::new());
    let observer = Observer::new(vec![sink.clone()]);
    let service = OpenShellService::new(
        OpenShellServiceConfig::new(db)
            .with_control_plane(control.clone())
            .with_observer(observer.clone()),
    );
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
    assert!(sink.is_empty(), "ValidateConfig is not a SQL activity");

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
    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].decision, AuditDecision::RequireApproval);
    assert_eq!(events[0].outcome, AttemptOutcome::Pending);
    assert_eq!(events[0].reason_code, "REQUIRE_APPROVAL");
    assert_eq!(
        events[0].approval_id.as_deref(),
        Some(pending[0].id.as_str())
    );
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
    let events = sink.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].decision, AuditDecision::Allow);
    assert_eq!(events[1].reason_code, "APPROVAL_GRANTED");
    assert_eq!(events[1].outcome, AttemptOutcome::Authorized);
    assert_eq!(
        events[1].approval_id.as_deref(),
        Some(pending[0].id.as_str())
    );
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
    let events = sink.events();
    assert_eq!(events.len(), 5);
    assert_eq!(events[2].decision, AuditDecision::RequireApproval);
    assert_eq!(events[3].decision, AuditDecision::RequireApproval);
    assert_eq!(events[4].decision, AuditDecision::RequireApproval);
    assert!(events.iter().all(|event| event.integration == "openshell"));
    let metrics = observer.metrics().render();
    assert!(metrics.contains(
        "queryknight_approval_requests_total{database=\"main\",environment=\"production\",integration=\"openshell\",operation=\"delete\",result=\"approved\"} 1"
    ));
    assert!(metrics.contains(
        "queryknight_approval_requests_total{database=\"main\",environment=\"production\",integration=\"openshell\",operation=\"delete\",result=\"waiting\"} 4"
    ));
    assert!(!metrics.contains(&sandbox_id));

    server.stop().await.expect("graceful server shutdown");
    daemon.stop().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unavailable_control_plane_is_a_grpc_failure() {
    let mut daemon = TestDaemon::start().await;
    let control = daemon.client();
    daemon.stop().await;

    let db = DbConfig::from_url("postgresql://user:secret@127.0.0.1/app").expect("db config");
    let sink = Arc::new(MemorySink::new());
    let observer = Observer::new(vec![sink.clone()]);
    let service = OpenShellService::new(
        OpenShellServiceConfig::new(db)
            .with_control_plane(control)
            .with_observer(observer),
    );
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

    let status = client
        .evaluate_http_request(request(
            b"DELETE FROM users WHERE id = 42".to_vec(),
            input,
            "",
        ))
        .await
        .expect_err("approval transport failure is a middleware error");
    assert_eq!(status.code(), tonic::Code::Unavailable);
    assert_eq!(status.message(), "OpenShell approval resolution failed");
    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].decision, AuditDecision::Deny);
    assert_eq!(events[0].reason_code, "APPROVAL_ERROR");
    assert_eq!(events[0].outcome, AttemptOutcome::Blocked);
    assert!(events[0].rows_affected.is_none());
    server.stop().await.expect("graceful server shutdown");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failing_audit_sink_never_changes_allow_deny_or_pending_responses() {
    let mut daemon = TestDaemon::start().await;
    let control = daemon.client();
    let db = DbConfig::from_url("postgresql://user:secret@127.0.0.1/app").expect("db config");
    let sink = Arc::new(MemorySink::new());
    sink.fail_next(3);
    let observer = Observer::new(vec![sink.clone()]);
    let service = OpenShellService::new(
        OpenShellServiceConfig::new(db)
            .with_control_plane(control.clone())
            .with_observer(observer.clone()),
    );
    let (mut client, server) = openshell_client(service).await;
    let input = config(qk_core::DEMO_POLICY);
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
        .evaluate_http_request(request(b"SELECT 1".to_vec(), input.clone(), ""))
        .await
        .expect("audit failure must preserve Allow")
        .into_inner();
    assert_eq!(allow.decision, Decision::Allow as i32);
    assert_decision_only_response(&allow);

    let deny = client
        .evaluate_http_request(request(b"DROP TABLE users".to_vec(), input.clone(), ""))
        .await
        .expect("audit failure must preserve Deny")
        .into_inner();
    assert_eq!(deny.decision, Decision::Deny as i32);
    assert_eq!(deny.reason_code, "queryknight_deny_rule");
    assert_decision_only_response(&deny);

    let pending = client
        .evaluate_http_request(request(
            b"DELETE FROM users WHERE id = 42".to_vec(),
            input.clone(),
            "",
        ))
        .await
        .expect("audit failure must preserve pending approval denial")
        .into_inner();
    assert_eq!(pending.decision, Decision::Deny as i32);
    assert_eq!(pending.reason_code, "queryknight_require_approval");
    assert_decision_only_response(&pending);
    assert!(sink.is_empty());
    assert_eq!(control.list_approvals().expect("waiting approval").len(), 1);
    let after_failures = client
        .evaluate_http_request(request(b"SELECT 1".to_vec(), input, ""))
        .await
        .expect("audit failure is not retried")
        .into_inner();
    assert_eq!(after_failures.decision, Decision::Allow as i32);
    assert_eq!(sink.len(), 1);
    assert_eq!(sink.events()[0].outcome, AttemptOutcome::Authorized);
    assert!(observer
        .metrics()
        .render()
        .contains("queryknight_evaluation_duration_seconds_count 4"));

    server.stop().await.expect("graceful server shutdown");
    daemon.stop().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_approval_is_scoped_and_audited_as_authorization_only() {
    let mut daemon = TestDaemon::start().await;
    let control = daemon.client();
    let db = DbConfig::from_url("postgresql://user:secret@127.0.0.1/app").expect("db config");
    let connection_key = db.redacted_url();
    let sandbox_id = control
        .create_session(&connection_key, "openshell")
        .expect("create sandbox session");
    let other_sandbox = control
        .create_session(&connection_key, "openshell")
        .expect("create second sandbox session");
    let sink = Arc::new(MemorySink::new());
    let observer = Observer::new(vec![sink.clone()]);
    let service = OpenShellService::new(
        OpenShellServiceConfig::new(db)
            .with_control_plane(control.clone())
            .with_observer(observer),
    );
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
            "sql": "DELETE FROM users WHERE id = $1",
            "params": [value]
        })
        .to_string()
        .into_bytes()
    };
    let pending = client
        .evaluate_http_request(request(body(1), input.clone(), &sandbox_id))
        .await
        .expect("initial session-scoped request")
        .into_inner();
    assert_eq!(pending.decision, Decision::Deny as i32);
    let row = control.list_approvals().expect("list approvals");
    assert_eq!(row.len(), 1);
    assert_eq!(row[0].binding_kind, ApprovalBindingKind::ExactV2);
    control
        .decide_approval(
            &row[0].id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Session),
        )
        .expect("approve for session");

    let session_retry = client
        .evaluate_http_request(request(body(2), input.clone(), &sandbox_id))
        .await
        .expect("same-session shape authorization")
        .into_inner();
    assert_eq!(session_retry.decision, Decision::Allow as i32);

    let other_scope = client
        .evaluate_http_request(request(body(2), input, &other_sandbox))
        .await
        .expect("session grant must not cross sandbox scope")
        .into_inner();
    assert_eq!(other_scope.decision, Decision::Deny as i32);
    assert_eq!(other_scope.reason_code, "queryknight_require_approval");

    let events = sink.events();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].decision, AuditDecision::RequireApproval);
    assert_eq!(events[0].outcome, AttemptOutcome::Pending);
    assert_eq!(events[1].decision, AuditDecision::Allow);
    assert_eq!(events[1].reason_code, "APPROVAL_GRANTED");
    assert_eq!(events[1].outcome, AttemptOutcome::Authorized);
    assert!(events[1].rows_affected.is_none());
    assert_eq!(events[2].decision, AuditDecision::RequireApproval);
    assert_eq!(events[2].outcome, AttemptOutcome::Pending);
    assert_eq!(
        qk_audit::to_ocsf(&events[1], "0.1.0-beta.0").status,
        "Unknown"
    );

    server.stop().await.expect("graceful server shutdown");
    daemon.stop().await;
}

#[tokio::test]
async fn describe_uses_v1_major_capability_negotiation() {
    let db = DbConfig::from_url("postgresql://user:secret@127.0.0.1/app").expect("db config");
    let service = OpenShellService::new(OpenShellServiceConfig::new(db));
    let (mut client, server) = openshell_client(service).await;
    let contract = "openshell.supervisor-middleware.contract".to_owned();

    let mut compatible = extension_proto::PeerMetadata {
        protocol_version: Some(extension_proto::ProtocolVersion {
            major: 1,
            minor: 99,
        }),
        implementation_name: "openshell/gateway".to_owned(),
        implementation_version: "test".to_owned(),
        supported_capabilities: vec![contract.clone(), "openshell.middleware.future".to_owned()],
        required_capabilities: vec![contract.clone()],
    };
    let manifest = client
        .describe(MiddlewareDescribeRequest {
            gateway: Some(compatible.clone()),
        })
        .await
        .expect("compatible minor and unknown optional capability")
        .into_inner();
    assert_eq!(
        manifest.extension.unwrap().protocol_version.unwrap().minor,
        0
    );

    compatible.protocol_version = Some(extension_proto::ProtocolVersion { major: 2, minor: 0 });
    assert_eq!(
        client
            .describe(MiddlewareDescribeRequest {
                gateway: Some(compatible.clone()),
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );

    compatible.protocol_version = None;
    assert_eq!(
        client
            .describe(MiddlewareDescribeRequest {
                gateway: Some(compatible.clone()),
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );

    compatible.protocol_version = Some(extension_proto::ProtocolVersion { major: 1, minor: 0 });
    compatible.supported_capabilities.clear();
    assert_eq!(
        client
            .describe(MiddlewareDescribeRequest {
                gateway: Some(compatible.clone()),
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );

    compatible.supported_capabilities.push(contract);
    compatible.required_capabilities = vec!["openshell.middleware.future.required".to_owned()];
    assert_eq!(
        client
            .describe(MiddlewareDescribeRequest {
                gateway: Some(compatible),
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );

    assert_eq!(
        client
            .describe(MiddlewareDescribeRequest { gateway: None })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    server.stop().await.expect("graceful server shutdown");
}
