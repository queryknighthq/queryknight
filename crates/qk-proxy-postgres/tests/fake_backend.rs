use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use qk_control_plane::{ApprovalDecision, ControlPlaneClient};
use qk_db::DbConfig;
use qk_proxy_postgres::protocol::{encode_message, encode_startup, Frame, FrameReader};
use qk_proxy_postgres::{ProxyConfig, ProxyServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;

const POLICY: &str = r#"
version: 1
defaults:
  decision: deny
  on_parse_error: deny
  on_unknown: require_approval
environments:
  production:
    databases:
      main:
        allow:
          - operations: [select, create, copy, set]
        deny:
          - operations: [drop, update, delete]
"#;

const APPROVAL_POLICY: &str = r#"
version: 1
defaults:
  decision: deny
  on_parse_error: deny
  on_unknown: deny
environments:
  production:
    databases:
      main:
        approval_required:
          - operations: [delete]
"#;

#[derive(Debug)]
enum BackendEvent {
    Startup {
        connection: usize,
        packet: Vec<u8>,
    },
    Password {
        connection: usize,
        byte_count: usize,
    },
    Query {
        connection: usize,
        raw: Vec<u8>,
        sql: String,
    },
}

struct FakeBackend {
    addr: std::net::SocketAddr,
    events: mpsc::UnboundedReceiver<BackendEvent>,
    connections: Arc<AtomicUsize>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl FakeBackend {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("backend bind");
        let addr = listener.local_addr().expect("backend address");
        let (event_tx, events) = mpsc::unbounded_channel();
        let connections = Arc::new(AtomicUsize::new(0));
        let connection_count = connections.clone();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        let connection = connection_count.fetch_add(1, Ordering::SeqCst) + 1;
                        let events = event_tx.clone();
                        tasks.spawn(run_fake_session(stream, connection, events));
                    }
                    Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
                }
            }
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        });
        Self {
            addr,
            events,
            connections,
            shutdown: Some(shutdown_tx),
            task: Some(task),
        }
    }

    async fn assert_backend_handshake(
        &mut self,
        expected_user: &str,
        expected_database: &str,
        expected_connection: usize,
    ) {
        let startup = tokio::time::timeout(Duration::from_secs(2), self.events.recv())
            .await
            .expect("backend StartupMessage")
            .expect("backend event");
        let BackendEvent::Startup { connection, packet } = startup else {
            panic!("expected backend StartupMessage");
        };
        assert_eq!(connection, expected_connection);
        let parameters = qk_proxy_postgres::protocol::parse_startup(&packet)
            .expect("validated backend StartupMessage");
        assert!(parameters
            .pairs
            .iter()
            .any(|(key, value)| key == "user" && value == expected_user));
        assert!(parameters
            .pairs
            .iter()
            .any(|(key, value)| key == "database" && value == expected_database));
        let password = tokio::time::timeout(Duration::from_secs(2), self.events.recv())
            .await
            .expect("backend auth response")
            .expect("backend event");
        assert!(matches!(
            password,
            BackendEvent::Password {
                connection: id,
                byte_count: count
            } if id == expected_connection && count > 0
        ));
    }

    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.await.expect("fake backend task");
        }
    }
}

async fn run_fake_session(
    stream: TcpStream,
    connection: usize,
    events: mpsc::UnboundedSender<BackendEvent>,
) {
    let (read, mut write) = stream.into_split();
    let mut reader = FrameReader::new(read);
    let Ok(startup) = reader.startup_packet().await else {
        return;
    };
    if events
        .send(BackendEvent::Startup {
            connection,
            packet: startup.to_vec(),
        })
        .is_err()
    {
        return;
    }
    let auth_request = encode_message(b'R', &[0, 0, 0, 3]).expect("auth request");
    if write.write_all(&auth_request).await.is_err() {
        return;
    }
    let Ok(password) = reader.message().await else {
        return;
    };
    if password.kind != b'p'
        || events
            .send(BackendEvent::Password {
                connection,
                byte_count: password.payload().len(),
            })
            .is_err()
    {
        return;
    }
    let auth_ok = encode_message(b'R', &[0, 0, 0, 0]).expect("auth ok");
    let parameter = encode_message(b'S', b"client_encoding\0UTF8\0").expect("parameter status");
    let key = encode_message(b'K', &[0, 0, 0, 1, 0, 0, 0, 2]).expect("backend key");
    let ready = encode_message(b'Z', b"I").expect("ready");
    for message in [auth_ok, parameter, key, ready] {
        if write.write_all(&message).await.is_err() {
            return;
        }
    }
    let mut transaction_status = b'I';
    while let Ok(frame) = reader.message().await {
        match frame.kind {
            b'X' => return,
            b'Q' => {
                let Ok(sql) = qk_proxy_postgres::protocol::simple_query_sql(frame.payload()) else {
                    return;
                };
                if events
                    .send(BackendEvent::Query {
                        connection,
                        raw: frame.raw.to_vec(),
                        sql: sql.to_owned(),
                    })
                    .is_err()
                {
                    return;
                }
                let upper = sql.trim().to_ascii_uppercase();
                let tag = if upper == "SELECT BACKEND_TX_BEGIN" {
                    transaction_status = b'T';
                    "SELECT 1"
                } else if upper == "SELECT BACKEND_TX_RESET" {
                    transaction_status = b'I';
                    "SELECT 1"
                } else if upper.starts_with("BEGIN") {
                    transaction_status = b'I';
                    if upper.starts_with("COMMIT") {
                        "COMMIT"
                    } else {
                        "ROLLBACK"
                    }
                } else if upper.contains("BACKEND_SYNTAX_ERROR") {
                    if transaction_status == b'T' {
                        transaction_status = b'E';
                    }
                    let error =
                        encode_message(b'E', b"SERROR\0C42601\0Mfake backend syntax error\0\0")
                            .expect("backend error");
                    if write.write_all(&error).await.is_err() {
                        return;
                    }
                    if write
                        .write_all(&encode_message(b'Z', &[transaction_status]).expect("ready"))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    continue;
                } else if upper.starts_with("SELECT") {
                    "SELECT 1"
                } else if upper.starts_with("UPDATE") {
                    "UPDATE 1"
                } else {
                    "COMMAND"
                };
                if write
                    .write_all(
                        &encode_message(b'C', &[tag.as_bytes(), &[0]].concat())
                            .expect("command complete"),
                    )
                    .await
                    .is_err()
                    || write
                        .write_all(&encode_message(b'Z', &[transaction_status]).expect("ready"))
                        .await
                        .is_err()
                {
                    return;
                }
            }
            _ => {
                // The Simple Query proxy must never forward Parse, Bind,
                // Execute, FunctionCall, or COPY messages.
                let _ = events.send(BackendEvent::Query {
                    connection,
                    raw: frame.raw.to_vec(),
                    sql: format!("unexpected backend message {}", frame.kind as char),
                });
                return;
            }
        }
    }
}

struct Frontend {
    reader: FrameReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
}

impl Frontend {
    async fn connect(addr: std::net::SocketAddr, user: &str, database: &str) -> Self {
        let stream = TcpStream::connect(addr).await.expect("proxy connect");
        Self::from_stream(stream, user, database).await
    }

    async fn connect_after_refusals(
        addr: std::net::SocketAddr,
        user: &str,
        database: &str,
    ) -> Self {
        let mut stream = TcpStream::connect(addr).await.expect("proxy connect");
        for code in [80_877_103u32, 80_877_104] {
            let mut request = Vec::from(8u32.to_be_bytes());
            request.extend_from_slice(&code.to_be_bytes());
            stream
                .write_all(&request)
                .await
                .expect("write encryption request");
            let mut answer = [0u8; 1];
            stream
                .read_exact(&mut answer)
                .await
                .expect("encryption refusal");
            assert_eq!(answer, [b'N']);
        }
        Self::from_stream(stream, user, database).await
    }

    async fn from_stream(mut stream: TcpStream, user: &str, database: &str) -> Self {
        let startup = encode_startup(&[
            ("user".to_owned(), user.to_owned()),
            ("database".to_owned(), database.to_owned()),
            ("client_encoding".to_owned(), "UTF8".to_owned()),
            ("application_name".to_owned(), "qk-fake-client".to_owned()),
        ])
        .expect("startup packet");
        stream.write_all(&startup).await.expect("write startup");
        let (read, write) = stream.into_split();
        let mut reader = FrameReader::new(read);
        let mut write = write;
        loop {
            let frame = reader.message().await.expect("startup response");
            match frame.kind {
                b'R' => {
                    let code =
                        u32::from_be_bytes(frame.payload()[..4].try_into().expect("auth code"));
                    if code == 3 {
                        let password = encode_message(b'p', b"PG_FRONTEND_PASSWORD_SECRET\0")
                            .expect("password message");
                        write.write_all(&password).await.expect("write password");
                    } else if code != 0 {
                        panic!("unexpected fake backend auth method {code}");
                    }
                }
                b'Z' => break,
                b'E' => panic!("startup was rejected: {:?}", frame.payload()),
                _ => {}
            }
        }
        Self {
            reader,
            writer: write,
        }
    }
    async fn rejected_startup(
        addr: std::net::SocketAddr,
        parameters: &[(String, String)],
    ) -> Frame {
        let stream = TcpStream::connect(addr).await.expect("proxy connect");
        let (read, mut write) = stream.into_split();
        let mut reader = FrameReader::new(read);
        let packet = encode_startup(parameters).expect("startup packet");
        write.write_all(&packet).await.expect("write startup");
        let frame = reader.message().await.expect("startup ErrorResponse");
        assert_eq!(frame.kind, b'E');
        frame
    }

    async fn simple_query(&mut self, sql: &str) -> (Vec<Frame>, u8) {
        let payload = [sql.as_bytes(), &[0]].concat();
        let frame = encode_message(b'Q', &payload).expect("query frame");
        self.writer.write_all(&frame).await.expect("write query");
        let mut messages = Vec::new();
        loop {
            let message = self.reader.message().await.expect("query response");
            let ready = if message.kind == b'Z' {
                Some(message.payload()[0])
            } else {
                None
            };
            messages.push(message);
            if let Some(status) = ready {
                return (messages, status);
            }
        }
    }

    async fn send(&mut self, frames: &[Vec<u8>]) {
        for frame in frames {
            self.writer
                .write_all(frame)
                .await
                .expect("write frontend frame");
        }
    }

    async fn read_until_ready(&mut self) -> (Vec<Frame>, u8) {
        let mut messages = Vec::new();
        loop {
            let message = self.reader.message().await.expect("extended response");
            let ready = if message.kind == b'Z' {
                Some(message.payload()[0])
            } else {
                None
            };
            messages.push(message);
            if let Some(status) = ready {
                return (messages, status);
            }
        }
    }
}

struct RunningProxy {
    addr: std::net::SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<(), qk_proxy_postgres::ProxyError>>>,
}

async fn start_proxy(
    backend: &FakeBackend,
    policy: qk_core::PolicyFile,
    control_plane: Option<ControlPlaneClient>,
) -> RunningProxy {
    let url = format!(
        "postgres://qk:BACKEND_URL_SECRET@127.0.0.1:{}/queryknight?sslmode=disable",
        backend.addr.port()
    );
    let db_config = DbConfig::from_url(&url).expect("typed postgres URL");
    let connection_key = format!(
        "postgres://qk@127.0.0.1:{}/queryknight",
        backend.addr.port()
    );
    let config = ProxyConfig::new(
        0,
        db_config,
        connection_key,
        "production".to_owned(),
        "main".to_owned(),
        policy,
        control_plane,
    )
    .expect("proxy config");
    assert!(!format!("{config:?}").contains("BACKEND_URL_SECRET"));
    let proxy = ProxyServer::bind(config).await.expect("proxy bind");
    let addr = proxy.local_addr().expect("proxy address");
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        proxy
            .run_until(async move {
                let _ = shutdown_rx.await;
            })
            .await
    });
    RunningProxy {
        addr,
        shutdown: Some(shutdown_tx),
        task: Some(task),
    }
}

impl RunningProxy {
    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.await.expect("proxy task").expect("proxy shutdown");
        }
    }
}

struct TestControlPlane {
    home: PathBuf,
    client: ControlPlaneClient,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), qk_daemon::runtime::RuntimeError>>,
}

impl TestControlPlane {
    async fn start() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let home = std::env::temp_dir().join(format!(
            "qk-proxy-postgres-daemon-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).expect("create isolated daemon home");
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
        tokio::time::timeout(Duration::from_secs(10), ready_rx)
            .await
            .expect("daemon readiness timeout")
            .expect("daemon address");
        let client = ControlPlaneClient::discover_with_url(Some(home.clone()), None)
            .expect("discover isolated daemon");
        Self {
            home,
            client,
            shutdown: Some(shutdown_tx),
            task,
        }
    }

    async fn stop(self) {
        if let Some(shutdown) = self.shutdown {
            let _ = shutdown.send(());
        }
        self.task
            .await
            .expect("daemon task")
            .expect("clean daemon stop");
        let _ = std::fs::remove_dir_all(self.home);
    }
}

fn test_policy() -> qk_core::PolicyFile {
    qk_core::parse_policy(POLICY).expect("test policy")
}

async fn next_query(events: &mut mpsc::UnboundedReceiver<BackendEvent>) -> BackendEvent {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(BackendEvent::Query {
                connection,
                raw,
                sql,
            }) = events.recv().await
            {
                break BackendEvent::Query {
                    connection,
                    raw,
                    sql,
                };
            }
        }
    })
    .await
    .expect("backend received Q")
}

async fn assert_no_query(events: &mut mpsc::UnboundedReceiver<BackendEvent>) {
    let result = tokio::time::timeout(Duration::from_millis(100), async {
        loop {
            if let Some(BackendEvent::Query { .. }) = events.recv().await {
                return true;
            }
        }
    })
    .await;
    assert!(
        result.is_err(),
        "backend received an executable frontend frame"
    );
}

fn error_sqlstate(messages: &[Frame]) -> Option<String> {
    for message in messages {
        if message.kind != b'E' {
            continue;
        }
        let mut offset = 0;
        let payload = message.payload();
        while offset < payload.len() {
            let field = payload[offset];
            offset += 1;
            if field == 0 {
                break;
            }
            let end = payload[offset..].iter().position(|byte| *byte == 0)? + offset;
            if field == b'C' {
                return std::str::from_utf8(&payload[offset..end])
                    .ok()
                    .map(str::to_owned);
            }
            offset = end + 1;
        }
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fake_backend_proves_permit_gate_original_frame_and_session_relay() {
    let mut backend = FakeBackend::start().await;
    let proxy = start_proxy(&backend, test_policy(), None).await;
    let mut client = Frontend::connect(proxy.addr, "qk", "queryknight").await;
    backend
        .assert_backend_handshake("qk", "queryknight", 1)
        .await;
    assert_eq!(backend.connections.load(Ordering::SeqCst), 1);

    let (messages, status) = client.simple_query("SELECT 1").await;
    assert_eq!(status, b'I');
    assert!(messages.iter().any(|message| message.kind == b'C'));
    let BackendEvent::Query {
        connection,
        raw,
        sql,
    } = next_query(&mut backend.events).await
    else {
        unreachable!()
    };
    assert_eq!(sql, "SELECT 1");
    assert_eq!(raw, encode_message(b'Q', b"SELECT 1\0").unwrap());
    assert_eq!(connection, 1);

    let (blocked, status) = client.simple_query("DROP TABLE protected_table").await;
    assert_eq!(status, b'I');
    assert_eq!(error_sqlstate(&blocked).as_deref(), Some("42501"));
    assert_no_query(&mut backend.events).await;

    let (multi, status) = client
        .simple_query("SELECT 1; DROP TABLE protected_table")
        .await;
    assert_eq!(status, b'I');
    assert_eq!(error_sqlstate(&multi).as_deref(), Some("42501"));
    assert_no_query(&mut backend.events).await;

    let (copy, status) = client.simple_query("COPY protected_table TO STDOUT").await;
    assert_eq!(status, b'I');
    assert_eq!(error_sqlstate(&copy).as_deref(), Some("0A000"));
    assert_no_query(&mut backend.events).await;

    let (set, status) = client.simple_query("SET ROLE superuser").await;
    assert_eq!(status, b'I');
    assert_eq!(error_sqlstate(&set).as_deref(), Some("0A000"));
    assert_no_query(&mut backend.events).await;

    proxy.stop().await;
    backend.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn extended_protocol_function_call_and_copy_streams_never_reach_backend() {
    let mut backend = FakeBackend::start().await;
    let proxy = start_proxy(&backend, test_policy(), None).await;
    let mut client = Frontend::connect(proxy.addr, "qk", "queryknight").await;
    backend
        .assert_backend_handshake("qk", "queryknight", 1)
        .await;
    let frames = [
        encode_message(b'P', b"s\0SELECT 1\0\0\0").unwrap(),
        encode_message(b'B', b"\0s\0\0\0\0\0\0\0").unwrap(),
        encode_message(b'E', b"\0\0\0\0\0").unwrap(),
        encode_message(b'S', &[]).unwrap(),
    ];
    client.send(&frames).await;
    let (responses, status) = client.read_until_ready().await;
    assert_eq!(status, b'I');
    assert_eq!(error_sqlstate(&responses).as_deref(), Some("0A000"));
    assert_no_query(&mut backend.events).await;

    let function = encode_message(b'F', &[]).unwrap();
    client.send(&[function]).await;
    let (responses, status) = client.read_until_ready().await;
    assert_eq!(status, b'I');
    assert_eq!(error_sqlstate(&responses).as_deref(), Some("0A000"));
    assert_no_query(&mut backend.events).await;

    // A Simple Query still works after synthetic extended-protocol recovery.
    let _ = client.simple_query("SELECT 1").await;
    let BackendEvent::Query { sql, .. } = next_query(&mut backend.events).await else {
        unreachable!()
    };
    assert_eq!(sql, "SELECT 1");

    for (kind, payload) in [
        (b'd', &b"copy-data"[..]),
        (b'c', &b""[..]),
        (b'f', &b"cancel"[..]),
    ] {
        let mut copy_client = Frontend::connect(proxy.addr, "qk", "queryknight").await;
        let frame = encode_message(kind, payload).unwrap();
        copy_client.send(&[frame]).await;
        let error = copy_client.reader.message().await.expect("COPY rejection");
        assert_eq!(error.kind, b'E');
        assert_eq!(error_sqlstate(&[error]).as_deref(), Some("08P01"));
        assert_no_query(&mut backend.events).await;
    }

    proxy.stop().await;
    backend.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn startup_security_modes_and_backend_identity_fail_closed() {
    let mut backend = FakeBackend::start().await;
    let proxy = start_proxy(&backend, test_policy(), None).await;
    let mut client = Frontend::connect_after_refusals(proxy.addr, "qk", "queryknight").await;
    backend
        .assert_backend_handshake("qk", "queryknight", 1)
        .await;
    let _ = client.simple_query("SELECT 1").await;
    let _ = next_query(&mut backend.events).await;

    let cancel = TcpStream::connect(proxy.addr)
        .await
        .expect("cancel connect");
    let mut cancel = cancel;
    let mut packet = Vec::from(16u32.to_be_bytes());
    packet.extend_from_slice(&80_877_102u32.to_be_bytes());
    packet.extend_from_slice(&[0; 8]);
    cancel
        .write_all(&packet)
        .await
        .expect("write CancelRequest");
    drop(cancel);

    for parameters in [
        vec![
            ("user".to_owned(), "qk".to_owned()),
            ("database".to_owned(), "another_database".to_owned()),
        ],
        vec![
            ("user".to_owned(), "qk".to_owned()),
            ("database".to_owned(), "queryknight".to_owned()),
            ("options".to_owned(), "-c role=superuser".to_owned()),
        ],
        vec![
            ("user".to_owned(), "qk".to_owned()),
            ("database".to_owned(), "queryknight".to_owned()),
            ("replication".to_owned(), "database".to_owned()),
        ],
        vec![
            ("user".to_owned(), "other_role".to_owned()),
            ("database".to_owned(), "queryknight".to_owned()),
        ],
    ] {
        let error = Frontend::rejected_startup(proxy.addr, &parameters).await;
        assert!(matches!(
            error_sqlstate(&[error]),
            Some(code) if code == "3D000" || code == "0A000" || code == "28000"
        ));
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(backend.connections.load(Ordering::SeqCst), 1);

    proxy.stop().await;
    backend.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_errors_keep_real_transaction_status_and_backend_status_wins() {
    let backend = FakeBackend::start().await;
    let proxy = start_proxy(&backend, test_policy(), None).await;
    let mut client = Frontend::connect(proxy.addr, "qk", "queryknight").await;

    let (_, status) = client.simple_query("SELECT BACKEND_TX_BEGIN").await;
    assert_eq!(status, b'T');
    let (blocked, status) = client.simple_query("DROP TABLE protected_table").await;
    assert_eq!(error_sqlstate(&blocked).as_deref(), Some("42501"));
    assert_eq!(status, b'T');

    let (backend_error, status) = client.simple_query("SELECT BACKEND_SYNTAX_ERROR").await;
    assert_eq!(error_sqlstate(&backend_error).as_deref(), Some("42601"));
    assert_eq!(status, b'E');

    let (_, status) = client.simple_query("SELECT BACKEND_TX_RESET").await;
    assert_eq!(status, b'I');
    proxy.stop().await;
    backend.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_approval_retry_is_exact_and_keeps_the_frontend_session() {
    let daemon = TestControlPlane::start().await;
    let mut backend = FakeBackend::start().await;
    let policy = qk_core::parse_policy(APPROVAL_POLICY).expect("approval policy");
    let proxy = start_proxy(&backend, policy, Some(daemon.client.clone())).await;
    let mut client = Frontend::connect(proxy.addr, "qk", "queryknight").await;
    let sql = "DELETE FROM customers WHERE id = 7";

    let (pending, status) = client.simple_query(sql).await;
    assert_eq!(status, b'I');
    assert_eq!(error_sqlstate(&pending).as_deref(), Some("42501"));
    assert_no_query(&mut backend.events).await;
    let approvals = daemon.client.list_approvals().expect("pending approval");
    assert_eq!(approvals.len(), 1);
    assert_eq!(
        approvals[0].status,
        qk_control_plane::ApprovalStatus::Waiting
    );
    assert_eq!(
        approvals[0].binding_kind,
        qk_control_plane::ApprovalBindingKind::ExactV1
    );
    daemon
        .client
        .decide_approval(
            &approvals[0].id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Once),
        )
        .expect("approve exact request");

    let (retried, status) = client.simple_query(sql).await;
    assert!(retried.iter().all(|frame| frame.kind != b'E'));
    assert_eq!(status, b'I');
    let BackendEvent::Query {
        connection,
        raw,
        sql: forwarded,
    } = next_query(&mut backend.events).await
    else {
        unreachable!()
    };
    assert_eq!(connection, 1);
    assert_eq!(forwarded, sql);
    assert_eq!(
        raw,
        encode_message(b'Q', &[sql.as_bytes(), &[0]].concat()).unwrap()
    );

    let changed = "DELETE FROM customers WHERE id = 8";
    let (not_reused, status) = client.simple_query(changed).await;
    assert_eq!(status, b'I');
    assert_eq!(error_sqlstate(&not_reused).as_deref(), Some("42501"));
    assert_no_query(&mut backend.events).await;
    let approvals = daemon.client.list_approvals().expect("second approval");
    assert_eq!(approvals.len(), 2);
    assert!(approvals
        .iter()
        .any(|row| { row.status == qk_control_plane::ApprovalStatus::Waiting }));
    assert!(approvals
        .iter()
        .any(|row| { row.status == qk_control_plane::ApprovalStatus::Approved }));

    let waiting_id = approvals
        .iter()
        .find(|row| row.status == qk_control_plane::ApprovalStatus::Waiting)
        .expect("changed exact request is waiting")
        .id
        .clone();
    daemon
        .client
        .decide_approval(
            &waiting_id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Session),
        )
        .expect("approve same-shape session");
    let (session_reuse, status) = client.simple_query(changed).await;
    assert!(session_reuse.iter().all(|frame| frame.kind != b'E'));
    assert_eq!(status, b'I');
    let BackendEvent::Query {
        connection,
        sql: forwarded,
        ..
    } = next_query(&mut backend.events).await
    else {
        unreachable!()
    };
    assert_eq!(connection, 1);
    assert_eq!(forwarded, changed);

    let mut other_client = Frontend::connect(proxy.addr, "qk", "queryknight").await;
    let (other_session, status) = other_client.simple_query(changed).await;
    assert_eq!(status, b'I');
    assert_eq!(error_sqlstate(&other_session).as_deref(), Some("42501"));
    assert_no_query(&mut backend.events).await;
    let final_approvals = daemon
        .client
        .list_approvals()
        .expect("other-session approval");
    assert_eq!(final_approvals.len(), 3);
    assert_eq!(
        final_approvals
            .iter()
            .filter(|row| row.status == qk_control_plane::ApprovalStatus::Waiting)
            .count(),
        1
    );

    proxy.stop().await;
    backend.stop().await;
    daemon.stop().await;
}
