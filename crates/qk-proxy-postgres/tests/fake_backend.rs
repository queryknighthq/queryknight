use std::collections::HashMap;
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
    Protocol {
        connection: usize,
        kind: u8,
    },
    Execute {
        connection: usize,
        portal_name: String,
        max_rows: u32,
        parameter_count: usize,
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

struct FakeStatement {
    sql: String,
    parameter_type_hints: Vec<Option<u32>>,
}

struct FakePortal {
    statement_name: String,
    sql: String,
    parameter_count: usize,
    parameter_values: Vec<Option<(qk_core::ParamRepresentation, Vec<u8>)>>,
    result_formats: Vec<i16>,
    execute_count: u32,
}

fn fake_parameter_description(statement: &FakeStatement) -> Vec<u8> {
    let mut payload = (statement.parameter_type_hints.len() as i16)
        .to_be_bytes()
        .to_vec();
    for oid in &statement.parameter_type_hints {
        payload.extend_from_slice(&oid.unwrap_or(0).to_be_bytes());
    }
    encode_message(b't', &payload).expect("ParameterDescription")
}

fn fake_row_description(sql: &str, format: i16) -> Vec<u8> {
    let type_oid = if sql.to_ascii_lowercase().contains("int") {
        23u32
    } else {
        25u32
    };
    let mut payload = 1i16.to_be_bytes().to_vec();
    payload.extend_from_slice(b"value\0");
    payload.extend_from_slice(&0u32.to_be_bytes());
    payload.extend_from_slice(&0i16.to_be_bytes());
    payload.extend_from_slice(&type_oid.to_be_bytes());
    payload.extend_from_slice(&4i16.to_be_bytes());
    payload.extend_from_slice(&(-1i32).to_be_bytes());
    payload.extend_from_slice(&format.to_be_bytes());
    encode_message(b'T', &payload).expect("RowDescription")
}

fn fake_command_complete(sql: &str) -> Vec<u8> {
    let upper = sql.trim().to_ascii_uppercase();
    let tag = if upper.starts_with("SELECT") {
        "SELECT 1"
    } else if upper.starts_with("INSERT") {
        "INSERT 0 1"
    } else if upper.starts_with("UPDATE") {
        "UPDATE 1"
    } else if upper.starts_with("DELETE") {
        "DELETE 1"
    } else {
        "COMMAND"
    };
    encode_message(b'C', &[tag.as_bytes(), &[0]].concat()).expect("CommandComplete")
}

fn fake_portal_data_row(portal: &FakePortal) -> Vec<u8> {
    let value = match portal.parameter_values.first() {
        Some(None) => None,
        Some(Some((qk_core::ParamRepresentation::Binary, bytes))) => Some(i32::from_be_bytes(
            bytes.as_slice().try_into().unwrap_or([0; 4]),
        )),
        Some(Some((qk_core::ParamRepresentation::Text, bytes))) => std::str::from_utf8(bytes)
            .ok()
            .and_then(|text| text.parse::<i32>().ok()),
        None => Some(1),
    };
    let output = value.map(|value| {
        if portal.result_formats.first().copied().unwrap_or(0) == 1 {
            value.to_be_bytes().to_vec()
        } else {
            value.to_string().into_bytes()
        }
    });
    let mut payload = 1i16.to_be_bytes().to_vec();
    match output {
        Some(value) => {
            payload.extend_from_slice(&(value.len() as i32).to_be_bytes());
            payload.extend_from_slice(&value);
        }
        None => payload.extend_from_slice(&(-1i32).to_be_bytes()),
    }
    encode_message(b'D', &payload).expect("DataRow")
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
    let mut statements = HashMap::<String, FakeStatement>::new();
    let mut portals = HashMap::<String, FakePortal>::new();
    let mut extended_error = false;
    while let Ok(frame) = reader.message().await {
        if extended_error && frame.kind != b'S' && frame.kind != b'X' {
            continue;
        }
        match frame.kind {
            b'X' => return,
            b'Q' => {
                statements.remove("");
                portals.remove("");
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
                    transaction_status = b'T';
                    "BEGIN"
                } else if upper.starts_with("COMMIT") {
                    transaction_status = b'I';
                    "COMMIT"
                } else if upper.starts_with("ROLLBACK") {
                    transaction_status = b'I';
                    "ROLLBACK"
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
            b'P' => {
                let Ok(parsed) = qk_proxy_postgres::protocol::parse_extended_parse(frame.payload())
                else {
                    return;
                };
                if parsed.name.is_empty() {
                    statements.remove("");
                } else if statements.contains_key(&parsed.name) {
                    let error = qk_proxy_postgres::protocol::encode_error(
                        "ERROR",
                        "42P05",
                        "prepared statement already exists",
                    )
                    .unwrap();
                    if write.write_all(&error).await.is_err() {
                        return;
                    }
                    extended_error = true;
                    continue;
                }
                if parsed.sql.contains("BACKEND_PARSE_ERROR") {
                    let error = qk_proxy_postgres::protocol::encode_error(
                        "ERROR",
                        "42601",
                        "fake backend Parse error",
                    )
                    .unwrap();
                    if write.write_all(&error).await.is_err() {
                        return;
                    }
                    extended_error = true;
                    continue;
                }
                if events
                    .send(BackendEvent::Protocol {
                        connection,
                        kind: b'P',
                    })
                    .is_err()
                {
                    return;
                }
                statements.insert(
                    parsed.name,
                    FakeStatement {
                        sql: parsed.sql,
                        parameter_type_hints: parsed.parameter_type_hints,
                    },
                );
                if write
                    .write_all(&encode_message(b'1', &[]).expect("ParseComplete"))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            b'B' => {
                if frame.payload().first() == Some(&0) {
                    portals.remove("");
                }
                let names = qk_proxy_postgres::protocol::parse_extended_bind(frame.payload(), &[]);
                let Ok(bound) = names else {
                    return;
                };
                let Some(statement) = statements.get(&bound.statement_name) else {
                    let error = qk_proxy_postgres::protocol::encode_error(
                        "ERROR",
                        "26000",
                        "prepared statement does not exist",
                    )
                    .unwrap();
                    if write.write_all(&error).await.is_err() {
                        return;
                    }
                    extended_error = true;
                    continue;
                };
                let invalid_int = statement.sql.contains("::int4")
                    && bound
                        .execution_params
                        .iter()
                        .any(|parameter| match parameter {
                            qk_core::ExecutionParam::Wire {
                                representation: qk_core::ParamRepresentation::Text,
                                bytes,
                                ..
                            } => std::str::from_utf8(bytes)
                                .ok()
                                .and_then(|value| value.parse::<i32>().ok())
                                .is_none(),
                            _ => false,
                        });
                if invalid_int {
                    let error = qk_proxy_postgres::protocol::encode_error(
                        "ERROR",
                        "22P02",
                        "fake backend Bind type error",
                    )
                    .unwrap();
                    if write.write_all(&error).await.is_err() {
                        return;
                    }
                    extended_error = true;
                    continue;
                }
                if !bound.portal_name.is_empty() && portals.contains_key(&bound.portal_name) {
                    let error = qk_proxy_postgres::protocol::encode_error(
                        "ERROR",
                        "42P03",
                        "portal already exists",
                    )
                    .unwrap();
                    if write.write_all(&error).await.is_err() {
                        return;
                    }
                    extended_error = true;
                    continue;
                }
                if events
                    .send(BackendEvent::Protocol {
                        connection,
                        kind: b'B',
                    })
                    .is_err()
                {
                    return;
                }
                portals.insert(
                    bound.portal_name,
                    FakePortal {
                        statement_name: bound.statement_name,
                        sql: statement.sql.clone(),
                        parameter_values: bound
                            .execution_params
                            .iter()
                            .map(|parameter| match parameter {
                                qk_core::ExecutionParam::Wire {
                                    representation,
                                    bytes,
                                    ..
                                } => Some((*representation, bytes.clone())),
                                qk_core::ExecutionParam::Null => None,
                                _ => unreachable!(),
                            })
                            .collect(),
                        parameter_count: bound.execution_params.len(),
                        result_formats: bound.result_formats,
                        execute_count: 0,
                    },
                );
                if write
                    .write_all(&encode_message(b'2', &[]).expect("BindComplete"))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            b'D' => {
                let Ok(target) =
                    qk_proxy_postgres::protocol::parse_extended_target(frame.payload())
                else {
                    return;
                };
                let response = match target.target {
                    qk_proxy_postgres::protocol::ExtendedTarget::Statement => {
                        let Some(statement) = statements.get(&target.name) else {
                            let error = qk_proxy_postgres::protocol::encode_error(
                                "ERROR",
                                "26000",
                                "prepared statement does not exist",
                            )
                            .unwrap();
                            if write.write_all(&error).await.is_err() {
                                return;
                            }
                            extended_error = true;
                            continue;
                        };
                        let description = fake_parameter_description(statement);
                        if write.write_all(&description).await.is_err() {
                            return;
                        }
                        if statement
                            .sql
                            .trim_start()
                            .to_ascii_lowercase()
                            .starts_with("select")
                        {
                            fake_row_description(&statement.sql, 0)
                        } else {
                            encode_message(b'n', &[]).expect("NoData")
                        }
                    }
                    qk_proxy_postgres::protocol::ExtendedTarget::Portal => {
                        let Some(portal) = portals.get(&target.name) else {
                            let error = qk_proxy_postgres::protocol::encode_error(
                                "ERROR",
                                "34000",
                                "portal does not exist",
                            )
                            .unwrap();
                            if write.write_all(&error).await.is_err() {
                                return;
                            }
                            extended_error = true;
                            continue;
                        };
                        if portal
                            .sql
                            .trim_start()
                            .to_ascii_lowercase()
                            .starts_with("select")
                        {
                            let format = portal.result_formats.first().copied().unwrap_or(0);
                            fake_row_description(&portal.sql, format)
                        } else {
                            encode_message(b'n', &[]).expect("NoData")
                        }
                    }
                };
                if events
                    .send(BackendEvent::Protocol {
                        connection,
                        kind: b'D',
                    })
                    .is_err()
                    || write.write_all(&response).await.is_err()
                {
                    return;
                }
            }
            b'E' => {
                let Ok(execute) =
                    qk_proxy_postgres::protocol::parse_extended_execute(frame.payload())
                else {
                    return;
                };
                let Some(portal) = portals.get_mut(&execute.portal_name) else {
                    return;
                };
                if events
                    .send(BackendEvent::Execute {
                        connection,
                        portal_name: execute.portal_name.clone(),
                        max_rows: execute.max_rows,
                        parameter_count: portal.parameter_count,
                    })
                    .is_err()
                {
                    return;
                }
                if portal.sql.contains("BACKEND_EXECUTE_ERROR") {
                    if transaction_status == b'T' {
                        transaction_status = b'E';
                    }
                    let error = qk_proxy_postgres::protocol::encode_error(
                        "ERROR",
                        "22012",
                        "fake backend execute error",
                    )
                    .unwrap();
                    if write.write_all(&error).await.is_err() {
                        return;
                    }
                    extended_error = true;
                    continue;
                }
                portal.execute_count += 1;
                if portal
                    .sql
                    .trim_start()
                    .to_ascii_lowercase()
                    .starts_with("select")
                    && write
                        .write_all(&fake_portal_data_row(portal))
                        .await
                        .is_err()
                {
                    return;
                }
                let response = if execute.max_rows > 0
                    && portal
                        .sql
                        .trim_start()
                        .to_ascii_lowercase()
                        .starts_with("select")
                    && portal.execute_count == 1
                {
                    encode_message(b's', &[]).expect("PortalSuspended")
                } else {
                    fake_command_complete(&portal.sql)
                };
                if write.write_all(&response).await.is_err() {
                    return;
                }
            }
            b'C' => {
                let Ok(target) =
                    qk_proxy_postgres::protocol::parse_extended_target(frame.payload())
                else {
                    return;
                };
                match target.target {
                    qk_proxy_postgres::protocol::ExtendedTarget::Statement => {
                        statements.remove(&target.name);
                        portals.retain(|_, portal| portal.statement_name != target.name);
                    }
                    qk_proxy_postgres::protocol::ExtendedTarget::Portal => {
                        portals.remove(&target.name);
                    }
                }
                if write
                    .write_all(&encode_message(b'3', &[]).expect("CloseComplete"))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            b'H' => {
                if !frame.payload().is_empty() {
                    return;
                }
                if events
                    .send(BackendEvent::Protocol {
                        connection,
                        kind: b'H',
                    })
                    .is_err()
                    || write.flush().await.is_err()
                {
                    return;
                }
            }
            b'S' => {
                if !frame.payload().is_empty() {
                    return;
                }
                extended_error = false;
                if write
                    .write_all(&encode_message(b'Z', &[transaction_status]).expect("ReadyForQuery"))
                    .await
                    .is_err()
                {
                    return;
                }
                if transaction_status == b'I' {
                    portals.clear();
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

    async fn read_execute_terminal(&mut self) -> Frame {
        loop {
            let frame = self.reader.message().await.expect("Execute response");
            if matches!(frame.kind, b'C' | b'I' | b's' | b'E') {
                return frame;
            }
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
    async fn read_one(&mut self) -> Frame {
        self.reader
            .message()
            .await
            .expect("single PostgreSQL response")
    }

    async fn sync(&mut self) -> (Vec<Frame>, u8) {
        let sync = encode_message(b'S', &[]).unwrap();
        self.send(&[sync]).await;
        self.read_until_ready().await
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

fn parse_frame(name: &str, sql: &str, oids: &[u32]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(name.as_bytes());
    payload.push(0);
    payload.extend_from_slice(sql.as_bytes());
    payload.push(0);
    payload.extend_from_slice(&(oids.len() as i16).to_be_bytes());
    for oid in oids {
        payload.extend_from_slice(&oid.to_be_bytes());
    }
    encode_message(b'P', &payload).unwrap()
}

fn bind_frame(
    portal: &str,
    statement: &str,
    formats: &[i16],
    values: &[Option<&[u8]>],
    result_formats: &[i16],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(portal.as_bytes());
    payload.push(0);
    payload.extend_from_slice(statement.as_bytes());
    payload.push(0);
    payload.extend_from_slice(&(formats.len() as i16).to_be_bytes());
    for format in formats {
        payload.extend_from_slice(&format.to_be_bytes());
    }
    payload.extend_from_slice(&(values.len() as i16).to_be_bytes());
    for value in values {
        match value {
            Some(value) => {
                payload.extend_from_slice(&(value.len() as i32).to_be_bytes());
                payload.extend_from_slice(value);
            }
            None => payload.extend_from_slice(&(-1i32).to_be_bytes()),
        }
    }
    payload.extend_from_slice(&(result_formats.len() as i16).to_be_bytes());
    for format in result_formats {
        payload.extend_from_slice(&format.to_be_bytes());
    }
    encode_message(b'B', &payload).unwrap()
}

fn execute_frame(portal: &str, max_rows: u32) -> Vec<u8> {
    let mut payload = portal.as_bytes().to_vec();
    payload.push(0);
    payload.extend_from_slice(&(max_rows as i32).to_be_bytes());
    encode_message(b'E', &payload).unwrap()
}

fn target_frame(kind: u8, target: u8, name: &str) -> Vec<u8> {
    let mut payload = vec![target];
    payload.extend_from_slice(name.as_bytes());
    payload.push(0);
    encode_message(kind, &payload).unwrap()
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

async fn next_execute(events: &mut mpsc::UnboundedReceiver<BackendEvent>) -> BackendEvent {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(BackendEvent::Execute {
                connection,
                portal_name,
                max_rows,
                parameter_count,
            }) = events.recv().await
            {
                break BackendEvent::Execute {
                    connection,
                    portal_name,
                    max_rows,
                    parameter_count,
                };
            }
        }
    })
    .await
    .expect("backend received Execute")
}

async fn next_protocol(events: &mut mpsc::UnboundedReceiver<BackendEvent>) -> BackendEvent {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(BackendEvent::Protocol { connection, kind }) = events.recv().await {
                break BackendEvent::Protocol { connection, kind };
            }
        }
    })
    .await
    .expect("backend received protocol setup")
}

async fn assert_no_execute(events: &mut mpsc::UnboundedReceiver<BackendEvent>) {
    let result = tokio::time::timeout(Duration::from_millis(100), async {
        loop {
            if let Some(BackendEvent::Execute { .. }) = events.recv().await {
                return true;
            }
        }
    })
    .await;
    assert!(
        result.is_err(),
        "backend received Execute without authorization"
    );
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
    let mut parse = Vec::new();
    parse.extend_from_slice(b"s\0SELECT $1::int4\0");
    parse.extend_from_slice(&1i16.to_be_bytes());
    parse.extend_from_slice(&23u32.to_be_bytes());
    let mut bind = b"p\0s\0".to_vec();
    bind.extend_from_slice(&0i16.to_be_bytes());
    bind.extend_from_slice(&1i16.to_be_bytes());
    bind.extend_from_slice(&2i32.to_be_bytes());
    bind.extend_from_slice(b"42");
    bind.extend_from_slice(&0i16.to_be_bytes());
    let frames = [
        encode_message(b'P', &parse).unwrap(),
        encode_message(b'B', &bind).unwrap(),
        encode_message(b'E', b"p\0\0\0\0\0").unwrap(),
        encode_message(b'S', &[]).unwrap(),
    ];
    client.send(&frames).await;
    let (responses, status) = client.read_until_ready().await;
    assert_eq!(status, b'I');
    assert!(responses.iter().all(|message| message.kind != b'E'));
    assert!(responses.iter().any(|message| message.kind == b'1'));
    assert!(responses.iter().any(|message| message.kind == b'2'));
    assert!(responses.iter().any(|message| message.kind == b'C'));
    assert!(matches!(
        next_protocol(&mut backend.events).await,
        BackendEvent::Protocol {
            connection: 1,
            kind: b'P'
        }
    ));
    assert!(matches!(
        next_protocol(&mut backend.events).await,
        BackendEvent::Protocol {
            connection: 1,
            kind: b'H'
        }
    ));
    assert!(matches!(
        next_protocol(&mut backend.events).await,
        BackendEvent::Protocol {
            connection: 1,
            kind: b'B'
        }
    ));
    assert!(matches!(
        next_protocol(&mut backend.events).await,
        BackendEvent::Protocol {
            connection: 1,
            kind: b'H'
        }
    ));
    assert!(matches!(
        next_execute(&mut backend.events).await,
        BackendEvent::Execute {
            connection: 1,
            portal_name,
            max_rows: 0,
            parameter_count: 1,
        } if portal_name == "p"
    ));
    assert_no_execute(&mut backend.events).await;

    let function = encode_message(b'F', &[]).unwrap();
    client.send(&[function]).await;
    let (responses, status) = client.read_until_ready().await;
    assert_eq!(status, b'I');
    assert_eq!(error_sqlstate(&responses).as_deref(), Some("0A000"));
    assert_no_execute(&mut backend.events).await;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tokio_postgres_prepared_query_uses_parse_bind_execute() {
    let mut backend = FakeBackend::start().await;
    let proxy = start_proxy(&backend, test_policy(), None).await;
    let url = format!(
        "postgres://qk:PG_FRONTEND_PASSWORD_SECRET@127.0.0.1:{}/queryknight?sslmode=disable",
        proxy.addr.port()
    );
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("real PostgreSQL client connects through proxy");
    let connection_task = tokio::spawn(connection);
    let statement = client
        .prepare_typed("SELECT $1::int4", &[tokio_postgres::types::Type::INT4])
        .await
        .expect("prepared statement");
    let row = client
        .query_one(&statement, &[&42i32])
        .await
        .expect("prepared Execute");
    assert_eq!(row.get::<_, i32>(0), 42);

    assert!(matches!(
        next_protocol(&mut backend.events).await,
        BackendEvent::Protocol {
            connection: 1,
            kind: b'P'
        }
    ));
    let execute = next_execute(&mut backend.events).await;
    assert!(matches!(
        execute,
        BackendEvent::Execute {
            connection: 1,
            parameter_count: 1,
            ..
        }
    ));
    assert_no_execute(&mut backend.events).await;

    drop(client);
    tokio::time::timeout(Duration::from_secs(2), connection_task)
        .await
        .expect("frontend disconnect is joined")
        .expect("connection task")
        .expect("client connection closes cleanly");
    proxy.stop().await;
    backend.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn extended_execute_uses_current_wire_identity_and_session_scope() {
    let daemon = TestControlPlane::start().await;
    let mut backend = FakeBackend::start().await;
    let policy = qk_core::parse_policy(APPROVAL_POLICY).expect("approval policy");
    let proxy = start_proxy(&backend, policy, Some(daemon.client.clone())).await;
    let mut client = Frontend::connect(proxy.addr, "qk", "queryknight").await;
    let sql = "DELETE FROM customers WHERE id = $1";
    client.send(&[parse_frame("s", sql, &[23])]).await;
    assert_eq!(client.read_one().await.kind, b'1');
    client
        .send(&[bind_frame("p1", "s", &[0], &[Some(b"42")], &[])])
        .await;
    assert_eq!(client.read_one().await.kind, b'2');
    assert!(daemon
        .client
        .list_approvals()
        .expect("setup messages do not create approvals")
        .is_empty());

    client.send(&[execute_frame("p1", 0)]).await;
    let pending = client.read_one().await;
    assert_eq!(error_sqlstate(&[pending]), Some("42501".to_owned()));
    assert_no_execute(&mut backend.events).await;
    let approvals = daemon
        .client
        .list_approvals()
        .expect("pending exact approval");
    assert_eq!(approvals.len(), 1);
    assert_eq!(
        approvals[0].binding_kind,
        qk_control_plane::ApprovalBindingKind::ExactV2
    );
    daemon
        .client
        .decide_approval(
            &approvals[0].id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Once),
        )
        .expect("approve exact V2 request");
    assert_eq!(client.sync().await.1, b'I');

    client
        .send(&[bind_frame("p2", "s", &[0], &[Some(b"42")], &[])])
        .await;
    assert_eq!(client.read_one().await.kind, b'2');
    client.send(&[execute_frame("p2", 0)]).await;
    assert_eq!(client.read_one().await.kind, b'C');
    assert_eq!(client.sync().await.1, b'I');
    assert!(matches!(
        next_execute(&mut backend.events).await,
        BackendEvent::Execute {
            connection: 1,
            portal_name,
            parameter_count: 1,
            ..
        } if portal_name == "p2"
    ));

    // Same SQL, OID and semantic int4 value, but binary bytes do not reuse
    // the text ExactV2 approval.
    client
        .send(&[bind_frame(
            "p-binary",
            "s",
            &[1],
            &[Some(&[0, 0, 0, 42])],
            &[],
        )])
        .await;
    assert_eq!(client.read_one().await.kind, b'2');
    client.send(&[execute_frame("p-binary", 0)]).await;
    let binary_pending = client.read_one().await;
    assert_eq!(error_sqlstate(&[binary_pending]).as_deref(), Some("42501"));
    assert_eq!(client.sync().await.1, b'I');
    assert_no_execute(&mut backend.events).await;

    // Once ExactV2 also refuses changed text bytes. The pending approval rows
    // are now explicitly upgraded to Session for the separate session test.
    client
        .send(&[bind_frame("p-43", "s", &[0], &[Some(b"43")], &[])])
        .await;
    assert_eq!(client.read_one().await.kind, b'2');
    client.send(&[execute_frame("p-43", 0)]).await;
    let changed_pending = client.read_one().await;
    assert_eq!(error_sqlstate(&[changed_pending]).as_deref(), Some("42501"));
    assert_eq!(client.sync().await.1, b'I');
    assert_no_execute(&mut backend.events).await;
    let approvals = daemon.client.list_approvals().expect("changed approvals");
    assert_eq!(approvals.len(), 3);
    let waiting = approvals
        .iter()
        .filter(|row| row.status == qk_control_plane::ApprovalStatus::Waiting)
        .map(|row| row.id.clone())
        .collect::<Vec<_>>();
    assert_eq!(waiting.len(), 2);
    for id in waiting {
        daemon
            .client
            .decide_approval(
                &id,
                ApprovalDecision::Approved,
                qk_approval::DecisionSource::Ui,
                Some(qk_approval::Scope::Session),
            )
            .expect("approve same-shape Session grant");
    }

    client
        .send(&[bind_frame("p-44", "s", &[0], &[Some(b"44")], &[])])
        .await;
    assert_eq!(client.read_one().await.kind, b'2');
    client.send(&[execute_frame("p-44", 0)]).await;
    assert_eq!(client.read_one().await.kind, b'C');
    assert_eq!(client.sync().await.1, b'I');
    assert!(matches!(
        next_execute(&mut backend.events).await,
        BackendEvent::Execute {
            connection: 1,
            portal_name,
            ..
        } if portal_name == "p-44"
    ));

    let other_sql = "DELETE FROM customers WHERE id = $1 AND name = $2";
    client
        .send(&[parse_frame("s2", other_sql, &[23, 25])])
        .await;
    assert_eq!(client.read_one().await.kind, b'1');
    client
        .send(&[bind_frame(
            "p-shape",
            "s2",
            &[0, 0],
            &[Some(b"45"), Some(b"customer")],
            &[],
        )])
        .await;
    assert_eq!(client.read_one().await.kind, b'2');
    client.send(&[execute_frame("p-shape", 0)]).await;
    let different_shape = client.read_one().await;
    assert_eq!(error_sqlstate(&[different_shape]).as_deref(), Some("42501"));
    assert_eq!(client.sync().await.1, b'I');
    assert_no_execute(&mut backend.events).await;

    let mut other_frontend = Frontend::connect(proxy.addr, "qk", "queryknight").await;
    other_frontend.send(&[parse_frame("s", sql, &[23])]).await;
    assert_eq!(other_frontend.read_one().await.kind, b'1');
    other_frontend
        .send(&[bind_frame("p", "s", &[0], &[Some(b"44")], &[])])
        .await;
    assert_eq!(other_frontend.read_one().await.kind, b'2');
    other_frontend.send(&[execute_frame("p", 0)]).await;
    let other_session = other_frontend.read_one().await;
    assert_eq!(error_sqlstate(&[other_session]).as_deref(), Some("42501"));
    assert_eq!(other_frontend.sync().await.1, b'I');
    assert_no_execute(&mut backend.events).await;

    proxy.stop().await;
    backend.stop().await;
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_shape_grant_never_authorizes_extended_execute() {
    let daemon = TestControlPlane::start().await;
    let mut backend = FakeBackend::start().await;
    let policy = qk_core::parse_policy(APPROVAL_POLICY).expect("approval policy");
    let proxy = start_proxy(&backend, policy, Some(daemon.client.clone())).await;
    let mut client = Frontend::connect(proxy.addr, "qk", "queryknight").await;

    let sql = "DELETE FROM customers WHERE id = $1";
    let store =
        qk_store::Store::open(&daemon.home.join("queryknight.db")).expect("open test daemon store");
    let session = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(session) = store
                .list_sessions()
                .expect("list sessions")
                .into_iter()
                .find(|session| session.source == "proxy")
            {
                break session;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("proxy connection session is created");
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    store
        .insert_grant(
            &qk_approval::StoredGrant {
                id: qk_approval::ApprovalId::new("qka_legacy_proxy_execute".to_owned()),
                shape: qk_core::sql_fingerprint(sql),
                binding: qk_approval::ApprovalBinding::LegacyShape,
                scope: qk_approval::ApprovalScope {
                    session_id: Some(session.id),
                    integration: "proxy_pg".to_owned(),
                    environment: "production".to_owned(),
                    database: "main".to_owned(),
                    agent_id: String::new(),
                    tool: "proxy_query".to_owned(),
                },
                status: qk_approval::GrantStatus::Approved,
                reuse: qk_approval::Scope::Session,
                expires_at_ms: now_ms + 60_000,
                reason_code: qk_core::ReasonCode::RequireApproval,
                message: "legacy grant fixture".to_owned(),
                schema_ddl: None,
                schema_diff: None,
                risk: "high".to_owned(),
                operation_summary: "delete customers".to_owned(),
                matched_policy: None,
                decided_at_ms: Some(now_ms),
                decided_by: Some(qk_approval::DecisionSource::Ui),
            },
            now_ms,
        )
        .expect("insert quarantined legacy row");

    client.send(&[parse_frame("s", sql, &[23])]).await;
    assert_eq!(client.read_one().await.kind, b'1');
    client
        .send(&[bind_frame("p", "s", &[0], &[Some(b"42")], &[])])
        .await;
    assert_eq!(client.read_one().await.kind, b'2');
    client.send(&[execute_frame("p", 0)]).await;
    let rejected = client.read_one().await;
    assert_eq!(error_sqlstate(&[rejected]).as_deref(), Some("42501"));
    assert_eq!(client.sync().await.1, b'I');
    assert_no_execute(&mut backend.events).await;
    assert!(daemon
        .client
        .list_approvals()
        .expect("approval rows")
        .iter()
        .any(|row| row.binding_kind == qk_control_plane::ApprovalBindingKind::LegacyShape));

    proxy.stop().await;
    backend.stop().await;
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn named_statement_close_and_redefinition_never_reuse_stale_sql() {
    let mut backend = FakeBackend::start().await;
    let proxy = start_proxy(&backend, test_policy(), None).await;
    let mut client = Frontend::connect(proxy.addr, "qk", "queryknight").await;

    client.send(&[parse_frame("s", "SELECT 1", &[])]).await;
    assert_eq!(client.read_one().await.kind, b'1');
    client
        .send(&[parse_frame("s", "DROP TABLE protected_table", &[])])
        .await;
    let duplicate = client.read_one().await;
    assert_eq!(error_sqlstate(&[duplicate]).as_deref(), Some("42P05"));
    assert_eq!(client.sync().await.1, b'I');

    client.send(&[bind_frame("p", "s", &[], &[], &[])]).await;
    assert_eq!(client.read_one().await.kind, b'2');
    client.send(&[execute_frame("p", 0)]).await;
    assert_eq!(client.read_execute_terminal().await.kind, b'C');
    assert!(matches!(
        next_execute(&mut backend.events).await,
        BackendEvent::Execute {
            connection: 1,
            portal_name,
            ..
        } if portal_name == "p"
    ));

    client.send(&[target_frame(b'C', b'S', "s")]).await;
    assert_eq!(client.read_one().await.kind, b'3');
    client.send(&[execute_frame("p", 0)]).await;
    let closed_portal = client.read_one().await;
    assert_eq!(error_sqlstate(&[closed_portal]).as_deref(), Some("34000"));
    assert_eq!(client.sync().await.1, b'I');

    client
        .send(&[parse_frame("s", "DROP TABLE protected_table", &[])])
        .await;
    assert_eq!(client.read_one().await.kind, b'1');
    client.send(&[bind_frame("p2", "s", &[], &[], &[])]).await;
    assert_eq!(client.read_one().await.kind, b'2');
    client.send(&[execute_frame("p2", 0)]).await;
    let blocked = client.read_one().await;
    assert_eq!(error_sqlstate(&[blocked]).as_deref(), Some("42501"));
    assert_eq!(client.sync().await.1, b'I');
    assert_no_execute(&mut backend.events).await;

    proxy.stop().await;
    backend.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unnamed_statement_and_portal_replacement_keep_bound_versions() {
    let mut backend = FakeBackend::start().await;
    let proxy = start_proxy(&backend, test_policy(), None).await;
    let mut client = Frontend::connect(proxy.addr, "qk", "queryknight").await;

    client.send(&[parse_frame("", "SELECT 1", &[])]).await;
    assert_eq!(client.read_one().await.kind, b'1');
    client.send(&[bind_frame("", "", &[], &[], &[])]).await;
    assert_eq!(client.read_one().await.kind, b'2');

    // Replacing the unnamed statement does not rewrite the SQL snapshot of
    // a portal that was already bound to the prior statement version.
    client
        .send(&[parse_frame("", "DROP TABLE protected_table", &[])])
        .await;
    assert_eq!(client.read_one().await.kind, b'1');
    client.send(&[execute_frame("", 0)]).await;
    assert_eq!(client.read_execute_terminal().await.kind, b'C');
    let BackendEvent::Execute {
        connection,
        portal_name,
        ..
    } = next_execute(&mut backend.events).await
    else {
        unreachable!()
    };
    assert_eq!(connection, 1);
    assert!(portal_name.is_empty());
    assert_eq!(client.sync().await.1, b'I');

    // A new unnamed Bind replaces that portal and binds the current,
    // dangerous unnamed statement; it is blocked before backend Execute.
    client.send(&[bind_frame("", "", &[], &[], &[])]).await;
    assert_eq!(client.read_one().await.kind, b'2');
    client.send(&[execute_frame("", 0)]).await;
    let blocked = client.read_one().await;
    assert_eq!(error_sqlstate(&[blocked]).as_deref(), Some("42501"));
    assert_eq!(client.sync().await.1, b'I');
    assert_no_execute(&mut backend.events).await;

    proxy.stop().await;
    backend.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn named_portal_rebind_cannot_substitute_statement_identity() {
    let mut backend = FakeBackend::start().await;
    let proxy = start_proxy(&backend, test_policy(), None).await;
    let mut client = Frontend::connect(proxy.addr, "qk", "queryknight").await;
    let (_, status) = client.simple_query("SELECT BACKEND_TX_BEGIN").await;
    assert_eq!(status, b'T');
    let _ = next_query(&mut backend.events).await;

    client.send(&[parse_frame("safe", "SELECT 1", &[])]).await;
    assert_eq!(client.read_one().await.kind, b'1');
    client
        .send(&[parse_frame("danger", "DROP TABLE protected_table", &[])])
        .await;
    assert_eq!(client.read_one().await.kind, b'1');
    client
        .send(&[bind_frame("portal", "safe", &[], &[], &[])])
        .await;
    assert_eq!(client.read_one().await.kind, b'2');

    // PostgreSQL rejects a duplicate named portal; its original binding and
    // the QueryKnight portal snapshot remain intact across Sync in T state.
    client
        .send(&[bind_frame("portal", "danger", &[], &[], &[])])
        .await;
    let duplicate = client.read_one().await;
    assert_eq!(error_sqlstate(&[duplicate]).as_deref(), Some("42P03"));
    assert_eq!(client.sync().await.1, b'T');
    client.send(&[execute_frame("portal", 0)]).await;
    assert_eq!(client.read_execute_terminal().await.kind, b'C');
    assert_eq!(client.sync().await.1, b'T');
    assert!(matches!(
        next_execute(&mut backend.events).await,
        BackendEvent::Execute {
            connection: 1,
            portal_name,
            ..
        } if portal_name == "portal"
    ));

    client.send(&[target_frame(b'C', b'P', "portal")]).await;
    assert_eq!(client.read_one().await.kind, b'3');
    client
        .send(&[bind_frame("portal", "danger", &[], &[], &[])])
        .await;
    assert_eq!(client.read_one().await.kind, b'2');
    client.send(&[execute_frame("portal", 0)]).await;
    let blocked = client.read_one().await;
    assert_eq!(error_sqlstate(&[blocked]).as_deref(), Some("42501"));
    assert_eq!(client.sync().await.1, b'T');
    assert_no_execute(&mut backend.events).await;

    proxy.stop().await;
    backend.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_frontends_isolate_same_statement_and_portal_names() {
    let mut backend = FakeBackend::start().await;
    let proxy = start_proxy(&backend, test_policy(), None).await;
    let mut client_a = Frontend::connect(proxy.addr, "qk", "queryknight").await;
    let mut client_b = Frontend::connect(proxy.addr, "qk", "queryknight").await;

    client_a.send(&[parse_frame("s", "SELECT 1", &[])]).await;
    client_b
        .send(&[parse_frame("s", "DROP TABLE protected_table", &[])])
        .await;
    assert_eq!(client_a.read_one().await.kind, b'1');
    assert_eq!(client_b.read_one().await.kind, b'1');
    client_a.send(&[bind_frame("p", "s", &[], &[], &[])]).await;
    client_b.send(&[bind_frame("p", "s", &[], &[], &[])]).await;
    assert_eq!(client_a.read_one().await.kind, b'2');
    assert_eq!(client_b.read_one().await.kind, b'2');

    client_a
        .send(&[execute_frame("p", 0), encode_message(b'S', &[]).unwrap()])
        .await;
    client_b
        .send(&[execute_frame("p", 0), encode_message(b'S', &[]).unwrap()])
        .await;
    let ((response_a, status_a), (response_b, status_b)) =
        tokio::join!(client_a.read_until_ready(), client_b.read_until_ready());
    assert_eq!(status_a, b'I');
    assert!(response_a.iter().any(|frame| frame.kind == b'C'));
    assert_eq!(status_b, b'I');
    assert_eq!(error_sqlstate(&response_b).as_deref(), Some("42501"));

    assert!(matches!(
        next_execute(&mut backend.events).await,
        BackendEvent::Execute {
            connection: 1,
            portal_name,
            ..
        } if portal_name == "p"
    ));
    assert_no_execute(&mut backend.events).await;

    proxy.stop().await;
    backend.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backend_parse_bind_and_execute_errors_keep_protocol_state_coherent() {
    let mut backend = FakeBackend::start().await;
    let proxy = start_proxy(&backend, test_policy(), None).await;
    let mut client = Frontend::connect(proxy.addr, "qk", "queryknight").await;

    client
        .send(&[parse_frame("bad-parse", "SELECT BACKEND_PARSE_ERROR", &[])])
        .await;
    let parse_error = client.read_one().await;
    assert_eq!(error_sqlstate(&[parse_error]).as_deref(), Some("42601"));
    assert_eq!(client.sync().await.1, b'I');

    client
        .send(&[bind_frame("missing", "bad-parse", &[], &[], &[])])
        .await;
    let missing_statement = client.read_one().await;
    assert_eq!(
        error_sqlstate(&[missing_statement]).as_deref(),
        Some("26000")
    );
    assert_eq!(client.sync().await.1, b'I');

    client
        .send(&[parse_frame("int-statement", "SELECT $1::int4", &[23])])
        .await;
    assert_eq!(client.read_one().await.kind, b'1');
    client
        .send(&[bind_frame(
            "bad-bind",
            "int-statement",
            &[0],
            &[Some(b"not-an-int")],
            &[],
        )])
        .await;
    let bind_error = client.read_one().await;
    assert_eq!(error_sqlstate(&[bind_error]).as_deref(), Some("22P02"));
    assert_eq!(client.sync().await.1, b'I');
    client.send(&[execute_frame("bad-bind", 0)]).await;
    let missing_portal = client.read_one().await;
    assert_eq!(error_sqlstate(&[missing_portal]).as_deref(), Some("34000"));
    assert_eq!(client.sync().await.1, b'I');
    assert_no_execute(&mut backend.events).await;

    client
        .send(&[parse_frame(
            "runtime-error",
            "SELECT BACKEND_EXECUTE_ERROR",
            &[],
        )])
        .await;
    assert_eq!(client.read_one().await.kind, b'1');
    client
        .send(&[bind_frame("runtime-portal", "runtime-error", &[], &[], &[])])
        .await;
    assert_eq!(client.read_one().await.kind, b'2');
    client.send(&[execute_frame("runtime-portal", 0)]).await;
    let execute_error = client.read_one().await;
    assert_eq!(error_sqlstate(&[execute_error]).as_deref(), Some("22012"));
    assert_eq!(client.sync().await.1, b'I');
    assert!(matches!(
        next_execute(&mut backend.events).await,
        BackendEvent::Execute {
            portal_name,
            ..
        } if portal_name == "runtime-portal"
    ));
    client.send(&[execute_frame("runtime-portal", 0)]).await;
    let failed_portal = client.read_one().await;
    assert_eq!(error_sqlstate(&[failed_portal]).as_deref(), Some("34000"));
    assert_eq!(client.sync().await.1, b'I');
    assert_no_execute(&mut backend.events).await;

    proxy.stop().await;
    backend.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn portal_suspension_requires_a_fresh_once_permit_for_each_execute() {
    let daemon = TestControlPlane::start().await;
    let mut backend = FakeBackend::start().await;
    let policy = qk_core::parse_policy(
        r#"
version: 1
defaults:
  decision: deny
  on_parse_error: deny
  on_unknown: require_approval
environments:
  production:
    databases:
      main:
        approval_required:
          - operations: [select]
"#,
    )
    .expect("approval policy");
    let proxy = start_proxy(&backend, policy, Some(daemon.client.clone())).await;
    let mut client = Frontend::connect(proxy.addr, "qk", "queryknight").await;

    let (waiting, status) = client.simple_query("SELECT BACKEND_TX_BEGIN").await;
    assert_eq!(status, b'I');
    assert_eq!(error_sqlstate(&waiting).as_deref(), Some("42501"));
    let request = daemon
        .client
        .list_approvals()
        .expect("transaction approval")
        .into_iter()
        .find(|row| row.status == qk_control_plane::ApprovalStatus::Waiting)
        .expect("transaction waiting");
    daemon
        .client
        .decide_approval(
            &request.id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Once),
        )
        .expect("approve transaction query");
    let (_, status) = client.simple_query("SELECT BACKEND_TX_BEGIN").await;
    assert_eq!(status, b'T');
    let _ = next_query(&mut backend.events).await;

    client
        .send(&[parse_frame("s", "SELECT $1::int4", &[23])])
        .await;
    assert_eq!(client.read_one().await.kind, b'1');
    client
        .send(&[bind_frame("p", "s", &[0], &[Some(b"7")], &[])])
        .await;
    assert_eq!(client.read_one().await.kind, b'2');
    client.send(&[execute_frame("p", 1)]).await;
    let pending = client.read_one().await;
    assert_eq!(error_sqlstate(&[pending]).as_deref(), Some("42501"));
    assert_no_execute(&mut backend.events).await;
    assert_eq!(client.sync().await.1, b'T');
    let prepared_request = daemon
        .client
        .list_approvals()
        .expect("prepared approval")
        .into_iter()
        .find(|row| row.status == qk_control_plane::ApprovalStatus::Waiting)
        .expect("prepared request waiting");
    daemon
        .client
        .decide_approval(
            &prepared_request.id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Once),
        )
        .expect("approve prepared request");

    client.send(&[execute_frame("p", 1)]).await;
    assert_eq!(client.read_one().await.kind, b'D');
    assert_eq!(client.read_one().await.kind, b's');
    client.send(&[execute_frame("p", 1)]).await;
    assert_eq!(client.read_one().await.kind, b'D');
    assert_eq!(client.read_one().await.kind, b'C');
    assert_eq!(client.sync().await.1, b'T');

    for _ in 0..2 {
        assert!(matches!(
            next_execute(&mut backend.events).await,
            BackendEvent::Execute {
                connection: 1,
                portal_name,
                max_rows: 1,
                parameter_count: 1,
            } if portal_name == "p"
        ));
    }
    assert_no_execute(&mut backend.events).await;
    proxy.stop().await;
    backend.stop().await;
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bind_sentinel_never_leaks_to_extended_errors_or_daemon_metadata() {
    let daemon = TestControlPlane::start().await;
    let mut backend = FakeBackend::start().await;
    let policy = qk_core::parse_policy(APPROVAL_POLICY).expect("approval policy");
    let proxy = start_proxy(&backend, policy, Some(daemon.client.clone())).await;
    let mut client = Frontend::connect(proxy.addr, "qk", "queryknight").await;
    let sentinel = "PG_BIND_SECRET_8675309";
    let sql = "DELETE FROM customers WHERE name = $1";

    client.send(&[parse_frame("s", sql, &[25])]).await;
    assert_eq!(client.read_one().await.kind, b'1');
    client
        .send(&[bind_frame(
            "p",
            "s",
            &[0],
            &[Some(sentinel.as_bytes())],
            &[],
        )])
        .await;
    assert_eq!(client.read_one().await.kind, b'2');
    client.send(&[execute_frame("p", 0)]).await;
    let error = client.read_one().await;
    assert!(!error
        .raw
        .windows(sentinel.len())
        .any(|window| window == sentinel.as_bytes()));
    assert!(!format!("{error:?}").contains(sentinel));
    assert_eq!(
        error_sqlstate(std::slice::from_ref(&error)).as_deref(),
        Some("42501")
    );
    assert_no_execute(&mut backend.events).await;

    let summaries = daemon.client.list_approvals().expect("daemon summaries");
    assert!(summaries
        .iter()
        .all(|row| !row.reason.contains(sentinel) && !row.operation_summary.contains(sentinel)));
    assert!(!format!("{summaries:?}").contains(sentinel));
    proxy.stop().await;
    backend.stop().await;
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn describe_portal_and_frontend_flush_are_protocol_only() {
    let mut backend = FakeBackend::start().await;
    let proxy = start_proxy(&backend, test_policy(), None).await;
    let mut client = Frontend::connect(proxy.addr, "qk", "queryknight").await;

    client.send(&[parse_frame("s", "SELECT 1", &[])]).await;
    assert_eq!(client.read_one().await.kind, b'1');
    assert!(matches!(
        next_protocol(&mut backend.events).await,
        BackendEvent::Protocol {
            connection: 1,
            kind: b'P'
        }
    ));
    assert!(matches!(
        next_protocol(&mut backend.events).await,
        BackendEvent::Protocol {
            connection: 1,
            kind: b'H'
        }
    ));

    client.send(&[bind_frame("p", "s", &[], &[], &[])]).await;
    assert_eq!(client.read_one().await.kind, b'2');
    assert!(matches!(
        next_protocol(&mut backend.events).await,
        BackendEvent::Protocol {
            connection: 1,
            kind: b'B'
        }
    ));
    assert!(matches!(
        next_protocol(&mut backend.events).await,
        BackendEvent::Protocol {
            connection: 1,
            kind: b'H'
        }
    ));

    client.send(&[target_frame(b'D', b'P', "p")]).await;
    assert_eq!(client.read_one().await.kind, b'T');
    assert!(matches!(
        next_protocol(&mut backend.events).await,
        BackendEvent::Protocol {
            connection: 1,
            kind: b'D'
        }
    ));
    assert!(matches!(
        next_protocol(&mut backend.events).await,
        BackendEvent::Protocol {
            connection: 1,
            kind: b'H'
        }
    ));

    client.send(&[encode_message(b'H', &[]).unwrap()]).await;
    assert!(matches!(
        next_protocol(&mut backend.events).await,
        BackendEvent::Protocol {
            connection: 1,
            kind: b'H'
        }
    ));
    assert_eq!(client.sync().await.1, b'I');
    assert_no_execute(&mut backend.events).await;

    proxy.stop().await;
    backend.stop().await;
}
