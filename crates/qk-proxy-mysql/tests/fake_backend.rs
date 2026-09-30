use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mysql_async::prelude::Queryable;
use mysql_async::{ChangeUserOpts, Conn, Opts};
use qk_control_plane::{ApprovalDecision, ControlPlaneClient};
use qk_db::DbConfig;
use qk_proxy_mysql::{ProxyConfig, ProxyServer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinSet;

const MYSQL_BACKEND_SECRET: &str = "MYSQL_BACKEND_SECRET_12345";
const MYSQL_AUTH_SECRET: &str = "MYSQL_AUTH_SECRET_67890";
const CAP_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CAP_COMPRESS: u32 = 0x0000_0020;
const CAP_LOCAL_FILES: u32 = 0x0000_0080;
const CAP_PROTOCOL_41: u32 = 0x0000_0200;
const CAP_SSL: u32 = 0x0000_0800;
const CAP_SECURE_CONNECTION: u32 = 0x0000_8000;
const CAP_MULTI_STATEMENTS: u32 = 0x0001_0000;
const CAP_MULTI_RESULTS: u32 = 0x0002_0000;
const CAP_PS_MULTI_RESULTS: u32 = 0x0004_0000;
const CAP_PLUGIN_AUTH: u32 = 0x0008_0000;
const CAP_PLUGIN_AUTH_LENENC: u32 = 0x0020_0000;
const CAP_DEPRECATE_EOF: u32 = 0x0100_0000;
const FORBIDDEN_CLIENT_CAPABILITIES: u32 = CAP_COMPRESS
    | CAP_LOCAL_FILES
    | CAP_SSL
    | CAP_MULTI_STATEMENTS
    | CAP_DEPRECATE_EOF
    | CAP_PS_MULTI_RESULTS
    | 0x0800_0000; // CLIENT_QUERY_ATTRIBUTES

const ALLOW_POLICY: &str = r#"
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
          - operations: [select, insert, set, transaction]
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
        allow:
          - operations: [select]
        approval_required:
          - operations: [delete]
"#;

#[derive(Clone, Debug)]
struct QueryEvent {
    connection: usize,
    sql: String,
    in_transaction: bool,
    autocommit: bool,
}

#[derive(Default)]
struct Facts {
    login_flags: Vec<u32>,
    commands: Vec<u8>,
    auth_responses: usize,
    queries: Vec<QueryEvent>,
    prepared_statements: Vec<(usize, u32, String)>,
    long_data: Vec<(usize, u32, u16, Vec<u8>)>,
    execute_bind_flags: Vec<u8>,
    local_infile_data_packets: usize,
    mutations: usize,
}

struct FakeMysql {
    addr: std::net::SocketAddr,
    facts: Arc<Mutex<Facts>>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl FakeMysql {
    async fn start() -> Self {
        Self::start_with_auth_more_data(None).await
    }

    async fn start_full_auth() -> Self {
        Self::start_with_auth_more_data(Some(0x04)).await
    }

    async fn start_with_auth_more_data(auth_more_data: Option<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("backend bind");
        let addr = listener.local_addr().expect("backend address");
        let facts = Arc::new(Mutex::new(Facts::default()));
        let worker_facts = facts.clone();
        let connection_counter = Arc::new(AtomicUsize::new(0));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut clients = JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    joined = clients.join_next(), if !clients.is_empty() => {
                        let _ = joined;
                    }
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        let connection = connection_counter.fetch_add(1, Ordering::Relaxed) + 1;
                        let facts = worker_facts.clone();
                        clients.spawn(async move {
                            serve_mysql_client(stream, connection, facts, auth_more_data).await;
                        });
                    }
                }
            }
            clients.abort_all();
            while clients.join_next().await.is_some() {}
        });
        Self {
            addr,
            facts,
            shutdown: Some(shutdown_tx),
            task: Some(task),
        }
    }

    fn query_count(&self) -> usize {
        self.facts.lock().expect("facts").queries.len()
    }

    fn mutation_count(&self) -> usize {
        self.facts.lock().expect("facts").mutations
    }

    fn login_flags(&self) -> Vec<u32> {
        self.facts.lock().expect("facts").login_flags.clone()
    }

    fn queries(&self) -> Vec<QueryEvent> {
        self.facts.lock().expect("facts").queries.clone()
    }
    fn auth_responses(&self) -> usize {
        self.facts.lock().expect("facts").auth_responses
    }

    fn commands(&self) -> Vec<u8> {
        self.facts.lock().expect("facts").commands.clone()
    }

    fn prepared_execute_count(&self) -> usize {
        self.facts
            .lock()
            .expect("facts")
            .commands
            .iter()
            .filter(|command| **command == 0x17)
            .count()
    }

    fn prepared_statements(&self) -> Vec<(usize, u32, String)> {
        self.facts
            .lock()
            .expect("facts")
            .prepared_statements
            .clone()
    }

    fn long_data(&self) -> Vec<(usize, u32, u16, Vec<u8>)> {
        self.facts.lock().expect("facts").long_data.clone()
    }
    fn execute_bind_flags(&self) -> Vec<u8> {
        self.facts.lock().expect("facts").execute_bind_flags.clone()
    }
    fn local_infile_data_packets(&self) -> usize {
        self.facts.lock().expect("facts").local_infile_data_packets
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

struct RunningProxy {
    addr: std::net::SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<(), qk_proxy_mysql::ProxyError>>>,
}

impl RunningProxy {
    async fn start(
        backend: &FakeMysql,
        policy: qk_core::PolicyFile,
        control_plane: Option<ControlPlaneClient>,
    ) -> Self {
        let url = format!(
            "mysql://qk:{MYSQL_BACKEND_SECRET}@127.0.0.1:{}/qk",
            backend.addr.port()
        );
        let db_config = DbConfig::from_url(&url).expect("typed MySQL URL");
        let key = format!("mysql://qk@127.0.0.1:{}/qk", backend.addr.port());
        let config = ProxyConfig::new(
            0,
            db_config,
            key,
            "production".to_owned(),
            "main".to_owned(),
            policy,
            control_plane,
        )
        .expect("proxy config");
        assert!(!format!("{config:?}").contains(MYSQL_BACKEND_SECRET));
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
        Self {
            addr,
            shutdown: Some(shutdown_tx),
            task: Some(task),
        }
    }

    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.await.expect("proxy task").expect("proxy shutdown");
        }
    }
}

async fn connect_client(addr: std::net::SocketAddr) -> Conn {
    let url = format!(
        "mysql://qk:{MYSQL_AUTH_SECRET}@127.0.0.1:{}/qk",
        addr.port()
    );
    let options: Opts =
        mysql_async::OptsBuilder::from_opts(Opts::from_url(&url).expect("client options"))
            .max_allowed_packet(Some(16 * 1024 * 1024))
            .wait_timeout(Some(28_800))
            .prefer_socket(Some(false))
            .into();
    Conn::new(options)
        .await
        .expect("connect through MySQL proxy")
}
struct RawMysqlClient {
    stream: TcpStream,
}

impl RawMysqlClient {
    async fn connect(address: std::net::SocketAddr) -> Self {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("raw client connect");
        let (sequence, greeting) = read_packet(&mut stream).await.expect("MySQL greeting");
        assert_eq!(sequence, 0);
        let mut offset = 1;
        let version_len = greeting[offset..]
            .iter()
            .position(|byte| *byte == 0)
            .expect("server version");
        offset += version_len + 1 + 4;
        let nonce_first = greeting[offset..offset + 8].to_vec();
        offset += 9 + 2 + 1 + 2 + 2;
        let auth_len = usize::from(greeting[offset]);
        offset += 1 + 10;
        let auth_tail_len = auth_len.saturating_sub(8).max(13);
        let auth_tail = &greeting[offset..offset + auth_tail_len];
        let mut nonce = nonce_first;
        nonce.extend_from_slice(&auth_tail[..12]);
        offset += auth_tail_len;
        let plugin = greeting[offset..]
            .split(|byte| *byte == 0)
            .next()
            .expect("authentication plugin");
        assert_eq!(plugin, b"caching_sha2_password");

        let capabilities = CAP_CONNECT_WITH_DB
            | CAP_PROTOCOL_41
            | CAP_SECURE_CONNECTION
            | CAP_MULTI_RESULTS
            | CAP_PLUGIN_AUTH;
        let mut login = Vec::new();
        login.extend_from_slice(&capabilities.to_le_bytes());
        login.extend_from_slice(&0x0100_0000u32.to_le_bytes());
        login.push(45);
        login.extend_from_slice(&[0; 23]);
        login.extend_from_slice(b"qk\0");
        let token = caching_sha2_token(MYSQL_AUTH_SECRET.as_bytes(), &nonce);
        login.push(token.len() as u8);
        login.extend_from_slice(&token);
        login.extend_from_slice(b"qk\0caching_sha2_password\0");
        write_packet(&mut stream, 1, &login)
            .await
            .expect("raw handshake response");
        let mut expected_sequence = 2u8;
        loop {
            let (sequence, response) = read_packet(&mut stream).await.expect("auth response");
            assert_eq!(sequence, expected_sequence);
            expected_sequence = expected_sequence.wrapping_add(1);
            match response.as_slice() {
                [0x00, ..] => break,
                [0x01, 0x03] => continue,
                [0xff, ..] => panic!("raw client authentication failed"),
                _ => panic!("unexpected MySQL authentication response"),
            }
        }
        Self { stream }
    }

    async fn prepare(&mut self, sql: &str) -> u32 {
        let mut payload = vec![0x16];
        payload.extend_from_slice(sql.as_bytes());
        write_packet(&mut self.stream, 0, &payload)
            .await
            .expect("send COM_STMT_PREPARE");
        let (sequence, response) = read_packet(&mut self.stream)
            .await
            .expect("prepare response");
        assert_eq!(sequence, 1);
        assert_eq!(response.first(), Some(&0x00));
        let statement_id = u32::from_le_bytes([response[1], response[2], response[3], response[4]]);
        let column_count = usize::from(u16::from_le_bytes([response[5], response[6]]));
        let parameter_count = usize::from(u16::from_le_bytes([response[7], response[8]]));
        let mut expected_sequence = 2u8;
        for count in [parameter_count, column_count] {
            for _ in 0..count {
                let (sequence, packet) = read_packet(&mut self.stream)
                    .await
                    .expect("prepared metadata");
                assert_eq!(sequence, expected_sequence);
                assert!(!packet.is_empty());
                expected_sequence = expected_sequence.wrapping_add(1);
            }
            if count != 0 {
                let (sequence, terminator) = read_packet(&mut self.stream)
                    .await
                    .expect("prepared metadata terminator");
                assert_eq!(sequence, expected_sequence);
                assert_eq!(terminator.first(), Some(&0xfe));
                expected_sequence = expected_sequence.wrapping_add(1);
            }
        }
        statement_id
    }

    async fn send_long_data(&mut self, statement_id: u32, parameter: u16, bytes: &[u8]) {
        let mut payload = vec![0x18];
        payload.extend_from_slice(&statement_id.to_le_bytes());
        payload.extend_from_slice(&parameter.to_le_bytes());
        payload.extend_from_slice(bytes);
        write_packet(&mut self.stream, 0, &payload)
            .await
            .expect("send COM_STMT_SEND_LONG_DATA");
    }

    async fn execute_one_string(&mut self, statement_id: u32, bind_types: bool) -> Vec<u8> {
        let mut payload = vec![0x17];
        payload.extend_from_slice(&statement_id.to_le_bytes());
        payload.push(0);
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.push(0);
        payload.push(u8::from(bind_types));
        if bind_types {
            payload.extend_from_slice(&[0xfd, 0]);
        }
        write_packet(&mut self.stream, 0, &payload)
            .await
            .expect("send COM_STMT_EXECUTE");
        let (sequence, response) = read_packet(&mut self.stream)
            .await
            .expect("execute response");
        assert_eq!(sequence, 1);
        response
    }

    async fn execute_without_parameters(&mut self, statement_id: u32) -> Result<Vec<u8>, ()> {
        let mut payload = vec![0x17];
        payload.extend_from_slice(&statement_id.to_le_bytes());
        payload.push(0);
        payload.extend_from_slice(&1u32.to_le_bytes());
        write_packet(&mut self.stream, 0, &payload).await?;
        let (sequence, response) = read_packet(&mut self.stream).await?;
        if sequence != 1 {
            return Err(());
        }
        Ok(response)
    }
    async fn reset_statement(&mut self, statement_id: u32) -> Vec<u8> {
        let mut payload = vec![0x1a];
        payload.extend_from_slice(&statement_id.to_le_bytes());
        write_packet(&mut self.stream, 0, &payload)
            .await
            .expect("send COM_STMT_RESET");
        let (sequence, response) = read_packet(&mut self.stream).await.expect("reset response");
        assert_eq!(sequence, 1);
        response
    }

    async fn close_statement(&mut self, statement_id: u32) {
        let mut payload = vec![0x19];
        payload.extend_from_slice(&statement_id.to_le_bytes());
        write_packet(&mut self.stream, 0, &payload)
            .await
            .expect("send COM_STMT_CLOSE");
    }
}

fn caching_sha2_token(password: &[u8], nonce: &[u8]) -> Vec<u8> {
    let first = Sha256::digest(password);
    let second = Sha256::digest(first);
    let mut salt = Vec::with_capacity(second.len() + nonce.len());
    salt.extend_from_slice(&second);
    salt.extend_from_slice(nonce);
    let third = Sha256::digest(salt);
    first
        .iter()
        .zip(third.iter())
        .map(|(left, right)| left ^ right)
        .collect()
}

fn status_flags(in_transaction: bool, autocommit: bool) -> u16 {
    (if in_transaction { 1 } else { 0 }) | (if autocommit { 2 } else { 0 })
}

async fn serve_mysql_client(
    mut stream: TcpStream,
    connection: usize,
    facts: Arc<Mutex<Facts>>,
    auth_more_data: Option<u8>,
) {
    let greeting = server_greeting();
    if write_packet(&mut stream, 0, &greeting).await.is_err() {
        return;
    }
    let Ok((login_sequence, login)) = read_packet(&mut stream).await else {
        return;
    };
    if login_sequence != 1 || login.len() < 4 {
        return;
    }
    let flags = u32::from_le_bytes([login[0], login[1], login[2], login[3]]);
    facts.lock().expect("facts").login_flags.push(flags);
    if let Some(code) = auth_more_data {
        if write_packet(&mut stream, 2, &[0x01, code]).await.is_err() {
            return;
        }
        if let Ok((sequence, _)) = read_packet(&mut stream).await {
            if sequence == 3 {
                facts.lock().expect("facts").auth_responses += 1;
            }
        }
        return;
    }
    let ok = [0x00, 0, 0, 2, 0, 0, 0];
    if write_packet(&mut stream, 2, &ok).await.is_err() {
        return;
    }

    let mut in_transaction = false;
    let mut autocommit = true;
    let mut session_value = 0u64;
    let mut prepared_statements = HashMap::<u32, String>::new();
    let mut next_statement_id = 1u32;
    loop {
        let Ok((sequence, payload)) = read_packet(&mut stream).await else {
            return;
        };
        if sequence != 0 || payload.is_empty() {
            return;
        }
        facts.lock().expect("facts").commands.push(payload[0]);
        match payload[0] {
            0x01 => return,
            0x0e => {
                if write_packet(&mut stream, 1, &ok).await.is_err() {
                    return;
                }
            }
            0x16 => {
                let Ok(sql) = std::str::from_utf8(&payload[1..]) else {
                    return;
                };
                let normalized = sql.trim().to_ascii_lowercase();
                if normalized.starts_with("select backend_syntax_error") || normalized.contains(';')
                {
                    if write_backend_error(&mut stream, 1).await.is_err() {
                        return;
                    }
                    continue;
                }
                let statement_id = next_statement_id;
                let Some(next) = next_statement_id.checked_add(1) else {
                    return;
                };
                next_statement_id = next;
                let parameter_count = sql.bytes().filter(|byte| *byte == b'?').count();
                let column_count = usize::from(normalized.starts_with("select"));
                prepared_statements.insert(statement_id, sql.to_owned());
                facts.lock().expect("facts").prepared_statements.push((
                    connection,
                    statement_id,
                    sql.to_owned(),
                ));
                if write_prepare_response(&mut stream, statement_id, parameter_count, column_count)
                    .await
                    .is_err()
                {
                    return;
                }
            }
            0x17 => {
                facts
                    .lock()
                    .expect("facts")
                    .execute_bind_flags
                    .push(payload.get(11).copied().unwrap_or(0xff));
                if payload.len() < 5 {
                    return;
                }
                let statement_id =
                    u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
                let Some(sql) = prepared_statements.get(&statement_id) else {
                    if write_backend_error(&mut stream, 1).await.is_err() {
                        return;
                    }
                    continue;
                };
                let normalized = sql.trim().to_ascii_lowercase();
                if normalized.starts_with("select prepared_local_infile") {
                    if write_packet(&mut stream, 1, &[0xfb, b'/']).await.is_err() {
                        return;
                    }
                    if read_packet(&mut stream).await.is_ok() {
                        facts.lock().expect("facts").local_infile_data_packets += 1;
                    }
                    return;
                } else if normalized.starts_with("select backend_execute_error") {
                    if write_backend_error(&mut stream, 1).await.is_err() {
                        return;
                    }
                } else if normalized.starts_with("select") {
                    if write_binary_resultset(
                        &mut stream,
                        1,
                        1,
                        status_flags(in_transaction, autocommit),
                    )
                    .await
                    .is_err()
                    {
                        return;
                    }
                } else {
                    if normalized.starts_with("insert")
                        || normalized.starts_with("delete")
                        || normalized.starts_with("update")
                    {
                        facts.lock().expect("facts").mutations += 1;
                    }
                    if write_ok(&mut stream, 1, status_flags(in_transaction, autocommit))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
            0x18 => {
                if payload.len() < 7 {
                    return;
                }
                let statement_id =
                    u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
                let parameter_index = u16::from_le_bytes([payload[5], payload[6]]);
                facts.lock().expect("facts").long_data.push((
                    connection,
                    statement_id,
                    parameter_index,
                    payload[7..].to_vec(),
                ));
            }
            0x19 => {
                if payload.len() != 5 {
                    return;
                }
                let statement_id =
                    u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
                prepared_statements.remove(&statement_id);
                next_statement_id = statement_id;
            }
            0x1a => {
                if payload.len() != 5 {
                    return;
                }
                let statement_id =
                    u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
                if !prepared_statements.contains_key(&statement_id) {
                    if write_backend_error(&mut stream, 1).await.is_err() {
                        return;
                    }
                } else if write_ok(&mut stream, 1, status_flags(in_transaction, autocommit))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            0x1c => {
                if write_backend_error(&mut stream, 1).await.is_err() {
                    return;
                }
            }
            0x03 => {
                let Ok(sql) = std::str::from_utf8(&payload[1..]) else {
                    return;
                };
                let normalized = sql.trim().to_ascii_lowercase();
                facts.lock().expect("facts").queries.push(QueryEvent {
                    connection,
                    sql: sql.to_owned(),
                    in_transaction,
                    autocommit,
                });
                if normalized.starts_with("select backend_syntax_error") || normalized.contains(';')
                {
                    if write_backend_error(&mut stream, 1).await.is_err() {
                        return;
                    }
                } else if normalized.starts_with("start transaction") || normalized == "begin" {
                    in_transaction = true;
                    if write_ok(&mut stream, 1, 0x0003).await.is_err() {
                        return;
                    }
                } else if normalized.starts_with("commit") || normalized.starts_with("rollback") {
                    in_transaction = false;
                    if write_ok(&mut stream, 1, if autocommit { 0x0002 } else { 0 })
                        .await
                        .is_err()
                    {
                        return;
                    }
                } else if normalized.starts_with("set autocommit = 0")
                    || normalized.starts_with("set autocommit=0")
                {
                    autocommit = false;
                    if write_ok(&mut stream, 1, 0).await.is_err() {
                        return;
                    }
                } else if normalized.starts_with("set autocommit = 1")
                    || normalized.starts_with("set autocommit=1")
                {
                    autocommit = true;
                    if write_ok(&mut stream, 1, if in_transaction { 0x0001 } else { 0x0002 })
                        .await
                        .is_err()
                    {
                        return;
                    }
                } else if normalized.starts_with("set @qk_test") {
                    if let Some(value) = sql
                        .split('=')
                        .nth(1)
                        .and_then(|value| value.trim().parse().ok())
                    {
                        session_value = value;
                    }
                    if write_ok(&mut stream, 1, status_flags(in_transaction, autocommit))
                        .await
                        .is_err()
                    {
                        return;
                    }
                } else if normalized.starts_with("select @qk_test") {
                    if write_resultset(
                        &mut stream,
                        1,
                        session_value,
                        status_flags(in_transaction, autocommit),
                    )
                    .await
                    .is_err()
                    {
                        return;
                    }
                } else if normalized.starts_with("select") {
                    if write_resultset(&mut stream, 1, 1, status_flags(in_transaction, autocommit))
                        .await
                        .is_err()
                    {
                        return;
                    }
                } else {
                    if normalized.starts_with("insert")
                        || normalized.starts_with("delete")
                        || normalized.starts_with("update")
                    {
                        facts.lock().expect("facts").mutations += 1;
                    }
                    if write_ok(&mut stream, 1, status_flags(in_transaction, autocommit))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
            _ => return,
        }
    }
}

fn server_greeting() -> Vec<u8> {
    let capabilities = CAP_CONNECT_WITH_DB
        | CAP_PROTOCOL_41
        | CAP_SECURE_CONNECTION
        | CAP_MULTI_RESULTS
        | CAP_PLUGIN_AUTH
        | CAP_PLUGIN_AUTH_LENENC
        | CAP_SSL
        | CAP_COMPRESS
        | CAP_MULTI_STATEMENTS
        | CAP_LOCAL_FILES
        | CAP_PS_MULTI_RESULTS
        | CAP_DEPRECATE_EOF;
    let mut payload = vec![10];
    payload.extend_from_slice(b"8.4.0-fake\0");
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(b"abcdefgh");
    payload.push(0);
    payload.extend_from_slice(&(capabilities as u16).to_le_bytes());
    payload.push(45);
    payload.extend_from_slice(&2u16.to_le_bytes());
    payload.extend_from_slice(&((capabilities >> 16) as u16).to_le_bytes());
    payload.push(21);
    payload.extend_from_slice(&[0; 10]);
    payload.extend_from_slice(b"ijklmnopqrst\0");
    payload.extend_from_slice(b"caching_sha2_password\0");
    payload
}

async fn read_packet(stream: &mut TcpStream) -> Result<(u8, Vec<u8>), ()> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.map_err(|_| ())?;
    let length =
        usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
    if length > 4 * 1024 * 1024 {
        return Err(());
    }
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await.map_err(|_| ())?;
    Ok((header[3], payload))
}

async fn write_packet(stream: &mut TcpStream, sequence: u8, payload: &[u8]) -> Result<(), ()> {
    let length = payload.len();
    let header = [
        length as u8,
        (length >> 8) as u8,
        (length >> 16) as u8,
        sequence,
    ];
    stream.write_all(&header).await.map_err(|_| ())?;
    stream.write_all(payload).await.map_err(|_| ())
}

async fn write_ok(stream: &mut TcpStream, sequence: u8, status: u16) -> Result<(), ()> {
    let mut payload = vec![0x00, 0, 0];
    payload.extend_from_slice(&status.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    write_packet(stream, sequence, &payload).await
}

async fn write_backend_error(stream: &mut TcpStream, sequence: u8) -> Result<(), ()> {
    let mut payload = vec![0xff, 0x1f, 0x04, b'#'];
    payload.extend_from_slice(b"42000");
    payload.extend_from_slice(b"Unknown column 'backend_syntax_error'");
    write_packet(stream, sequence, &payload).await
}

async fn write_resultset(
    stream: &mut TcpStream,
    sequence: u8,
    value: u64,
    status: u16,
) -> Result<(), ()> {
    let mut next = sequence;
    write_packet(stream, next, &[1]).await?;
    next = next.wrapping_add(1);

    let mut column = Vec::new();
    for field in [
        b"def".as_slice(),
        b"qk",
        b"proxy",
        b"proxy",
        b"value",
        b"value",
    ] {
        column.push(field.len() as u8);
        column.extend_from_slice(field);
    }
    column.push(0x0c);
    column.extend_from_slice(&45u16.to_le_bytes());
    column.extend_from_slice(&64u32.to_le_bytes());
    column.push(0x08); // MYSQL_TYPE_LONGLONG
    column.extend_from_slice(&0u16.to_le_bytes());
    column.push(0);
    column.extend_from_slice(&0u16.to_le_bytes());
    write_packet(stream, next, &column).await?;
    next = next.wrapping_add(1);

    write_packet(
        stream,
        next,
        &[0xfe, 0, 0, status as u8, (status >> 8) as u8],
    )
    .await?;
    next = next.wrapping_add(1);

    let value = value.to_string();
    let mut row = vec![value.len() as u8];
    row.extend_from_slice(value.as_bytes());
    write_packet(stream, next, &row).await?;
    next = next.wrapping_add(1);
    write_packet(
        stream,
        next,
        &[0xfe, 0, 0, status as u8, (status >> 8) as u8],
    )
    .await
}

async fn write_prepare_response(
    stream: &mut TcpStream,
    statement_id: u32,
    parameter_count: usize,
    column_count: usize,
) -> Result<(), ()> {
    let mut payload = vec![0x00];
    payload.extend_from_slice(&statement_id.to_le_bytes());
    payload.extend_from_slice(&(column_count as u16).to_le_bytes());
    payload.extend_from_slice(&(parameter_count as u16).to_le_bytes());
    payload.push(0);
    payload.extend_from_slice(&0u16.to_le_bytes());
    let mut sequence = 1u8;
    write_packet(stream, sequence, &payload).await?;
    sequence = sequence.wrapping_add(1);
    for index in 0..parameter_count {
        let column = prepared_column_definition(format!("param{index}").as_bytes(), 0xfd);
        write_packet(stream, sequence, &column).await?;
        sequence = sequence.wrapping_add(1);
    }
    if parameter_count > 0 {
        write_packet(stream, sequence, &[0xfe, 0, 0, 2, 0]).await?;
        sequence = sequence.wrapping_add(1);
    }
    for _ in 0..column_count {
        let column = prepared_column_definition(b"value", 0x08);
        write_packet(stream, sequence, &column).await?;
        sequence = sequence.wrapping_add(1);
    }
    if column_count > 0 {
        write_packet(stream, sequence, &[0xfe, 0, 0, 2, 0]).await?;
    }
    Ok(())
}

fn prepared_column_definition(name: &[u8], type_code: u8) -> Vec<u8> {
    let mut column = Vec::new();
    for field in [
        b"def".as_slice(),
        b"qk",
        b"prepared",
        b"prepared",
        name,
        name,
    ] {
        column.push(field.len() as u8);
        column.extend_from_slice(field);
    }
    column.push(0x0c);
    column.extend_from_slice(&45u16.to_le_bytes());
    column.extend_from_slice(&64u32.to_le_bytes());
    column.push(type_code);
    column.extend_from_slice(&0u16.to_le_bytes());
    column.push(0);
    column.extend_from_slice(&0u16.to_le_bytes());
    column
}

async fn write_binary_resultset(
    stream: &mut TcpStream,
    sequence: u8,
    value: u64,
    status: u16,
) -> Result<(), ()> {
    let mut next = sequence;
    write_packet(stream, next, &[1]).await?;
    next = next.wrapping_add(1);
    write_packet(stream, next, &prepared_column_definition(b"value", 0x08)).await?;
    next = next.wrapping_add(1);
    write_packet(
        stream,
        next,
        &[0xfe, 0, 0, status as u8, (status >> 8) as u8],
    )
    .await?;
    next = next.wrapping_add(1);
    let mut row = vec![0x00, 0x00];
    row.extend_from_slice(&value.to_le_bytes());
    write_packet(stream, next, &row).await?;
    next = next.wrapping_add(1);
    write_packet(
        stream,
        next,
        &[0xfe, 0, 0, status as u8, (status >> 8) as u8],
    )
    .await
}
fn allow_policy() -> qk_core::PolicyFile {
    qk_core::parse_policy(ALLOW_POLICY).expect("allow policy")
}

fn approval_policy() -> qk_core::PolicyFile {
    qk_core::parse_policy(APPROVAL_POLICY).expect("approval policy")
}

async fn open_proxy_client(proxy: &RunningProxy) -> Conn {
    connect_client(proxy.addr).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mysql_async_query_gate_session_state_and_response_relay() {
    let backend = FakeMysql::start().await;
    let proxy = RunningProxy::start(&backend, allow_policy(), None).await;
    let mut client = open_proxy_client(&proxy).await;

    let one: Option<u64> = client.query_first("SELECT 1").await.expect("result set");
    assert_eq!(one, Some(1));
    client
        .query_drop("SET @qk_test = 123")
        .await
        .expect("set variable");
    let value: Option<u64> = client
        .query_first("SELECT @qk_test")
        .await
        .expect("same session");
    assert_eq!(value, Some(123));

    client.query_drop("START TRANSACTION").await.expect("begin");
    let before_block = backend.query_count();
    let blocked_error = client
        .query_drop("UPDATE users SET name = 'blocked' WHERE id = 1")
        .await
        .expect_err("blocked mutation");
    assert!(!blocked_error.to_string().contains(MYSQL_AUTH_SECRET));
    assert_eq!(
        backend.query_count(),
        before_block,
        "blocked mutation never reached backend"
    );
    let prepared_before_block = backend.prepared_execute_count();
    let unbounded_update = client
        .prep("UPDATE users SET name = ?")
        .await
        .expect("prepare unbounded UPDATE");
    assert!(client
        .exec_drop(&unbounded_update, ("blocked".to_owned(),))
        .await
        .is_err());
    let bounded_update = client
        .prep("UPDATE users SET name = ? WHERE id = ?")
        .await
        .expect("prepare bounded UPDATE");
    assert!(client
        .exec_drop(&bounded_update, ("blocked".to_owned(), 1u64))
        .await
        .is_err());
    assert_eq!(backend.prepared_execute_count(), prepared_before_block);
    let inside: Option<u64> = client
        .query_first("SELECT 1")
        .await
        .expect("transaction remains usable");
    assert_eq!(inside, Some(1));
    client
        .query_drop("COMMIT")
        .await
        .expect("commit after local error");
    let events = backend.queries();
    assert!(events
        .iter()
        .any(|event| event.sql.to_ascii_lowercase().starts_with("commit") && event.in_transaction));

    client
        .query_drop("SET autocommit = 0")
        .await
        .expect("disable autocommit");
    client
        .query_drop("SET @qk_test = 456")
        .await
        .expect("set in persistent session");
    let persisted: Option<u64> = client
        .query_first("SELECT @qk_test")
        .await
        .expect("read session value");
    assert_eq!(persisted, Some(456));

    client
        .query_drop("SET time_zone = '+00:00'")
        .await
        .expect("session setting uses ordinary policy path");

    let count = backend.query_count();
    assert!(client.query_drop("SET NAMES latin1").await.is_err());
    assert!(client
        .query_drop("SET sql_mode = 'NO_BACKSLASH_ESCAPES'")
        .await
        .is_err());
    assert_eq!(
        backend.query_count(),
        count,
        "unsupported charset transition never reaches backend"
    );
    for sql in [
        "SELECT 1 INTO OUTFILE '/tmp/qk-outfile'",
        "SELECT 1 /*!80000 INTO OUTFILE '/tmp/qk-comment-outfile' */",
    ] {
        assert!(client.query_drop(sql).await.is_err());
    }
    assert_eq!(
        backend.query_count(),
        count,
        "file-writing SELECT forms never reach the backend"
    );
    let oversized = format!("SELECT {}", "1".repeat(1_000_001));
    assert!(
        client.query_drop(&oversized).await.is_err(),
        "SQL byte limit is enforced"
    );
    assert_eq!(
        backend.query_count(),
        count,
        "oversized SQL never reaches backend"
    );
    assert!(client
        .query_drop("SELECT 1; DROP TABLE protected")
        .await
        .is_err());
    assert_eq!(
        backend.query_count(),
        count,
        "whole dangerous batch blocked"
    );
    assert!(client
        .query_drop("LOAD DATA LOCAL INFILE '/tmp/no-file' INTO TABLE users")
        .await
        .is_err());
    assert_eq!(
        backend.query_count(),
        count,
        "LOCAL INFILE is denied before backend command"
    );
    let statement = client.prep("SELECT ?").await.expect("prepared statement");
    let prepared_value: Option<u64> = client
        .exec_first(&statement, (7u64,))
        .await
        .expect("prepared binary result");
    assert_eq!(prepared_value, Some(1));
    assert_eq!(backend.query_count(), count, "PREPARE is not COM_QUERY");
    assert_eq!(backend.prepared_execute_count(), 1);
    let prepared_count = backend.prepared_statements().len();
    assert!(client.prep("SELECT backend_syntax_error").await.is_err());
    assert!(client.prep("SELECT 1; DROP TABLE protected").await.is_err());
    assert_eq!(backend.prepared_statements().len(), prepared_count);
    let backend_error_statement = client
        .prep("SELECT backend_execute_error")
        .await
        .expect("prepare executable query");
    let backend_error = client
        .exec_first::<u64, _, _>(&backend_error_statement, ())
        .await
        .expect_err("prepared backend error");
    assert!(backend_error.to_string().contains("backend_syntax_error"));
    assert_eq!(backend.prepared_execute_count(), 2);

    assert!(client
        .query_first::<u64, _>("SELECT backend_syntax_error")
        .await
        .is_err());
    assert_eq!(
        backend.query_count(),
        count + 1,
        "backend syntax error is relayed after one authorized query"
    );
    assert!(backend
        .login_flags()
        .iter()
        .all(|flags| flags & FORBIDDEN_CLIENT_CAPABILITIES == 0));
    assert_eq!(
        backend.mutation_count(),
        0,
        "blocked mutation caused no backend side effect"
    );

    let mut second = open_proxy_client(&proxy).await;
    let isolated: Option<u64> = second
        .query_first("SELECT @qk_test")
        .await
        .expect("new session");
    assert_eq!(
        isolated,
        Some(0),
        "frontend sessions do not share backend variables"
    );
    second
        .query_drop("SET @qk_test = 789")
        .await
        .expect("second session state");
    let first_value: Option<u64> = client
        .query_first("SELECT @qk_test")
        .await
        .expect("first session state");
    assert_eq!(
        first_value,
        Some(456),
        "concurrent frontend state remains separate"
    );
    let session_events = backend.queries();
    let first_connection = session_events
        .iter()
        .find(|event| {
            event
                .sql
                .to_ascii_lowercase()
                .starts_with("set @qk_test = 123")
        })
        .expect("first frontend query")
        .connection;
    let second_connection = session_events
        .iter()
        .find(|event| {
            event
                .sql
                .to_ascii_lowercase()
                .starts_with("set @qk_test = 789")
        })
        .expect("second frontend query")
        .connection;
    assert_ne!(
        first_connection, second_connection,
        "frontends own separate backend sockets"
    );
    assert!(session_events.iter().any(|event| {
        event
            .sql
            .to_ascii_lowercase()
            .starts_with("set @qk_test = 456")
            && !event.autocommit
    }));
    let before_reset = backend.commands().len();
    assert!(client.reset().await.is_err());
    assert_eq!(
        backend.commands().len(),
        before_reset,
        "COM_RESET_CONNECTION is never forwarded"
    );
    let reset_value: Option<u64> = client
        .query_first("SELECT @qk_test")
        .await
        .expect("session remains usable after rejected reset");
    assert_eq!(reset_value, Some(456));

    let before_change_user = backend.commands().len();
    assert!(second
        .change_user(ChangeUserOpts::default().with_user(Some("other".to_owned())))
        .await
        .is_err());
    assert_eq!(
        backend.commands().len(),
        before_change_user,
        "COM_CHANGE_USER is never forwarded"
    );
    assert!(second.query_first::<u64, _>("SELECT 1").await.is_err());

    client.disconnect().await.expect("disconnect client");
    let _ = second.disconnect().await;
    proxy.stop().await;
    backend.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn caching_sha2_full_auth_is_rejected_without_relaying_full_secret() {
    let backend = FakeMysql::start_full_auth().await;
    let proxy = RunningProxy::start(&backend, allow_policy(), None).await;
    let url = format!(
        "mysql://qk:{MYSQL_AUTH_SECRET}@127.0.0.1:{}/qk",
        proxy.addr.port()
    );
    assert!(Conn::new(Opts::from_url(&url).expect("client options"))
        .await
        .is_err());
    assert_eq!(
        backend.auth_responses(),
        0,
        "full-auth response never reaches backend"
    );
    assert_eq!(backend.query_count(), 0);
    proxy.stop().await;
    backend.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frontend_login_cannot_change_trusted_mysql_user_or_database() {
    let backend = FakeMysql::start().await;
    let proxy = RunningProxy::start(&backend, allow_policy(), None).await;
    for url in [
        format!(
            "mysql://other:{MYSQL_AUTH_SECRET}@127.0.0.1:{}/qk",
            proxy.addr.port()
        ),
        format!(
            "mysql://qk:{MYSQL_AUTH_SECRET}@127.0.0.1:{}/other",
            proxy.addr.port()
        ),
    ] {
        assert!(Conn::new(Opts::from_url(&url).expect("client options"))
            .await
            .is_err());
    }
    assert!(
        backend.login_flags().is_empty(),
        "mismatched login was not relayed upstream"
    );
    assert_eq!(backend.query_count(), 0);
    proxy.stop().await;
    backend.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn once_and_session_approvals_are_rechecked_for_mysql_queries() {
    let daemon = TestControlPlane::start().await;
    let backend = FakeMysql::start().await;
    let proxy = RunningProxy::start(&backend, approval_policy(), Some(daemon.client.clone())).await;
    let mut client = open_proxy_client(&proxy).await;
    let once_sql = "DELETE FROM users WHERE id = 42";

    assert!(client.query_drop(once_sql).await.is_err());
    assert_eq!(backend.query_count(), 0);
    let first = daemon
        .client
        .list_approvals()
        .expect("waiting Once request");
    assert_eq!(first.len(), 1);
    daemon
        .client
        .decide_approval(
            &first[0].id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Once),
        )
        .expect("approve Once");
    client
        .query_drop(once_sql)
        .await
        .expect("exact retry executes");
    assert_eq!(backend.query_count(), 1);
    assert_eq!(backend.mutation_count(), 1);

    let changed_sql = "DELETE FROM users WHERE id = 43";
    assert!(
        client.query_drop(changed_sql).await.is_err(),
        "Once does not authorize changed literal"
    );
    assert_eq!(backend.query_count(), 1);
    let approvals = daemon
        .client
        .list_approvals()
        .expect("changed-literal approval");
    let waiting = approvals
        .iter()
        .find(|approval| approval.status == qk_control_plane::ApprovalStatus::Waiting)
        .expect("changed literal is pending");
    daemon
        .client
        .decide_approval(
            &waiting.id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Session),
        )
        .expect("approve session shape");
    client.query_drop(changed_sql).await.expect("Session retry");
    client
        .query_drop("DELETE FROM users WHERE id = 44")
        .await
        .expect("Session permits changed literal on the same frontend");
    assert_eq!(backend.query_count(), 3);
    assert_eq!(backend.mutation_count(), 3);

    assert!(client
        .query_drop("DELETE FROM another_table WHERE id = 45")
        .await
        .is_err());
    assert_eq!(
        backend.query_count(),
        3,
        "different shape requires a new approval"
    );
    let mut other_client = open_proxy_client(&proxy).await;
    assert!(other_client
        .query_drop("DELETE FROM users WHERE id = 46")
        .await
        .is_err());
    assert_eq!(
        backend.query_count(),
        3,
        "Session grant is isolated to its frontend"
    );
    other_client
        .disconnect()
        .await
        .expect("disconnect second client");
    client.disconnect().await.expect("disconnect client");
    proxy.stop().await;
    backend.stop().await;
    daemon.stop().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepared_once_and_session_approvals_bind_exact_parameter_values() {
    let daemon = TestControlPlane::start().await;
    let backend = FakeMysql::start().await;
    let proxy = RunningProxy::start(&backend, approval_policy(), Some(daemon.client.clone())).await;
    let mut client = open_proxy_client(&proxy).await;
    let statement = client
        .prep("DELETE FROM users WHERE id = ?")
        .await
        .expect("prepared delete");

    assert!(client.exec_drop(&statement, (42u64,)).await.is_err());
    assert_eq!(backend.prepared_execute_count(), 0);
    assert_eq!(backend.mutation_count(), 0);
    let approvals = daemon.client.list_approvals().expect("pending approval");
    assert_eq!(approvals.len(), 1);
    daemon
        .client
        .decide_approval(
            &approvals[0].id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Once),
        )
        .expect("approve Once");
    client
        .exec_drop(&statement, (42u64,))
        .await
        .expect("exact prepared retry");
    assert_eq!(backend.prepared_execute_count(), 1);
    assert_eq!(backend.mutation_count(), 1);

    assert!(
        client.exec_drop(&statement, (43u64,)).await.is_err(),
        "Once must not authorize a changed bound value"
    );
    assert_eq!(backend.prepared_execute_count(), 1);
    assert_eq!(backend.mutation_count(), 1);
    let waiting = daemon
        .client
        .list_approvals()
        .expect("changed parameter request")
        .into_iter()
        .find(|approval| approval.status == qk_control_plane::ApprovalStatus::Waiting)
        .expect("changed parameter is pending");
    daemon
        .client
        .decide_approval(
            &waiting.id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Session),
        )
        .expect("approve Session shape");
    client
        .exec_drop(&statement, (43u64,))
        .await
        .expect("Session request-specific permit");
    client
        .exec_drop(&statement, (44u64,))
        .await
        .expect("Session grant permits same shape with a fresh request permit");
    assert_eq!(backend.prepared_execute_count(), 3);
    assert_eq!(backend.mutation_count(), 3);

    let mut other_client = open_proxy_client(&proxy).await;
    let other_statement = other_client
        .prep("DELETE FROM users WHERE id = ?")
        .await
        .expect("second frontend statement");
    assert!(other_client
        .exec_drop(&other_statement, (45u64,))
        .await
        .is_err());
    assert_eq!(backend.prepared_execute_count(), 3);
    assert_eq!(backend.mutation_count(), 3);
    other_client
        .disconnect()
        .await
        .expect("disconnect second client");
    client.disconnect().await.expect("disconnect client");
    proxy.stop().await;
    backend.stop().await;
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepared_long_data_is_deferred_and_exact_retry_preserves_wire_order() {
    let daemon = TestControlPlane::start().await;
    let backend = FakeMysql::start().await;
    let proxy = RunningProxy::start(&backend, approval_policy(), Some(daemon.client.clone())).await;
    let mut client = RawMysqlClient::connect(proxy.addr).await;
    let sql = "DELETE FROM users WHERE id = ?";
    let statement_id = client.prepare(sql).await;
    let first_chunk = b"MYSQL_PREPARED_SECRET_";
    let second_chunk = b"8675309\0\x80\xff";
    let binary_sentinel = [0, 0x80, 0xff];
    client.send_long_data(statement_id, 0, first_chunk).await;
    client.send_long_data(statement_id, 0, second_chunk).await;

    let pending = client.execute_one_string(statement_id, true).await;
    assert_eq!(pending.first(), Some(&0xff));
    assert!(!String::from_utf8_lossy(&pending).contains("MYSQL_PREPARED_SECRET_8675309"));
    assert!(!pending
        .windows(binary_sentinel.len())
        .any(|window| window == binary_sentinel));
    assert_eq!(backend.long_data().len(), 0);
    assert_eq!(backend.prepared_execute_count(), 0);
    assert_eq!(backend.mutation_count(), 0);
    assert_eq!(backend.prepared_statements()[0].2, sql);

    client.send_long_data(statement_id, 0, first_chunk).await;
    client.send_long_data(statement_id, 0, second_chunk).await;
    assert_eq!(
        client.execute_one_string(statement_id, false).await.first(),
        Some(&0xff),
        "a repeated upload after local rejection is staged as a fresh attempt"
    );
    assert_eq!(backend.long_data().len(), 0);
    assert_eq!(backend.prepared_execute_count(), 0);
    let approval = daemon
        .client
        .list_approvals()
        .expect("waiting prepared approval")
        .into_iter()
        .find(|approval| approval.status == qk_control_plane::ApprovalStatus::Waiting)
        .expect("long-data execution is pending");
    daemon
        .client
        .decide_approval(
            &approval.id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Once),
        )
        .expect("approve exact prepared request");

    let retry = client.execute_one_string(statement_id, false).await;
    assert_eq!(retry.first(), Some(&0x00));
    assert_eq!(backend.prepared_execute_count(), 1);
    assert_eq!(backend.mutation_count(), 1);
    assert_eq!(
        backend.long_data(),
        vec![
            (1, statement_id, 0, first_chunk.to_vec()),
            (1, statement_id, 0, second_chunk.to_vec()),
        ],
        "approved retry forwards the original chunks once and in order"
    );
    assert_eq!(backend.execute_bind_flags(), vec![1]);
    let approval_debug = format!("{approval:?}");
    assert!(!approval_debug.contains("MYSQL_PREPARED_SECRET_8675309"));
    assert!(!approval_debug
        .as_bytes()
        .windows(binary_sentinel.len())
        .any(|window| window == binary_sentinel));
    let store = qk_store::Store::open(&daemon.home.join("queryknight.db")).expect("history store");
    let history = store.list_events(100).expect("query history");
    assert!(history
        .iter()
        .any(|event| event.sql.as_deref() == Some(sql)));
    assert!(history.iter().all(|event| !event
        .sql
        .as_deref()
        .unwrap_or_default()
        .contains("MYSQL_PREPARED_SECRET_8675309")));
    let history_debug = format!("{history:?}");
    assert!(!history_debug.contains("MYSQL_PREPARED_SECRET_8675309"));
    assert!(!history_debug
        .as_bytes()
        .windows(binary_sentinel.len())
        .any(|window| window == binary_sentinel));

    client
        .send_long_data(statement_id, 0, b"changed-8675309")
        .await;
    let changed = client.execute_one_string(statement_id, false).await;
    assert_eq!(changed.first(), Some(&0xff));
    assert_eq!(backend.prepared_execute_count(), 1);
    assert_eq!(backend.mutation_count(), 1);
    assert_eq!(backend.long_data().len(), 2);
    client.close_statement(statement_id).await;
    proxy.stop().await;
    backend.stop().await;
    daemon.stop().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepared_empty_long_data_is_distinct_from_null() {
    let daemon = TestControlPlane::start().await;
    let backend = FakeMysql::start().await;
    let proxy = RunningProxy::start(&backend, approval_policy(), Some(daemon.client.clone())).await;
    let mut client = RawMysqlClient::connect(proxy.addr).await;
    let statement_id = client.prepare("DELETE FROM users WHERE id = ?").await;
    client.send_long_data(statement_id, 0, &[]).await;
    assert_eq!(
        client.execute_one_string(statement_id, true).await.first(),
        Some(&0xff)
    );
    assert_eq!(backend.prepared_execute_count(), 0);
    let approval = daemon
        .client
        .list_approvals()
        .expect("empty binary parameter approval")
        .into_iter()
        .find(|approval| approval.status == qk_control_plane::ApprovalStatus::Waiting)
        .expect("empty bytes request pending");
    daemon
        .client
        .decide_approval(
            &approval.id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Once),
        )
        .expect("approve empty binary value");
    assert_eq!(
        client.execute_one_string(statement_id, false).await.first(),
        Some(&0x00)
    );
    assert_eq!(
        backend.long_data(),
        vec![(1, statement_id, 0, Vec::new())],
        "empty long data remains distinct and is forwarded after its permit"
    );
    assert_eq!(backend.mutation_count(), 1);
    client.close_statement(statement_id).await;
    proxy.stop().await;
    backend.stop().await;
    daemon.stop().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reused_backend_statement_id_gets_fresh_local_sql_and_parameters() {
    let daemon = TestControlPlane::start().await;
    let backend = FakeMysql::start().await;
    let proxy = RunningProxy::start(&backend, approval_policy(), Some(daemon.client.clone())).await;
    let mut client = RawMysqlClient::connect(proxy.addr).await;
    let old_sql = "DELETE FROM users WHERE id = ?";
    let old_id = client.prepare(old_sql).await;
    client.send_long_data(old_id, 0, b"old-pending-value").await;
    client.close_statement(old_id).await;

    let new_sql = "DELETE FROM users WHERE status = ?";
    let new_id = client.prepare(new_sql).await;
    assert_eq!(
        new_id, old_id,
        "fake backend deliberately reuses closed IDs"
    );
    client.send_long_data(new_id, 0, b"new-value").await;
    let pending = client.execute_one_string(new_id, true).await;
    assert_eq!(pending.first(), Some(&0xff));
    assert_eq!(backend.long_data().len(), 0);
    let approval = daemon
        .client
        .list_approvals()
        .expect("approval for reused ID")
        .into_iter()
        .find(|approval| approval.status == qk_control_plane::ApprovalStatus::Waiting)
        .expect("new SQL remains approval-gated");
    daemon
        .client
        .decide_approval(
            &approval.id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Once),
        )
        .expect("approve current statement identity");
    assert_eq!(
        client.execute_one_string(new_id, false).await.first(),
        Some(&0x00)
    );
    assert_eq!(backend.prepared_execute_count(), 1);
    assert_eq!(backend.mutation_count(), 1);
    assert_eq!(
        backend.long_data(),
        vec![(1, new_id, 0, b"new-value".to_vec())],
        "closed statement long data cannot leak into a reused numeric ID"
    );
    assert_eq!(backend.prepared_statements()[1].2, new_sql);
    client.close_statement(new_id).await;
    proxy.stop().await;
    backend.stop().await;
    daemon.stop().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepared_reset_clears_pending_long_data_before_reuse() {
    let daemon = TestControlPlane::start().await;
    let backend = FakeMysql::start().await;
    let proxy = RunningProxy::start(&backend, approval_policy(), Some(daemon.client.clone())).await;
    let mut client = RawMysqlClient::connect(proxy.addr).await;
    let statement_id = client.prepare("DELETE FROM users WHERE id = ?").await;
    let value = b"MYSQL_PREPARED_SECRET_8675309";
    client.send_long_data(statement_id, 0, value).await;
    assert_eq!(client.execute_one_string(statement_id, true).await[0], 0xff);
    let approval = daemon
        .client
        .list_approvals()
        .expect("pending reset fixture approval")
        .into_iter()
        .find(|approval| approval.status == qk_control_plane::ApprovalStatus::Waiting)
        .expect("prepared mutation pending");
    daemon
        .client
        .decide_approval(
            &approval.id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Once),
        )
        .expect("approve exact value");

    assert_eq!(
        client.reset_statement(statement_id).await.first(),
        Some(&0x00)
    );
    assert_eq!(
        client.execute_one_string(statement_id, false).await.first(),
        Some(&0xff),
        "reset prevents the old long-data value from being reused"
    );
    assert_eq!(backend.prepared_execute_count(), 0);
    client.send_long_data(statement_id, 0, value).await;
    assert_eq!(
        client.execute_one_string(statement_id, false).await.first(),
        Some(&0x00),
        "the same identity can execute only after the value is restaged"
    );
    assert_eq!(backend.prepared_execute_count(), 1);
    assert_eq!(
        backend.long_data(),
        vec![(1, statement_id, 0, value.to_vec())]
    );
    client.close_statement(statement_id).await;
    proxy.stop().await;
    backend.stop().await;
    daemon.stop().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepared_local_infile_request_is_never_relayed() {
    let backend = FakeMysql::start().await;
    let proxy = RunningProxy::start(&backend, allow_policy(), None).await;
    let mut client = RawMysqlClient::connect(proxy.addr).await;
    let statement_id = client.prepare("SELECT prepared_local_infile").await;
    assert!(client
        .execute_without_parameters(statement_id)
        .await
        .is_err());
    assert_eq!(backend.prepared_execute_count(), 1);
    assert_eq!(backend.local_infile_data_packets(), 0);
    proxy.stop().await;
    backend.stop().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepared_once_identity_includes_unsigned_type_flags() {
    let daemon = TestControlPlane::start().await;
    let backend = FakeMysql::start().await;
    let proxy = RunningProxy::start(&backend, approval_policy(), Some(daemon.client.clone())).await;
    let mut client = open_proxy_client(&proxy).await;
    let statement = client
        .prep("DELETE FROM users WHERE id = ?")
        .await
        .expect("prepared delete");
    assert!(client.exec_drop(&statement, (42u64,)).await.is_err());
    let approval = daemon
        .client
        .list_approvals()
        .expect("unsigned parameter approval")
        .into_iter()
        .find(|approval| approval.status == qk_control_plane::ApprovalStatus::Waiting)
        .expect("unsigned request pending");
    daemon
        .client
        .decide_approval(
            &approval.id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Once),
        )
        .expect("approve unsigned request Once");
    client
        .exec_drop(&statement, (42u64,))
        .await
        .expect("exact unsigned retry");
    assert_eq!(backend.prepared_execute_count(), 1);
    assert_eq!(backend.mutation_count(), 1);

    assert!(
        client.exec_drop(&statement, (42i64,)).await.is_err(),
        "signed and unsigned descriptors must have distinct ExactV2 identities"
    );
    assert_eq!(backend.prepared_execute_count(), 1);
    assert_eq!(backend.mutation_count(), 1);
    client.disconnect().await.expect("disconnect client");
    proxy.stop().await;
    backend.stop().await;
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepared_once_null_identity_differs_from_zero() {
    let daemon = TestControlPlane::start().await;
    let backend = FakeMysql::start().await;
    let proxy = RunningProxy::start(&backend, approval_policy(), Some(daemon.client.clone())).await;
    let mut client = open_proxy_client(&proxy).await;
    let statement = client
        .prep("DELETE FROM users WHERE status = ?")
        .await
        .expect("prepared delete");
    assert!(client.exec_drop(&statement, (None::<u64>,)).await.is_err());
    let approval = daemon
        .client
        .list_approvals()
        .expect("NULL parameter approval")
        .into_iter()
        .find(|approval| approval.status == qk_control_plane::ApprovalStatus::Waiting)
        .expect("NULL request pending");
    daemon
        .client
        .decide_approval(
            &approval.id,
            ApprovalDecision::Approved,
            qk_approval::DecisionSource::Ui,
            Some(qk_approval::Scope::Once),
        )
        .expect("approve NULL request Once");
    client
        .exec_drop(&statement, (None::<u64>,))
        .await
        .expect("exact NULL retry");
    assert_eq!(backend.prepared_execute_count(), 1);
    assert_eq!(backend.mutation_count(), 1);
    assert!(
        client.exec_drop(&statement, (Some(0u64),)).await.is_err(),
        "NULL must not share a Once identity with zero"
    );
    assert_eq!(backend.prepared_execute_count(), 1);
    assert_eq!(backend.mutation_count(), 1);
    client.disconnect().await.expect("disconnect client");
    proxy.stop().await;
    backend.stop().await;
    daemon.stop().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_shape_approval_never_authorizes_mysql_query() {
    let daemon = TestControlPlane::start().await;
    let backend = FakeMysql::start().await;
    let proxy = RunningProxy::start(&backend, approval_policy(), Some(daemon.client.clone())).await;
    let mut client = open_proxy_client(&proxy).await;
    let sql = "DELETE FROM users WHERE id = 47";
    let store = qk_store::Store::open(&daemon.home.join("queryknight.db")).expect("test store");
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
    .expect("proxy approval session created");
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64;
    store
        .insert_grant(
            &qk_approval::StoredGrant {
                id: qk_approval::ApprovalId::new("qka_legacy_mysql_proxy".to_owned()),
                shape: qk_core::sql_fingerprint(sql),
                binding: qk_approval::ApprovalBinding::LegacyShape,
                scope: qk_approval::ApprovalScope {
                    session_id: Some(session.id),
                    integration: "proxy_mysql".to_owned(),
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
                operation_summary: "delete users".to_owned(),
                matched_policy: None,
                decided_at_ms: Some(now_ms),
                decided_by: Some(qk_approval::DecisionSource::Ui),
            },
            now_ms,
        )
        .expect("insert legacy grant");

    assert!(client.query_drop(sql).await.is_err());
    assert_eq!(backend.query_count(), 0);
    let prepared = client
        .prep("DELETE FROM users WHERE id = ?")
        .await
        .expect("prepared statement");
    assert!(client.exec_drop(&prepared, (47u64,)).await.is_err());
    assert_eq!(backend.prepared_execute_count(), 0);
    assert_eq!(backend.mutation_count(), 0);
    assert!(daemon
        .client
        .list_approvals()
        .expect("approval rows")
        .iter()
        .any(
            |approval| approval.binding_kind == qk_control_plane::ApprovalBindingKind::LegacyShape
        ));
    client.disconnect().await.expect("disconnect client");
    proxy.stop().await;
    backend.stop().await;
    daemon.stop().await;
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
            "qk-proxy-mysql-daemon-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).expect("create isolated daemon home");
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
            .expect("daemon ready timeout")
            .expect("daemon ready");
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
