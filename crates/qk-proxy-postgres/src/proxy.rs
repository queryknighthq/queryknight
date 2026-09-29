use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use qk_approval::{ApprovalProvider, InMemoryApprovalStore};
use qk_control_plane::DaemonApprovalProvider;
use qk_core::ExecutionParam;
use qk_db::{
    authorize_guarded, ApprovalSetup, AuthorizationOutcome, AuthorizationRequest, CursorStore,
    GuardedAuthorizationCall, ResolveMode, TrustedContext,
};
use qk_sql::Operation;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::config::{BackendConfig, ProxyConfig, ProxyConfigError};
use crate::protocol::{
    self, encode_empty_query, encode_error, encode_ready, parse_startup, simple_query_sql, Frame,
    FrameError, FrameReader, StartupKind,
};

/// At most this many independent PostgreSQL backend sessions are active.
pub const MAX_CLIENTS: usize = 128;
/// Backend TCP connect bound. Query execution itself remains PostgreSQL-native
/// and has no qk-db per-operation timeout or reconnect/replay behavior.
pub const BACKEND_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Proxy startup/accept failure. No backend URL, credentials, SQL, or token is
/// included in its display surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyError {
    /// Trusted backend/listener configuration failed validation.
    Configuration,
    /// Listener bind or accept failed.
    Listener,
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Configuration => "PostgreSQL proxy configuration failed",
            Self::Listener => "PostgreSQL proxy listener failed",
        })
    }
}

impl std::error::Error for ProxyError {}

impl From<ProxyConfigError> for ProxyError {
    fn from(_: ProxyConfigError) -> Self {
        Self::Configuration
    }
}

/// Bound loopback PostgreSQL listener. `run_until` owns all client tasks and
/// closes their frontend/backend sockets before returning on shutdown.
pub struct ProxyServer {
    listener: TcpListener,
    config: Arc<ProxyConfig>,
}

impl ProxyServer {
    /// Bind the configured loopback listener.
    pub async fn bind(config: ProxyConfig) -> Result<Self, ProxyError> {
        let listener = TcpListener::bind(config.listen_addr())
            .await
            .map_err(|_| ProxyError::Listener)?;
        Ok(Self {
            listener,
            config: Arc::new(config),
        })
    }

    /// Actual bound address (port may be ephemeral in tests).
    pub fn local_addr(&self) -> Result<SocketAddr, ProxyError> {
        self.listener.local_addr().map_err(|_| ProxyError::Listener)
    }

    /// Accept clients until `shutdown` completes. Per-client tasks are owned
    /// in a JoinSet, bounded by [`MAX_CLIENTS`], and joined before return.
    pub async fn run_until<F>(self, shutdown: F) -> Result<(), ProxyError>
    where
        F: Future<Output = ()> + Send,
    {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let semaphore = Arc::new(Semaphore::new(MAX_CLIENTS));
        let mut clients = JoinSet::new();
        tokio::pin!(shutdown);
        let mut stopping = false;
        loop {
            if stopping {
                if clients.join_next().await.is_none() {
                    break;
                }
                continue;
            }
            tokio::select! {
                _ = &mut shutdown => {
                    stopping = true;
                    let _ = shutdown_tx.send(true);
                }
                joined = clients.join_next(), if !clients.is_empty() => {
                    let _ = joined;
                }
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted.map_err(|_| ProxyError::Listener)?;
                    let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                        let mut stream = stream;
                        let _ = write_error(&mut stream, "FATAL", "53300", "proxy client limit reached").await;
                        continue;
                    };
                    clients.spawn(handle_client(stream, self.config.clone(), shutdown_rx.clone(), permit));
                }
            }
        }
        Ok(())
    }
}

struct BackendSession {
    reader: FrameReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
    transaction_status: u8,
    client_encoding: Option<String>,
}

async fn handle_client(
    stream: TcpStream,
    config: Arc<ProxyConfig>,
    mut shutdown: watch::Receiver<bool>,
    _client_permit: OwnedSemaphorePermit,
) {
    let (frontend_read, mut frontend_write) = stream.into_split();
    let mut frontend = FrameReader::new(frontend_read);
    let startup =
        match read_startup_with_refusals(&mut frontend, &mut frontend_write, &mut shutdown).await {
            Ok(Some(packet)) => packet,
            Ok(None) | Err(()) => return,
        };
    let startup_parameters = match parse_startup(&startup) {
        Ok(parameters) => parameters,
        Err(_) => {
            let _ = write_error(
                &mut frontend_write,
                "FATAL",
                "08P01",
                "invalid PostgreSQL startup packet",
            )
            .await;
            return;
        }
    };
    if let Err((code, message)) = validate_startup(&startup_parameters.pairs, &config.backend) {
        let _ = write_error(&mut frontend_write, "FATAL", code, message).await;
        return;
    }
    let backend_stream = match timeout(
        BACKEND_CONNECT_TIMEOUT,
        TcpStream::connect((config.backend.host.as_str(), config.backend.port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        _ => {
            let _ = write_error(
                &mut frontend_write,
                "FATAL",
                "08001",
                "cannot connect to configured PostgreSQL backend",
            )
            .await;
            return;
        }
    };
    let (backend_read, backend_write) = backend_stream.into_split();
    let mut backend = BackendSession {
        reader: FrameReader::new(backend_read),
        writer: backend_write,
        transaction_status: b'I',
        client_encoding: None,
    };
    if backend.writer.write_all(&startup).await.is_err() {
        let _ = write_error(
            &mut frontend_write,
            "FATAL",
            "08006",
            "PostgreSQL backend connection failed",
        )
        .await;
        return;
    }
    if relay_authentication(
        &mut frontend,
        &mut frontend_write,
        &mut backend,
        &mut shutdown,
    )
    .await
    .is_err()
    {
        return;
    }
    if !backend
        .client_encoding
        .as_deref()
        .is_some_and(|encoding| encoding.eq_ignore_ascii_case("UTF8"))
    {
        let _ = write_error(
            &mut frontend_write,
            "FATAL",
            "0A000",
            "proxy requires UTF8 client encoding",
        )
        .await;
        return;
    }
    let session_id = create_proxy_session(&config, &mut shutdown).await;
    let mut pending_frontend = None;
    loop {
        if *shutdown.borrow() {
            return;
        }
        let frame = match pending_frontend.take() {
            Some(frame) => frame,
            None => {
                tokio::select! {
                    _ = wait_shutdown(&mut shutdown) => return,
                    result = frontend.message() => match result {
                        Ok(frame) => frame,
                        Err(FrameError::Eof) => return,
                        Err(FrameError::QueryTooLarge) => {
                            if send_local_error(&mut frontend_write, backend.transaction_status, "54000", "SQL query exceeds the QueryKnight size limit").await.is_err() {
                                return;
                            }
                            continue;
                        }
                        Err(_) => {
                            let _ = write_error(&mut frontend_write, "FATAL", "08P01", "invalid PostgreSQL frontend frame").await;
                            return;
                        }
                    }
                }
            }
        };
        match frame.kind {
            b'Q' => {
                let sql = match simple_query_sql(frame.payload()) {
                    Ok(sql) => sql,
                    Err(_) => {
                        let _ = write_error(
                            &mut frontend_write,
                            "FATAL",
                            "08P01",
                            "invalid Simple Query frame",
                        )
                        .await;
                        return;
                    }
                };
                if sql.trim().is_empty() {
                    let Ok(empty) = encode_empty_query() else {
                        return;
                    };
                    if frontend_write.write_all(&empty).await.is_err()
                        || send_ready(&mut frontend_write, backend.transaction_status)
                            .await
                            .is_err()
                    {
                        return;
                    }
                    continue;
                }
                if !backend
                    .client_encoding
                    .as_deref()
                    .is_some_and(|encoding| encoding.eq_ignore_ascii_case("UTF8"))
                {
                    if send_local_error(
                        &mut frontend_write,
                        backend.transaction_status,
                        "22021",
                        "proxy requires UTF8 client encoding",
                    )
                    .await
                    .is_err()
                    {
                        return;
                    }
                    continue;
                }
                let outcome = match authorize_query(
                    config.clone(),
                    session_id.clone(),
                    sql.to_owned(),
                    AuthorizationIo {
                        frontend: &mut frontend,
                        client: &mut frontend_write,
                        backend_writer: &mut backend.writer,
                        pending_frontend: &mut pending_frontend,
                        shutdown: &mut shutdown,
                    },
                )
                .await
                {
                    Some(outcome) => outcome,
                    None => return,
                };
                match outcome {
                    AuthorizationOutcome::Blocked(reason) => {
                        let (code, message) = if reason.code == "UNSUPPORTED_OPERATION" {
                            ("0A000", reason.message.as_str())
                        } else {
                            ("42501", reason.message.as_str())
                        };
                        if send_local_error(
                            &mut frontend_write,
                            backend.transaction_status,
                            code,
                            message,
                        )
                        .await
                        .is_err()
                        {
                            return;
                        }
                    }
                    AuthorizationOutcome::PendingApproval(pending) => {
                        let message = format!("waiting for approval: {}", pending.approval_id);
                        if send_local_error(
                            &mut frontend_write,
                            backend.transaction_status,
                            "42501",
                            &message,
                        )
                        .await
                        .is_err()
                        {
                            return;
                        }
                    }
                    AuthorizationOutcome::Failed(error) => {
                        if send_local_error(
                            &mut frontend_write,
                            backend.transaction_status,
                            "42501",
                            error.message(),
                        )
                        .await
                        .is_err()
                        {
                            return;
                        }
                    }
                    AuthorizationOutcome::Permitted(permit) => {
                        if permit.dialect() != qk_sql::SqlDialect::PostgreSql {
                            let _ = send_local_error(
                                &mut frontend_write,
                                backend.transaction_status,
                                "42501",
                                "authorization dialect mismatch",
                            )
                            .await;
                            return;
                        }
                        if permit.includes_operation(&Operation::Copy)
                            || permit.includes_operation(&Operation::Set)
                        {
                            if send_local_error(
                                &mut frontend_write,
                                backend.transaction_status,
                                "0A000",
                                "COPY and SQL SET are not supported by this proxy",
                            )
                            .await
                            .is_err()
                            {
                                return;
                            }
                            continue;
                        }
                        if !record_history(
                            &config,
                            session_id.as_deref(),
                            sql,
                            &mut frontend,
                            &mut frontend_write,
                            &mut pending_frontend,
                            &mut shutdown,
                        )
                        .await
                        {
                            return;
                        }
                        if forward_permitted_query(*permit, frame, &mut backend.writer)
                            .await
                            .is_err()
                        {
                            let _ = write_error(
                                &mut frontend_write,
                                "FATAL",
                                "08006",
                                "PostgreSQL backend connection failed",
                            )
                            .await;
                            return;
                        }
                        if relay_until_ready(
                            &mut backend,
                            &mut frontend,
                            &mut frontend_write,
                            &mut pending_frontend,
                            &mut shutdown,
                        )
                        .await
                        .is_err()
                        {
                            let _ = write_error(
                                &mut frontend_write,
                                "FATAL",
                                "08006",
                                "PostgreSQL backend connection failed",
                            )
                            .await;
                            return;
                        }
                    }
                }
            }
            b'X' => {
                let _ = backend.writer.write_all(&frame.raw).await;
                return;
            }
            b'P' | b'B' | b'D' | b'E' | b'C' | b'H' => {
                if send_error_only(
                    &mut frontend_write,
                    "ERROR",
                    "0A000",
                    "PostgreSQL extended query protocol is not supported by this proxy",
                )
                .await
                .is_err()
                {
                    return;
                }
                if drain_until_sync(
                    &mut frontend,
                    &mut frontend_write,
                    &mut backend,
                    &mut pending_frontend,
                    &mut shutdown,
                )
                .await
                .is_err()
                {
                    return;
                }
            }
            b'S' => {
                if send_error_only(
                    &mut frontend_write,
                    "ERROR",
                    "0A000",
                    "PostgreSQL Sync without supported extended execution is not supported",
                )
                .await
                .is_err()
                    || send_ready(&mut frontend_write, backend.transaction_status)
                        .await
                        .is_err()
                {
                    return;
                }
            }
            b'F' => {
                if send_local_error(
                    &mut frontend_write,
                    backend.transaction_status,
                    "0A000",
                    "PostgreSQL FunctionCall is not supported by this proxy",
                )
                .await
                .is_err()
                {
                    return;
                }
            }
            b'd' | b'c' | b'f' => {
                if write_error(
                    &mut frontend_write,
                    "FATAL",
                    "08P01",
                    "COPY messages are not valid in this proxy state",
                )
                .await
                .is_err()
                {
                    return;
                }
                return;
            }
            _ => {
                let _ = write_error(
                    &mut frontend_write,
                    "FATAL",
                    "08P01",
                    "unsupported PostgreSQL frontend message",
                )
                .await;
                return;
            }
        }
    }
}

async fn read_startup_with_refusals(
    frontend: &mut FrameReader<tokio::net::tcp::OwnedReadHalf>,
    client: &mut tokio::net::tcp::OwnedWriteHalf,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<Option<Vec<u8>>, ()> {
    let mut refusals = 0;
    loop {
        let packet = tokio::select! {
            _ = wait_shutdown(shutdown) => return Ok(None),
            packet = frontend.startup_packet() => packet,
        };
        let packet = match packet {
            Ok(packet) => packet,
            Err(FrameError::Eof) => return Ok(None),
            Err(_) => {
                let _ = write_error(
                    client,
                    "FATAL",
                    "08P01",
                    "invalid PostgreSQL startup packet",
                )
                .await;
                return Err(());
            }
        };
        match protocol::startup_kind(&packet).map_err(|_| ())? {
            StartupKind::SslRequest | StartupKind::GssEncryptionRequest => {
                refusals += 1;
                if refusals > 2 || client.write_all(b"N").await.is_err() {
                    return Err(());
                }
            }
            StartupKind::CancelRequest => return Ok(None),
            StartupKind::Startup => return Ok(Some(packet.to_vec())),
            StartupKind::Unsupported => {
                let _ = write_error(
                    client,
                    "FATAL",
                    "0A000",
                    "PostgreSQL protocol version or startup mode is unsupported",
                )
                .await;
                return Err(());
            }
        }
    }
}

fn validate_startup(
    pairs: &[(String, String)],
    backend: &BackendConfig,
) -> Result<(), (&'static str, &'static str)> {
    let mut seen = std::collections::HashSet::new();
    let mut user = None;
    let mut database = None;
    for (key, value) in pairs {
        if !seen.insert(key.as_str()) {
            return Err(("08P01", "duplicate PostgreSQL startup parameter"));
        }
        match key.as_str() {
            "user" => user = Some(value.as_str()),
            "database" => database = Some(value.as_str()),
            "application_name" => {}
            "client_encoding" if value.eq_ignore_ascii_case("UTF8") => {}
            "client_encoding" => return Err(("0A000", "proxy requires UTF8 client encoding")),
            "options" if value.is_empty() => {}
            "options" => return Err(("0A000", "non-empty startup options are not supported")),
            "replication" if value.is_empty() => {}
            "replication" => return Err(("0A000", "PostgreSQL replication mode is not supported")),
            _ => return Err(("0A000", "startup parameter is not supported by this proxy")),
        }
    }
    let Some(user) = user else {
        return Err((
            "28000",
            "startup user does not match the configured backend",
        ));
    };
    if user != backend.user {
        return Err((
            "28000",
            "startup user does not match the configured backend",
        ));
    }
    let requested_database = database.unwrap_or(user);
    if requested_database != backend.database {
        return Err((
            "3D000",
            "startup database does not match the configured backend",
        ));
    }
    Ok(())
}

async fn create_proxy_session(
    config: &ProxyConfig,
    shutdown: &mut watch::Receiver<bool>,
) -> Option<String> {
    let client = config.control_plane.clone()?;
    let connection_key = config.connection_key.clone();
    let mut worker =
        tokio::task::spawn_blocking(move || client.create_session(&connection_key, "proxy"));
    tokio::select! {
        _ = wait_shutdown(shutdown) => {
            let _ = (&mut worker).await;
            None
        }
        result = &mut worker => result.ok().and_then(Result::ok).filter(|id| !id.is_empty()),
    }
}

async fn relay_authentication(
    frontend: &mut FrameReader<tokio::net::tcp::OwnedReadHalf>,
    client: &mut tokio::net::tcp::OwnedWriteHalf,
    backend: &mut BackendSession,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(), ()> {
    loop {
        let result = tokio::select! {
            _ = wait_shutdown(shutdown) => return Err(()),
            message = backend.reader.message() => message,
            client_message = frontend.message() => {
                if client_message.is_ok() {
                    let _ = write_error(client, "FATAL", "08P01", "unexpected frontend message during authentication").await;
                }
                return Err(());
            }
        };
        let message = result.map_err(|_| ())?;
        if message.kind == b'R' {
            let payload = message.payload();
            if payload.len() < 4 {
                let _ = write_error(
                    client,
                    "FATAL",
                    "08P01",
                    "invalid backend authentication message",
                )
                .await;
                return Err(());
            }
            let method = u32::from_be_bytes(payload[..4].try_into().map_err(|_| ())?);
            if !matches!(method, 0 | 3 | 5 | 10 | 11 | 12) {
                let _ = write_error(
                    client,
                    "FATAL",
                    "0A000",
                    "backend authentication method is not supported by this proxy",
                )
                .await;
                return Err(());
            }
            client.write_all(&message.raw).await.map_err(|_| ())?;
            if matches!(method, 3 | 5 | 10 | 11) {
                let response = tokio::select! {
                    _ = wait_shutdown(shutdown) => return Err(()),
                    response = frontend.message() => response.map_err(|_| ())?,
                };
                if response.kind != b'p' || response.raw.len() > protocol::MAX_AUTH_FRAME_LENGTH {
                    let _ = write_error(
                        client,
                        "FATAL",
                        "08P01",
                        "invalid PostgreSQL authentication response",
                    )
                    .await;
                    return Err(());
                }
                backend
                    .writer
                    .write_all(&response.raw)
                    .await
                    .map_err(|_| ())?;
            }
            continue;
        }
        if message.kind == b'S' {
            if let Some((name, value)) = parse_parameter_status(message.payload()) {
                if name == "client_encoding" {
                    backend.client_encoding = Some(value);
                }
            } else {
                let _ = write_error(
                    client,
                    "FATAL",
                    "08P01",
                    "invalid backend ParameterStatus message",
                )
                .await;
                return Err(());
            }
        }
        if message.kind == b'Z' {
            backend.transaction_status = parse_ready_status(message.payload()).map_err(|_| ())?;
            client.write_all(&message.raw).await.map_err(|_| ())?;
            return Ok(());
        }
        if message.kind == b'E' {
            client.write_all(&message.raw).await.map_err(|_| ())?;
            return Err(());
        }
        client.write_all(&message.raw).await.map_err(|_| ())?;
    }
}

struct AuthorizationIo<'a> {
    frontend: &'a mut FrameReader<tokio::net::tcp::OwnedReadHalf>,
    client: &'a mut tokio::net::tcp::OwnedWriteHalf,
    backend_writer: &'a mut tokio::net::tcp::OwnedWriteHalf,
    pending_frontend: &'a mut Option<Frame>,
    shutdown: &'a mut watch::Receiver<bool>,
}

async fn authorize_query(
    config: Arc<ProxyConfig>,
    session_id: Option<String>,
    sql: String,
    io: AuthorizationIo<'_>,
) -> Option<AuthorizationOutcome> {
    let AuthorizationIo {
        frontend,
        client,
        backend_writer,
        pending_frontend,
        shutdown,
    } = io;
    let worker_config = config.clone();
    let worker_session = session_id.clone();
    let worker_sql = sql;
    let mut worker = tokio::task::spawn_blocking(move || {
        let store = InMemoryApprovalStore::new();
        let provider = match (worker_config.control_plane.clone(), worker_session.clone()) {
            (Some(client), Some(session_id)) => Some(
                DaemonApprovalProvider::new(
                    client,
                    Some(session_id),
                    worker_config.connection_key.clone(),
                    None,
                )
                .with_exact_lookup_retry(),
            ),
            _ => None,
        };
        let setup = ApprovalSetup {
            store: &store,
            provider: provider
                .as_ref()
                .map(|provider| provider as &dyn ApprovalProvider),
            ttl_ms: 60_000,
            now_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_millis() as u64)
                .unwrap_or(0),
        };
        let auth = TrustedContext {
            integration: "proxy_pg".to_owned(),
            environment: worker_config.environment.clone(),
            database: worker_config.database.clone(),
            tool: "proxy_query".to_owned(),
            session_id: worker_session,
        };
        let mut request = AuthorizationRequest::new(worker_sql, Vec::<ExecutionParam>::new());
        request
            .reject_operations
            .extend([Operation::Copy, Operation::Set]);
        authorize_guarded(
            &CursorStore::new(),
            &GuardedAuthorizationCall {
                config: &worker_config.db_config,
                connection_key: &worker_config.connection_key,
                auth: &auth,
                approval: Some(&setup),
                policy: &worker_config.policy,
            },
            &request,
            ResolveMode::ResolveApprovals,
        )
    });

    loop {
        tokio::select! {
            _ = wait_shutdown(shutdown) => {
                let _ = backend_writer.shutdown().await;
                let _ = (&mut worker).await;
                return None;
            }
            incoming = frontend.message(), if pending_frontend.is_none() => {
                match incoming {
                    Ok(frame) if frame.kind == b'X' => {
                        let _ = backend_writer.shutdown().await;
                        let _ = (&mut worker).await;
                        return None;
                    }
                    Ok(frame) => *pending_frontend = Some(frame),
                    Err(FrameError::Eof) => {
                        let _ = backend_writer.shutdown().await;
                        let _ = (&mut worker).await;
                        return None;
                    }
                    Err(_) => {
                        let _ = write_error(client, "FATAL", "08P01", "invalid pipelined PostgreSQL frame").await;
                        let _ = backend_writer.shutdown().await;
                        let _ = (&mut worker).await;
                        return None;
                    }
                }
            }
            result = &mut worker => {
                return Some(result.unwrap_or_else(|_| {
                    AuthorizationOutcome::Failed(qk_db::DbError::new(
                        qk_db::DbErrorKind::Internal,
                        "authorization worker failed",
                    ))
                }));
            }
        }
    }
}

async fn record_history(
    config: &ProxyConfig,
    session_id: Option<&str>,
    sql: &str,
    frontend: &mut FrameReader<tokio::net::tcp::OwnedReadHalf>,
    client: &mut tokio::net::tcp::OwnedWriteHalf,
    pending_frontend: &mut Option<Frame>,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    let (Some(control_plane), Some(session_id)) =
        (config.control_plane.clone(), session_id.map(str::to_owned))
    else {
        return true;
    };
    let connection_key = config.connection_key.clone();
    let sql = sql.to_owned();
    let mut worker = tokio::task::spawn_blocking(move || {
        control_plane.record_query(&session_id, &connection_key, "proxy", &sql)
    });
    loop {
        tokio::select! {
            _ = wait_shutdown(shutdown) => {
                let _ = (&mut worker).await;
                return false;
            }
            incoming = frontend.message(), if pending_frontend.is_none() => {
                match incoming {
                    Ok(frame) if frame.kind == b'X' => {
                        let _ = (&mut worker).await;
                        return false;
                    }
                    Ok(frame) => *pending_frontend = Some(frame),
                    Err(FrameError::Eof) => {
                        let _ = (&mut worker).await;
                        return false;
                    }
                    Err(_) => {
                        let _ = (&mut worker).await;
                        let _ = write_error(client, "FATAL", "08P01", "invalid pipelined PostgreSQL frame").await;
                        return false;
                    }
                }
            }
            result = &mut worker => {
                // History failure is observational only: do not block, deny,
                // or retry a permitted backend operation because it failed.
                let _ = result;
                return true;
            }
        }
    }
}

async fn forward_permitted_query(
    permit: qk_db::ExecutionPermit,
    frame: Frame,
    backend: &mut tokio::net::tcp::OwnedWriteHalf,
) -> Result<(), ()> {
    if permit.dialect() != qk_sql::SqlDialect::PostgreSql {
        return Err(());
    }
    // Move-only authority is consumed before the original frame is written.
    drop(permit);
    backend.write_all(&frame.raw).await.map_err(|_| ())
}

async fn relay_until_ready(
    backend: &mut BackendSession,
    frontend: &mut FrameReader<tokio::net::tcp::OwnedReadHalf>,
    client: &mut tokio::net::tcp::OwnedWriteHalf,
    pending_frontend: &mut Option<Frame>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(), ()> {
    loop {
        tokio::select! {
            _ = wait_shutdown(shutdown) => return Err(()),
            incoming = frontend.message(), if pending_frontend.is_none() => {
                match incoming {
                    Ok(frame) => *pending_frontend = Some(frame),
                    Err(FrameError::Eof) => return Err(()),
                    Err(_) => return Err(()),
                }
            }
            incoming = backend.reader.message() => {
                let message = incoming.map_err(|_| ())?;
                if matches!(message.kind, b'G' | b'H' | b'W' | b'd' | b'c' | b'f') {
                    // The originating SQL should already have been rejected
                    // by the shared Operation::Copy gate. Never relay a COPY
                    // stream even if a backend responds unexpectedly.
                    return Err(());
                }
                if message.kind == b'S' {
                    let (name, value) = parse_parameter_status(message.payload()).ok_or(())?;
                    if name == "client_encoding" {
                        backend.client_encoding = Some(value);
                    }
                }
                if message.kind == b'Z' {
                    backend.transaction_status = parse_ready_status(message.payload()).map_err(|_| ())?;
                    client.write_all(&message.raw).await.map_err(|_| ())?;
                    return Ok(());
                }
                client.write_all(&message.raw).await.map_err(|_| ())?;
            }
        }
    }
}

async fn drain_until_sync(
    frontend: &mut FrameReader<tokio::net::tcp::OwnedReadHalf>,
    client: &mut tokio::net::tcp::OwnedWriteHalf,
    backend: &mut BackendSession,
    pending_frontend: &mut Option<Frame>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(), ()> {
    loop {
        let frame = match pending_frontend.take() {
            Some(frame) => frame,
            None => tokio::select! {
                _ = wait_shutdown(shutdown) => return Err(()),
                message = frontend.message() => message.map_err(|_| ())?,
            },
        };
        if frame.kind == b'X' {
            let _ = backend.writer.write_all(&frame.raw).await;
            return Err(());
        }
        if frame.kind == b'S' {
            if !frame.payload().is_empty() {
                return Err(());
            }
            send_ready(client, backend.transaction_status).await?;
            return Ok(());
        }
        // Ignore all messages after the synthetic error until Sync. No stale
        // executable operation is sent to the backend.
    }
}

fn parse_parameter_status(payload: &[u8]) -> Option<(String, String)> {
    let name_end = payload.iter().position(|byte| *byte == 0)?;
    let rest = payload.get(name_end + 1..)?;
    let value_end = rest.iter().position(|byte| *byte == 0)?;
    if value_end + 1 != rest.len() {
        return None;
    }
    Some((
        std::str::from_utf8(payload.get(..name_end)?)
            .ok()?
            .to_owned(),
        std::str::from_utf8(rest.get(..value_end)?).ok()?.to_owned(),
    ))
}

fn parse_ready_status(payload: &[u8]) -> Result<u8, ()> {
    if payload.len() == 1 && matches!(payload[0], b'I' | b'T' | b'E') {
        Ok(payload[0])
    } else {
        Err(())
    }
}

async fn send_local_error(
    frontend: &mut tokio::net::tcp::OwnedWriteHalf,
    status: u8,
    code: &str,
    message: &str,
) -> Result<(), ()> {
    send_error_only(frontend, "ERROR", code, message).await?;
    send_ready(frontend, status).await
}

async fn send_error_only(
    frontend: &mut tokio::net::tcp::OwnedWriteHalf,
    severity: &str,
    code: &str,
    message: &str,
) -> Result<(), ()> {
    let error = encode_error(severity, code, message).map_err(|_| ())?;
    frontend.write_all(&error).await.map_err(|_| ())
}

async fn send_ready(frontend: &mut tokio::net::tcp::OwnedWriteHalf, status: u8) -> Result<(), ()> {
    let ready = encode_ready(status).map_err(|_| ())?;
    frontend.write_all(&ready).await.map_err(|_| ())
}

async fn write_error<W: AsyncWrite + Unpin>(
    frontend: &mut W,
    severity: &str,
    code: &str,
    message: &str,
) -> Result<(), ()> {
    let error = encode_error(severity, code, message).map_err(|_| ())?;
    frontend.write_all(&error).await.map_err(|_| ())
}

async fn wait_shutdown(shutdown: &mut watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}
