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

const BACKEND_FLUSH_FRAME: [u8; 5] = [b'H', 0, 0, 0, 4];

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

/// Bound per-frontend prepared statement/portal capacity.
const MAX_STATEMENTS_PER_CLIENT: usize = 1024;
const MAX_PORTALS_PER_CLIENT: usize = 1024;
const MAX_CLIENT_EXTENDED_STATE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug)]
struct PreparedStatement {
    sql: String,
    parameter_type_hints: Vec<Option<u32>>,
    version: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PortalState {
    Bound,
    Suspended,
    Completed,
    Failed,
}

#[derive(Debug)]
struct Portal {
    statement: Arc<PreparedStatement>,
    execution_params: Vec<ExecutionParam>,
    parameter_formats: Vec<qk_core::ParamRepresentation>,
    result_formats: Vec<i16>,
    backend_state: PortalState,
}

/// Prepared protocol state is private to one frontend/backend session.
#[derive(Default)]
struct ExtendedState {
    statements: std::collections::HashMap<String, Arc<PreparedStatement>>,
    portals: std::collections::HashMap<String, Portal>,
    next_statement_version: u64,
    retained_bytes: usize,
    error_until_sync: bool,
}

impl ExtendedState {
    fn begin_unnamed_parse(&mut self) {
        if let Some(statement) = self.statements.remove("") {
            self.retained_bytes = self
                .retained_bytes
                .saturating_sub(statement_state_bytes(&statement));
        }
    }

    fn begin_unnamed_bind(&mut self) {
        self.remove_portal("");
    }

    fn clear_unnamed_for_simple_query(&mut self) {
        self.begin_unnamed_parse();
        self.begin_unnamed_bind();
    }

    fn insert_statement(&mut self, name: String, statement: Arc<PreparedStatement>) {
        self.retained_bytes = self
            .retained_bytes
            .saturating_add(statement_state_bytes(&statement));
        self.statements.insert(name, statement);
    }

    fn remove_statement(&mut self, name: &str) {
        if let Some(statement) = self.statements.remove(name) {
            self.retained_bytes = self
                .retained_bytes
                .saturating_sub(statement_state_bytes(&statement));
            let mut removed_bytes = 0usize;
            self.portals.retain(|_, portal| {
                let keep = !Arc::ptr_eq(&portal.statement, &statement);
                if !keep {
                    removed_bytes = removed_bytes.saturating_add(portal_state_bytes(portal));
                }
                keep
            });
            self.retained_bytes = self.retained_bytes.saturating_sub(removed_bytes);
        }
    }

    fn insert_portal(&mut self, name: String, portal: Portal) {
        self.remove_portal(&name);
        self.retained_bytes = self
            .retained_bytes
            .saturating_add(portal_state_bytes(&portal));
        self.portals.insert(name, portal);
    }

    fn remove_portal(&mut self, name: &str) {
        if let Some(portal) = self.portals.remove(name) {
            self.retained_bytes = self
                .retained_bytes
                .saturating_sub(portal_state_bytes(&portal));
        }
    }

    fn complete_sync(&mut self, transaction_status: u8) {
        self.error_until_sync = false;
        if transaction_status == b'I' {
            let portal_bytes = self
                .portals
                .values()
                .map(portal_state_bytes)
                .fold(0usize, usize::saturating_add);
            self.retained_bytes = self.retained_bytes.saturating_sub(portal_bytes);
            self.portals.clear();
        }
    }
}

fn statement_state_bytes(statement: &PreparedStatement) -> usize {
    statement
        .sql
        .len()
        .saturating_add(statement.parameter_type_hints.len() * std::mem::size_of::<Option<u32>>())
}

fn execution_param_bytes(parameter: &ExecutionParam) -> usize {
    match parameter {
        ExecutionParam::Null => 0,
        ExecutionParam::Bool(_) => std::mem::size_of::<bool>(),
        ExecutionParam::Int(_) | ExecutionParam::UInt(_) | ExecutionParam::FloatBits(_) => 8,
        ExecutionParam::Text(value) => value.len(),
        ExecutionParam::Bytes(value) => value.len(),
        ExecutionParam::Wire { bytes, .. } => bytes.len(),
    }
}

fn portal_state_bytes(portal: &Portal) -> usize {
    let parameter_bytes = portal
        .execution_params
        .iter()
        .map(execution_param_bytes)
        .fold(0usize, usize::saturating_add);
    portal
        .statement
        .sql
        .len()
        .saturating_add(parameter_bytes)
        .saturating_add(
            portal.statement.parameter_type_hints.len() * std::mem::size_of::<Option<u32>>(),
        )
        .saturating_add(
            portal.parameter_formats.len() * std::mem::size_of::<qk_core::ParamRepresentation>(),
        )
        .saturating_add(portal.result_formats.len() * std::mem::size_of::<i16>())
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
    let mut extended = ExtendedState::default();
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
        if frame.kind == b'X' {
            let _ = backend.writer.write_all(&frame.raw).await;
            return;
        }
        if extended.error_until_sync {
            if frame.kind != b'S' {
                continue;
            }
            if protocol::validate_empty_message(frame.payload()).is_err() {
                let _ = write_error(
                    &mut frontend_write,
                    "FATAL",
                    "08P01",
                    "invalid PostgreSQL Sync message",
                )
                .await;
                return;
            }
            if backend.writer.write_all(&frame.raw).await.is_err()
                || relay_extended_ready(
                    &mut backend,
                    &mut frontend,
                    &mut frontend_write,
                    &mut pending_frontend,
                    &mut shutdown,
                    &extended,
                )
                .await
                .is_err()
            {
                return;
            }
            extended.complete_sync(backend.transaction_status);
            continue;
        }
        match frame.kind {
            b'Q' => {
                extended.clear_unnamed_for_simple_query();
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
            b'P' | b'B' | b'D' | b'E' | b'C' | b'H' => {
                if process_extended_frame(
                    frame,
                    &mut extended,
                    config.clone(),
                    session_id.clone(),
                    ExtendedIo {
                        frontend: &mut frontend,
                        client: &mut frontend_write,
                        backend: &mut backend,
                        pending_frontend: &mut pending_frontend,
                        shutdown: &mut shutdown,
                    },
                )
                .await
                .is_err()
                {
                    return;
                }
            }
            b'S' => {
                if protocol::validate_empty_message(frame.payload()).is_err() {
                    let _ = write_error(
                        &mut frontend_write,
                        "FATAL",
                        "08P01",
                        "invalid PostgreSQL Sync message",
                    )
                    .await;
                    return;
                }
                if backend.writer.write_all(&frame.raw).await.is_err() {
                    return;
                }
                if relay_extended_ready(
                    &mut backend,
                    &mut frontend,
                    &mut frontend_write,
                    &mut pending_frontend,
                    &mut shutdown,
                    &extended,
                )
                .await
                .is_err()
                {
                    return;
                }
                extended.complete_sync(backend.transaction_status);
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

struct ExtendedIo<'a> {
    frontend: &'a mut FrameReader<tokio::net::tcp::OwnedReadHalf>,
    client: &'a mut tokio::net::tcp::OwnedWriteHalf,
    backend: &'a mut BackendSession,
    pending_frontend: &'a mut Option<Frame>,
    shutdown: &'a mut watch::Receiver<bool>,
}

#[derive(Clone, Copy)]
enum ExtendedBoundary {
    Parse,
    Bind,
    Describe,
    Close,
    Execute,
}

enum ExtendedResponse {
    Complete(u8),
    Error,
}

async fn process_extended_frame(
    frame: Frame,
    state: &mut ExtendedState,
    config: Arc<ProxyConfig>,
    session_id: Option<String>,
    io: ExtendedIo<'_>,
) -> Result<(), ()> {
    let ExtendedIo {
        frontend,
        client,
        backend,
        pending_frontend,
        shutdown,
    } = io;
    match frame.kind {
        b'P' => {
            let parsed = match protocol::parse_extended_parse(frame.payload()) {
                Ok(parsed) => parsed,
                Err(error) => {
                    let (code, message) =
                        extended_decode_error(error, "invalid PostgreSQL Parse message");
                    return reject_extended(state, client, code, message).await;
                }
            };
            if parsed.name.is_empty() {
                state.begin_unnamed_parse();
            }
            let new_statement_bytes = parsed.sql.len().saturating_add(
                parsed.parameter_type_hints.len() * std::mem::size_of::<Option<u32>>(),
            );
            let existing_named =
                !parsed.name.is_empty() && state.statements.contains_key(&parsed.name);
            if !existing_named
                && !state.statements.contains_key(&parsed.name)
                && state.statements.len() >= MAX_STATEMENTS_PER_CLIENT
            {
                return reject_extended(state, client, "54000", "prepared statement limit reached")
                    .await;
            }
            if !existing_named
                && state.retained_bytes.saturating_add(new_statement_bytes)
                    > MAX_CLIENT_EXTENDED_STATE_BYTES
            {
                return reject_extended(
                    state,
                    client,
                    "54000",
                    "prepared statement state limit reached",
                )
                .await;
            }
            let Some(version) = state.next_statement_version.checked_add(1) else {
                return reject_extended(state, client, "54000", "statement version limit reached")
                    .await;
            };
            let pending_statement = Arc::new(PreparedStatement {
                sql: parsed.sql,
                parameter_type_hints: parsed.parameter_type_hints,
                version,
            });
            backend.writer.write_all(&frame.raw).await.map_err(|_| ())?;
            flush_backend_output(&mut backend.writer).await?;
            match relay_extended_response(
                backend,
                frontend,
                client,
                pending_frontend,
                shutdown,
                ExtendedBoundary::Parse,
                None,
            )
            .await?
            {
                ExtendedResponse::Complete(b'1') => {
                    state.next_statement_version = version;
                    state.insert_statement(parsed.name, pending_statement);
                }
                ExtendedResponse::Error => state.error_until_sync = true,
                _ => return Err(()),
            }
        }
        b'B' => {
            if frame.payload().first() == Some(&0) {
                state.begin_unnamed_bind();
            }
            let mut bound = match protocol::parse_extended_bind(frame.payload(), &[]) {
                Ok(bound) => bound,
                Err(error) => {
                    let (code, message) =
                        extended_decode_error(error, "invalid PostgreSQL Bind message");
                    return reject_extended(state, client, code, message).await;
                }
            };
            let Some(statement) = state.statements.get(&bound.statement_name).cloned() else {
                return reject_extended(
                    state,
                    client,
                    "26000",
                    "prepared statement does not exist",
                )
                .await;
            };
            for (index, parameter) in bound.execution_params.iter_mut().enumerate() {
                if let ExecutionParam::Wire { type_hint, .. } = parameter {
                    *type_hint = statement.parameter_type_hints.get(index).copied().flatten();
                }
            }
            if !bound.portal_name.is_empty()
                && !state.portals.contains_key(&bound.portal_name)
                && state.portals.len() >= MAX_PORTALS_PER_CLIENT
            {
                return reject_extended(state, client, "54000", "portal limit reached").await;
            }
            let portal_name = bound.portal_name.clone();
            let pending_portal = Portal {
                statement,
                execution_params: bound.execution_params,
                parameter_formats: bound.parameter_formats,
                result_formats: bound.result_formats,
                backend_state: PortalState::Bound,
            };
            if !state.portals.contains_key(&portal_name)
                && state
                    .retained_bytes
                    .saturating_add(portal_state_bytes(&pending_portal))
                    > MAX_CLIENT_EXTENDED_STATE_BYTES
            {
                return reject_extended(state, client, "54000", "portal state limit reached").await;
            }
            let redaction_parameters = [pending_portal.execution_params.as_slice()];
            backend.writer.write_all(&frame.raw).await.map_err(|_| ())?;
            flush_backend_output(&mut backend.writer).await?;
            match relay_extended_response(
                backend,
                frontend,
                client,
                pending_frontend,
                shutdown,
                ExtendedBoundary::Bind,
                Some(&redaction_parameters),
            )
            .await?
            {
                ExtendedResponse::Complete(b'2') => {
                    state.insert_portal(portal_name, pending_portal);
                }
                ExtendedResponse::Error => state.error_until_sync = true,
                _ => return Err(()),
            }
        }
        b'D' => {
            let target = match protocol::parse_extended_target(frame.payload()) {
                Ok(target) => target,
                Err(_) => {
                    return reject_extended(
                        state,
                        client,
                        "08P01",
                        "invalid PostgreSQL Describe target",
                    )
                    .await;
                }
            };
            let exists = match target.target {
                protocol::ExtendedTarget::Statement => state.statements.contains_key(&target.name),
                protocol::ExtendedTarget::Portal => state.portals.contains_key(&target.name),
            };
            if !exists {
                let (code, message) = match target.target {
                    protocol::ExtendedTarget::Statement => {
                        ("26000", "prepared statement does not exist")
                    }
                    protocol::ExtendedTarget::Portal => ("34000", "portal does not exist"),
                };
                return reject_extended(state, client, code, message).await;
            }
            let redaction_parameters = match target.target {
                protocol::ExtendedTarget::Statement => Vec::new(),
                protocol::ExtendedTarget::Portal => state
                    .portals
                    .get(&target.name)
                    .map(|portal| vec![portal.execution_params.as_slice()])
                    .unwrap_or_default(),
            };
            backend.writer.write_all(&frame.raw).await.map_err(|_| ())?;
            flush_backend_output(&mut backend.writer).await?;
            match relay_extended_response(
                backend,
                frontend,
                client,
                pending_frontend,
                shutdown,
                ExtendedBoundary::Describe,
                Some(&redaction_parameters),
            )
            .await?
            {
                ExtendedResponse::Complete(b'T' | b'n') => {}
                ExtendedResponse::Error => state.error_until_sync = true,
                _ => return Err(()),
            }
        }
        b'C' => {
            let target = match protocol::parse_extended_target(frame.payload()) {
                Ok(target) => target,
                Err(_) => {
                    return reject_extended(
                        state,
                        client,
                        "08P01",
                        "invalid PostgreSQL Close target",
                    )
                    .await;
                }
            };
            backend.writer.write_all(&frame.raw).await.map_err(|_| ())?;
            flush_backend_output(&mut backend.writer).await?;
            match relay_extended_response(
                backend,
                frontend,
                client,
                pending_frontend,
                shutdown,
                ExtendedBoundary::Close,
                None,
            )
            .await?
            {
                ExtendedResponse::Complete(b'3') => match target.target {
                    protocol::ExtendedTarget::Statement => state.remove_statement(&target.name),
                    protocol::ExtendedTarget::Portal => {
                        state.remove_portal(&target.name);
                    }
                },
                ExtendedResponse::Error => state.error_until_sync = true,
                _ => return Err(()),
            }
        }
        b'H' => {
            if protocol::validate_empty_message(frame.payload()).is_err() {
                return reject_extended(state, client, "08P01", "invalid PostgreSQL Flush message")
                    .await;
            }
            backend.writer.write_all(&frame.raw).await.map_err(|_| ())?;
            backend.writer.flush().await.map_err(|_| ())?;
        }
        b'E' => {
            let execute = match protocol::parse_extended_execute(frame.payload()) {
                Ok(execute) => execute,
                Err(_) => {
                    return reject_extended(
                        state,
                        client,
                        "08P01",
                        "invalid PostgreSQL Execute message",
                    )
                    .await;
                }
            };
            let Some(portal) = state.portals.get(&execute.portal_name) else {
                return reject_extended(state, client, "34000", "portal does not exist").await;
            };
            if portal.backend_state == PortalState::Failed {
                return reject_extended(state, client, "34000", "portal is not executable").await;
            }
            if portal.parameter_formats.len() != portal.execution_params.len()
                || portal
                    .result_formats
                    .iter()
                    .any(|format| !matches!(format, 0 | 1))
                || !portal
                    .parameter_formats
                    .iter()
                    .zip(&portal.execution_params)
                    .all(|(format, parameter)| match parameter {
                        ExecutionParam::Wire { representation, .. } => format == representation,
                        ExecutionParam::Null => true,
                        _ => false,
                    })
            {
                return Err(());
            }
            let redaction_parameters = [portal.execution_params.as_slice()];
            let statement_version = portal.statement.version;
            let sql = portal.statement.sql.clone();
            let params = portal.execution_params.clone();
            let authorization = match authorize_extended_execute(
                config.clone(),
                session_id.clone(),
                sql.clone(),
                params,
                AuthorizationIo {
                    frontend,
                    client,
                    backend_writer: &mut backend.writer,
                    pending_frontend,
                    shutdown,
                },
            )
            .await
            {
                Some(outcome) => outcome,
                None => return Err(()),
            };
            let permit = match authorization {
                AuthorizationOutcome::Blocked(reason) => {
                    let code = if reason.code == "UNSUPPORTED_OPERATION" {
                        "0A000"
                    } else {
                        "42501"
                    };
                    return reject_extended(state, client, code, &reason.message).await;
                }
                AuthorizationOutcome::PendingApproval(pending) => {
                    let message = format!("waiting for approval: {}", pending.approval_id);
                    return reject_extended(state, client, "42501", &message).await;
                }
                AuthorizationOutcome::Failed(error) => {
                    return reject_extended(state, client, "42501", error.message()).await;
                }
                AuthorizationOutcome::Permitted(permit) => permit,
            };
            if permit.dialect() != qk_sql::SqlDialect::PostgreSql
                || permit.includes_operation(&Operation::Copy)
                || permit.includes_operation(&Operation::Set)
            {
                return reject_extended(
                    state,
                    client,
                    "0A000",
                    "statement operation is not supported by this proxy",
                )
                .await;
            }
            if !record_history(
                &config,
                session_id.as_deref(),
                &sql,
                frontend,
                client,
                pending_frontend,
                shutdown,
            )
            .await
            {
                return Err(());
            }
            forward_permitted_execute(*permit, frame, &mut backend.writer)
                .await
                .map_err(|_| ())?;
            flush_backend_output(&mut backend.writer).await?;
            match relay_extended_response(
                backend,
                frontend,
                client,
                pending_frontend,
                shutdown,
                ExtendedBoundary::Execute,
                Some(&redaction_parameters),
            )
            .await?
            {
                ExtendedResponse::Complete(b'C' | b'I') => {
                    if let Some(portal) = state.portals.get_mut(&execute.portal_name) {
                        if portal.statement.version != statement_version {
                            return Err(());
                        }
                        portal.backend_state = PortalState::Completed;
                    }
                }
                ExtendedResponse::Complete(b's') => {
                    if let Some(portal) = state.portals.get_mut(&execute.portal_name) {
                        if portal.statement.version != statement_version {
                            return Err(());
                        }
                        portal.backend_state = PortalState::Suspended;
                    }
                }
                ExtendedResponse::Error => {
                    if let Some(portal) = state.portals.get_mut(&execute.portal_name) {
                        portal.backend_state = PortalState::Failed;
                    }
                    state.error_until_sync = true;
                }
                _ => return Err(()),
            }
        }
        _ => return Err(()),
    }
    Ok(())
}

fn extended_decode_error(
    error: FrameError,
    malformed: &'static str,
) -> (&'static str, &'static str) {
    if error == FrameError::TooLarge {
        (
            "54000",
            "PostgreSQL extended message exceeds the proxy limit",
        )
    } else {
        ("08P01", malformed)
    }
}

async fn reject_extended(
    state: &mut ExtendedState,
    client: &mut tokio::net::tcp::OwnedWriteHalf,
    code: &str,
    message: &str,
) -> Result<(), ()> {
    send_error_only(client, "ERROR", code, message).await?;
    state.error_until_sync = true;
    Ok(())
}

async fn relay_extended_response(
    backend: &mut BackendSession,
    frontend: &mut FrameReader<tokio::net::tcp::OwnedReadHalf>,
    client: &mut tokio::net::tcp::OwnedWriteHalf,
    pending_frontend: &mut Option<Frame>,
    shutdown: &mut watch::Receiver<bool>,
    boundary: ExtendedBoundary,
    parameters: Option<&[&[ExecutionParam]]>,
) -> Result<ExtendedResponse, ()> {
    loop {
        let incoming = tokio::select! {
            _ = wait_shutdown(shutdown) => return Err(()),
            frontend_frame = frontend.message(), if pending_frontend.is_none() => {
                match frontend_frame {
                    Ok(frame) => {
                        *pending_frontend = Some(frame);
                    }
                    Err(_) => return Err(()),
                }
                continue;
            }
            backend_frame = backend.reader.message() => backend_frame.map_err(|_| ())?,
        };
        if matches!(incoming.kind, b'G' | b'H' | b'W' | b'd' | b'c' | b'f') {
            return Err(());
        }
        if incoming.kind == b'S' {
            let (name, value) = parse_parameter_status(incoming.payload()).ok_or(())?;
            if name == "client_encoding" {
                backend.client_encoding = Some(value);
            }
        }
        if incoming.kind == b'E' {
            let redacted = match parameters {
                Some(parameters) => redact_backend_error(&incoming, parameters)?,
                None => None,
            };
            client
                .write_all(redacted.as_deref().unwrap_or(&incoming.raw))
                .await
                .map_err(|_| ())?;
            return Ok(ExtendedResponse::Error);
        }
        if incoming.kind == b'Z' {
            return Err(());
        }
        let kind = incoming.kind;
        client.write_all(&incoming.raw).await.map_err(|_| ())?;
        let complete = match boundary {
            ExtendedBoundary::Parse => kind == b'1',
            ExtendedBoundary::Bind => kind == b'2',
            ExtendedBoundary::Describe => matches!(kind, b'T' | b'n'),
            ExtendedBoundary::Close => kind == b'3',
            ExtendedBoundary::Execute => matches!(kind, b'C' | b'I' | b's'),
        };
        if complete {
            return Ok(ExtendedResponse::Complete(kind));
        }
    }
}

async fn relay_extended_ready(
    backend: &mut BackendSession,
    frontend: &mut FrameReader<tokio::net::tcp::OwnedReadHalf>,
    client: &mut tokio::net::tcp::OwnedWriteHalf,
    pending_frontend: &mut Option<Frame>,
    shutdown: &mut watch::Receiver<bool>,
    state: &ExtendedState,
) -> Result<(), ()> {
    let parameter_groups: Vec<&[ExecutionParam]> = state
        .portals
        .values()
        .map(|portal| portal.execution_params.as_slice())
        .collect();
    loop {
        tokio::select! {
            _ = wait_shutdown(shutdown) => return Err(()),
            frontend_frame = frontend.message(), if pending_frontend.is_none() => {
                match frontend_frame {
                    Ok(frame) => *pending_frontend = Some(frame),
                    Err(_) => return Err(()),
                }
            }
            backend_frame = backend.reader.message() => {
                let message = backend_frame.map_err(|_| ())?;
                if matches!(message.kind, b'G' | b'H' | b'W' | b'd' | b'c' | b'f') {
                    return Err(());
                }
                if message.kind == b'S' {
                    let (name, value) = parse_parameter_status(message.payload()).ok_or(())?;
                    if name == "client_encoding" {
                        backend.client_encoding = Some(value);
                    }
                }
                if message.kind == b'E' {
                    let redacted = redact_backend_error(&message, &parameter_groups)?;
                    client
                        .write_all(redacted.as_deref().unwrap_or(&message.raw))
                        .await
                        .map_err(|_| ())?;
                    continue;
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

const MAX_ERROR_REDACTION_PARAMETERS: usize = 16;
const MAX_ERROR_REDACTION_PARAMETER_BYTES: usize = 512;
const MAX_ERROR_REDACTION_FRAME_BYTES: usize = 8 * 1024;

fn parameter_bytes(parameter: &ExecutionParam) -> Option<&[u8]> {
    match parameter {
        ExecutionParam::Wire { bytes, .. } => Some(bytes),
        ExecutionParam::Text(text) => Some(text.as_bytes()),
        ExecutionParam::Bytes(bytes) => Some(bytes),
        ExecutionParam::Null
        | ExecutionParam::Bool(_)
        | ExecutionParam::Int(_)
        | ExecutionParam::UInt(_)
        | ExecutionParam::FloatBits(_) => None,
    }
}

fn contains_bind_bytes(field: &[u8], parameter_groups: &[&[ExecutionParam]]) -> bool {
    parameter_groups
        .iter()
        .flat_map(|group| group.iter())
        .any(|parameter| {
            let Some(value) = parameter_bytes(parameter) else {
                return false;
            };
            !value.is_empty()
                && value.len() <= field.len()
                && field.windows(value.len()).any(|window| window == value)
        })
}

fn error_field_has_bind_bytes(
    payload: &[u8],
    parameter_groups: &[&[ExecutionParam]],
) -> Result<bool, ()> {
    let mut offset = 0usize;
    while offset < payload.len() {
        let tag = payload[offset];
        offset += 1;
        if tag == 0 {
            return (offset == payload.len()).then_some(false).ok_or(());
        }
        let end = payload
            .get(offset..)
            .and_then(|rest| rest.iter().position(|byte| *byte == 0))
            .map(|relative| offset + relative)
            .ok_or(())?;
        if contains_bind_bytes(&payload[offset..end], parameter_groups) {
            return Ok(true);
        }
        offset = end + 1;
    }
    Err(())
}

fn redacted_error_message(parameter_groups: &[&[ExecutionParam]]) -> Option<&'static [u8]> {
    [
        b"backend details redacted".as_slice(),
        b"query details omitted".as_slice(),
        b"database response withheld".as_slice(),
    ]
    .into_iter()
    .find(|message| !contains_bind_bytes(message, parameter_groups))
}

/// Preserve backend ErrorResponse fields unless they contain a bound value.
/// Large/high-arity requests use conservative message-field removal instead
/// of an unbounded many-pattern scan.
fn redact_backend_error(
    frame: &Frame,
    parameter_groups: &[&[ExecutionParam]],
) -> Result<Option<Vec<u8>>, ()> {
    let mut aggregate_bytes = 0usize;
    let mut nonempty_count = 0usize;
    for parameter in parameter_groups.iter().flat_map(|group| group.iter()) {
        if let Some(bytes) = parameter_bytes(parameter) {
            if !bytes.is_empty() {
                aggregate_bytes = aggregate_bytes.saturating_add(bytes.len());
                nonempty_count += 1;
            }
        }
    }
    if nonempty_count == 0 {
        return Ok(None);
    }
    let payload = frame.payload();
    let conservative = frame.raw.len() > MAX_ERROR_REDACTION_FRAME_BYTES
        || aggregate_bytes > MAX_ERROR_REDACTION_PARAMETER_BYTES
        || nonempty_count > MAX_ERROR_REDACTION_PARAMETERS;
    if !conservative && !error_field_has_bind_bytes(payload, parameter_groups)? {
        return Ok(None);
    }

    let generic_message = redacted_error_message(parameter_groups);
    let mut redacted = Vec::with_capacity(payload.len().min(MAX_ERROR_REDACTION_FRAME_BYTES));
    let mut offset = 0usize;
    let mut has_message = false;
    while offset < payload.len() {
        let tag = payload[offset];
        offset += 1;
        if tag == 0 {
            if offset != payload.len() {
                return Err(());
            }
            break;
        }
        let end = payload
            .get(offset..)
            .and_then(|rest| rest.iter().position(|byte| *byte == 0))
            .map(|relative| offset + relative)
            .ok_or(())?;
        let value = &payload[offset..end];
        let matches_parameter = contains_bind_bytes(value, parameter_groups);
        let control_field = matches!(tag, b'S' | b'V' | b'C');
        let keep = if conservative {
            control_field && !matches_parameter
        } else {
            !matches_parameter && tag != b'M'
        };
        if keep {
            redacted.push(tag);
            redacted.extend_from_slice(value);
            redacted.push(0);
            has_message |= tag == b'M';
        } else if tag == b'M' {
            if let Some(message) = generic_message {
                redacted.push(b'M');
                redacted.extend_from_slice(message);
                redacted.push(0);
                has_message = true;
            }
        }
        offset = end + 1;
    }
    if !has_message {
        if let Some(message) = generic_message {
            redacted.push(b'M');
            redacted.extend_from_slice(message);
            redacted.push(0);
        }
    }
    redacted.push(0);
    protocol::encode_message(b'E', &redacted)
        .map(Some)
        .map_err(|_| ())
}

async fn authorize_extended_execute(
    config: Arc<ProxyConfig>,
    session_id: Option<String>,
    sql: String,
    params: Vec<ExecutionParam>,
    io: AuthorizationIo<'_>,
) -> Option<AuthorizationOutcome> {
    let AuthorizationIo {
        frontend,
        client,
        backend_writer,
        pending_frontend,
        shutdown,
    } = io;
    let mut worker = tokio::task::spawn_blocking(move || {
        let store = InMemoryApprovalStore::new();
        let provider = match (config.control_plane.clone(), session_id.clone()) {
            (Some(client), Some(session_id)) => Some(
                DaemonApprovalProvider::new(
                    client,
                    Some(session_id),
                    config.connection_key.clone(),
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
            environment: config.environment.clone(),
            database: config.database.clone(),
            tool: "proxy_query".to_owned(),
            session_id,
        };
        let mut request = AuthorizationRequest::new(sql, params);
        request
            .reject_operations
            .extend([Operation::Copy, Operation::Set]);
        authorize_guarded(
            &CursorStore::new(),
            &GuardedAuthorizationCall {
                config: &config.db_config,
                connection_key: &config.connection_key,
                auth: &auth,
                approval: Some(&setup),
                policy: &config.policy,
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

async fn forward_permitted_execute(
    permit: qk_db::ExecutionPermit,
    frame: Frame,
    backend: &mut tokio::net::tcp::OwnedWriteHalf,
) -> Result<(), ()> {
    if permit.dialect() != qk_sql::SqlDialect::PostgreSql {
        return Err(());
    }
    drop(permit);
    backend.write_all(&frame.raw).await.map_err(|_| ())
}

async fn flush_backend_output(backend: &mut tokio::net::tcp::OwnedWriteHalf) -> Result<(), ()> {
    backend
        .write_all(&BACKEND_FLUSH_FRAME)
        .await
        .map_err(|_| ())?;
    backend.flush().await.map_err(|_| ())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn backend_error(message: &str) -> Frame {
        let payload = [b"SERROR\0C22P02\0M".as_slice(), message.as_bytes(), b"\0\0"].concat();
        Frame {
            kind: b'E',
            raw: protocol::encode_message(b'E', &payload).unwrap().into(),
        }
    }

    fn wire_text(value: &[u8]) -> ExecutionParam {
        ExecutionParam::Wire {
            representation: qk_core::ParamRepresentation::Text,
            type_hint: Some(25),
            bytes: value.to_vec(),
        }
    }

    #[test]
    fn backend_parameter_echo_is_redacted_but_non_echo_error_is_preserved() {
        let secret = b"PG_BIND_SECRET_8675309";
        let frame = backend_error("invalid value PG_BIND_SECRET_8675309");
        let parameters = [wire_text(secret)];
        let groups = [parameters.as_slice()];
        let redacted = redact_backend_error(&frame, &groups)
            .unwrap()
            .expect("matched bind bytes");
        assert!(!redacted
            .windows(secret.len())
            .any(|window| window == secret));
        assert!(redacted.windows(5).any(|window| window == b"22P02"));
        assert!(redacted
            .windows(b"backend details redacted".len())
            .any(|window| window == b"backend details redacted"));

        let unrelated = backend_error("invalid input syntax for type integer");
        assert!(redact_backend_error(&unrelated, &groups).unwrap().is_none());
    }

    #[test]
    fn large_bind_error_uses_conservative_redaction() {
        let parameters: Vec<_> = (0..MAX_ERROR_REDACTION_PARAMETERS + 1)
            .map(|index| wire_text(format!("large-secret-{index}").as_bytes()))
            .collect();
        let frame = backend_error("specific backend details may include an input value");
        let groups = [parameters.as_slice()];
        let redacted = redact_backend_error(&frame, &groups)
            .unwrap()
            .expect("large bind set uses conservative redaction");
        for parameter in &parameters {
            if let ExecutionParam::Wire { bytes, .. } = parameter {
                assert!(!redacted
                    .windows(bytes.len())
                    .any(|window| window == bytes.as_slice()));
            }
        }
        assert!(redacted.windows(5).any(|window| window == b"22P02"));
    }
}
