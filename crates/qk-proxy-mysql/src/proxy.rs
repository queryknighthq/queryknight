use qk_approval::{ApprovalProvider, InMemoryApprovalStore};
use qk_control_plane::DaemonApprovalProvider;
use qk_db::{
    authorize_guarded, ApprovalSetup, AuthorizationOutcome, AuthorizationRequest, CursorStore,
    GuardedAuthorizationCall, ResolveMode, TrustedContext,
};
use qk_sql::Operation;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::config::{ProxyConfig, ProxyConfigError};
use crate::protocol::{
    auth_switch_plugin, command_code, encode_err, filter_server_greeting, is_eof, is_err, is_ok,
    lenenc, parse_login, query_sql, read_command, read_message, response_has_more_results,
    server_status_from_eof, server_status_from_ok, write_message, CapabilityState, FrontendCommand,
    Message, ProtocolError, COM_CHANGE_USER, COM_CONNECT, COM_DEBUG, COM_FIELD_LIST, COM_INIT_DB,
    COM_PING, COM_PROCESS_INFO, COM_PROCESS_KILL, COM_QUERY, COM_QUIT, COM_REFRESH,
    COM_RESET_CONNECTION, COM_SET_OPTION, COM_SHUTDOWN, COM_STATISTICS, COM_STMT_CLOSE,
    COM_STMT_EXECUTE, COM_STMT_FETCH, COM_STMT_PREPARE, COM_STMT_RESET, COM_STMT_SEND_LONG_DATA,
    MAX_COLUMNS, MAX_HANDSHAKE_PAYLOAD, MAX_LOGICAL_RESPONSE,
};
#[path = "proxy_prepared.rs"]
mod prepared_proxy;

/// Maximum simultaneous frontend/backend sessions.
pub const MAX_CLIENTS: usize = 128;
/// Maximum time to open the configured backend socket.
pub const BACKEND_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MYSQL_POLICY_ERROR: u16 = 1227;
const MYSQL_AUTH_ERROR: u16 = 1045;
const SQLSTATE_GENERAL: &[u8; 5] = b"HY000";
const SQLSTATE_AUTH: &[u8; 5] = b"28000";

/// Proxy startup/accept error. It never includes a URL, SQL, credential, or token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyError {
    /// Trusted backend or policy configuration failed validation.
    Configuration,
    /// Loopback listener bind, accept, or local address lookup failed.
    Listener,
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Configuration => "MySQL proxy configuration failed",
            Self::Listener => "MySQL proxy listener failed",
        })
    }
}

impl std::error::Error for ProxyError {}

impl From<ProxyConfigError> for ProxyError {
    fn from(_: ProxyConfigError) -> Self {
        Self::Configuration
    }
}

/// Bound loopback MySQL listener.
pub struct ProxyServer {
    listener: TcpListener,
    config: Arc<ProxyConfig>,
}

impl ProxyServer {
    /// Bind the configured listener.
    pub async fn bind(config: ProxyConfig) -> Result<Self, ProxyError> {
        let listener = TcpListener::bind(config.listen_addr())
            .await
            .map_err(|_| ProxyError::Listener)?;
        Ok(Self {
            listener,
            config: Arc::new(config),
        })
    }

    /// Actual listener address (port may be ephemeral in tests).
    pub fn local_addr(&self) -> Result<SocketAddr, ProxyError> {
        self.listener.local_addr().map_err(|_| ProxyError::Listener)
    }

    /// Accept clients until `shutdown` completes, then drop every session.
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
                        let error = encode_err(0, 1040, SQLSTATE_GENERAL, "MySQL proxy client limit reached");
                        let _ = stream.write_all(&error).await;
                        continue;
                    };
                    let config = self.config.clone();
                    let shutdown = shutdown_rx.clone();
                    clients.spawn(async move {
                        let _permit = permit;
                        tokio::select! {
                            _ = wait_for_shutdown(shutdown) => {}
                            _ = handle_client(stream, config) => {}
                        }
                    });
                }
            }
        }
        Ok(())
    }
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    let _ = shutdown.changed().await;
}

async fn handle_client(mut frontend: TcpStream, config: Arc<ProxyConfig>) {
    let backend = timeout(
        BACKEND_CONNECT_TIMEOUT,
        TcpStream::connect((config.backend.host.as_str(), config.backend.port)),
    )
    .await;
    let Ok(Ok(mut backend)) = backend else {
        let error = encode_err(
            0,
            2003,
            SQLSTATE_GENERAL,
            "cannot connect to configured MySQL backend",
        );
        let _ = frontend.write_all(&error).await;
        return;
    };

    let Ok((status_flags, capabilities)) =
        relay_handshake(&mut frontend, &mut backend, &config.backend).await
    else {
        return;
    };
    let session_id = create_proxy_session(&config).await;
    let mut backend_state = BackendState {
        status_flags,
        capabilities,
    };
    command_loop(
        &mut frontend,
        &mut backend,
        config.clone(),
        session_id.as_deref(),
        &mut backend_state,
    )
    .await;
}

async fn relay_handshake(
    frontend: &mut TcpStream,
    backend: &mut TcpStream,
    trusted: &crate::config::BackendConfig,
) -> Result<(u16, CapabilityState), ProtocolError> {
    let greeting = read_message(backend, Some(0), MAX_HANDSHAKE_PAYLOAD).await?;
    let filtered = match filter_server_greeting(&greeting.payload) {
        Ok(filtered) => filtered,
        Err(error) => {
            let packet = encode_err(
                0,
                MYSQL_AUTH_ERROR,
                SQLSTATE_AUTH,
                "unsupported MySQL backend handshake",
            );
            let _ = frontend.write_all(&packet).await;
            return Err(error);
        }
    };
    let server_advertised = filtered.server_capabilities;
    let proxy_supported = filtered.proxy_capabilities;
    write_message(frontend, greeting.sequence, &filtered.payload).await?;

    let login = read_message(frontend, Some(1), MAX_HANDSHAKE_PAYLOAD).await?;
    let parsed = match parse_login(&login.payload, proxy_supported) {
        Ok(parsed) => parsed,
        Err(error) => {
            let packet = encode_err(
                login.next_sequence(),
                MYSQL_AUTH_ERROR,
                SQLSTATE_AUTH,
                "unsupported MySQL login capabilities or character set",
            );
            let _ = frontend.write_all(&packet).await;
            return Err(error);
        }
    };
    if parsed.username != trusted.user.as_bytes() || parsed.database != trusted.database.as_bytes()
    {
        let packet = encode_err(
            login.next_sequence(),
            MYSQL_AUTH_ERROR,
            SQLSTATE_AUTH,
            "frontend MySQL user/database must match configured backend identity",
        );
        let _ = frontend.write_all(&packet).await;
        return Err(ProtocolError::Unsupported);
    }
    let capabilities = CapabilityState {
        server_advertised,
        proxy_supported,
        client_selected: parsed.capabilities,
    };
    write_message(backend, login.sequence, &login.payload).await?;

    let mut server_sequence = login.next_sequence();
    loop {
        let auth = read_message(backend, Some(server_sequence), MAX_HANDSHAKE_PAYLOAD).await?;
        let Some(kind) = auth.payload.first().copied() else {
            return Err(ProtocolError::Malformed);
        };
        if is_ok(&auth.payload) || is_err(&auth.payload) {
            write_message(frontend, auth.sequence, &auth.payload).await?;
            return if is_ok(&auth.payload) {
                Ok((server_status_from_ok(&auth.payload)?, capabilities))
            } else {
                Err(ProtocolError::Unsupported)
            };
        }
        if kind == 0xfe {
            auth_switch_plugin(&auth.payload)?;
            write_message(frontend, auth.sequence, &auth.payload).await?;
            let response =
                read_message(frontend, Some(auth.next_sequence()), MAX_HANDSHAKE_PAYLOAD).await?;
            write_message(backend, response.sequence, &response.payload).await?;
            server_sequence = response.next_sequence();
            continue;
        }
        if kind == 0x01 && auth.payload.get(1) == Some(&0x03) {
            write_message(frontend, auth.sequence, &auth.payload).await?;
            server_sequence = auth.next_sequence();
            continue;
        }
        return Err(ProtocolError::Unsupported);
    }
}

async fn create_proxy_session(config: &ProxyConfig) -> Option<String> {
    let client = config.control_plane.clone()?;
    let connection_key = config.connection_key.clone();
    tokio::task::spawn_blocking(move || client.create_session(&connection_key, "proxy"))
        .await
        .ok()
        .and_then(Result::ok)
        .filter(|session_id| !session_id.is_empty())
}

pub(super) struct BackendState {
    status_flags: u16,
    capabilities: CapabilityState,
}

async fn command_loop(
    frontend: &mut TcpStream,
    backend: &mut TcpStream,
    config: Arc<ProxyConfig>,
    session_id: Option<&str>,
    backend_state: &mut BackendState,
) {
    let mut prepared = prepared_proxy::PreparedState::default();
    loop {
        let command = match read_command(frontend).await {
            Ok(command) => command,
            Err(_) => return,
        };
        let message = match command {
            FrontendCommand::Message(message) => message,
            FrontendCommand::Oversized { response_sequence } => {
                let error = encode_err(
                    response_sequence,
                    MYSQL_POLICY_ERROR,
                    SQLSTATE_GENERAL,
                    "QueryKnight query exceeds the 1,000,000-byte SQL limit",
                );
                if frontend.write_all(&error).await.is_err() {
                    return;
                }
                continue;
            }
        };
        if message.sequence != 0 {
            return;
        }
        let code = match command_code(&message.payload) {
            Ok(code) => code,
            Err(_) => return,
        };
        match code {
            COM_QUIT => return,
            COM_PING => {
                if message.payload.len() != 1 {
                    if write_policy_error(frontend, 1, "malformed COM_PING")
                        .await
                        .is_err()
                    {
                        return;
                    }
                    continue;
                }
                if write_message(backend, 0, &message.payload).await.is_err()
                    || relay_response(frontend, backend, 1, backend_state, false)
                        .await
                        .is_err()
                {
                    return;
                }
            }
            COM_STMT_PREPARE => {
                if prepared_proxy::handle_prepare(
                    frontend,
                    backend,
                    &message,
                    &mut prepared,
                    backend_state,
                )
                .await
                .is_err()
                {
                    return;
                }
            }
            COM_STMT_EXECUTE => {
                if prepared_proxy::handle_execute(
                    frontend,
                    backend,
                    &message,
                    config.clone(),
                    session_id,
                    &mut prepared,
                    backend_state,
                )
                .await
                .is_err()
                {
                    return;
                }
            }
            COM_STMT_SEND_LONG_DATA => {
                if prepared_proxy::buffer_long_data(&message, &mut prepared).is_err() {
                    return;
                }
            }
            COM_STMT_RESET => {
                if prepared_proxy::handle_reset(
                    frontend,
                    backend,
                    &message,
                    &mut prepared,
                    backend_state,
                )
                .await
                .is_err()
                {
                    return;
                }
            }
            COM_STMT_CLOSE => {
                if prepared_proxy::handle_close(backend, &message, &mut prepared)
                    .await
                    .is_err()
                {
                    return;
                }
            }
            COM_STMT_FETCH => {
                if write_policy_error(
                    frontend,
                    message.next_sequence(),
                    "QueryKnight does not support MySQL prepared-statement cursors",
                )
                .await
                .is_err()
                {
                    return;
                }
            }
            COM_QUERY => {
                let sql = match query_sql(&message.payload) {
                    Ok(sql) => sql,
                    Err(ProtocolError::Oversized) => {
                        if write_policy_error(
                            frontend,
                            message.next_sequence(),
                            "QueryKnight query exceeds the 1,000,000-byte SQL limit",
                        )
                        .await
                        .is_err()
                        {
                            return;
                        }
                        continue;
                    }
                    Err(_) => {
                        if write_policy_error(
                            frontend,
                            message.next_sequence(),
                            "invalid or empty COM_QUERY",
                        )
                        .await
                        .is_err()
                        {
                            return;
                        }
                        continue;
                    }
                };
                let outcome = match authorize_request(
                    config.clone(),
                    session_id.map(str::to_owned),
                    sql.to_owned(),
                    Vec::new(),
                )
                .await
                {
                    Some(outcome) => outcome,
                    None => {
                        if write_policy_error(
                            frontend,
                            message.next_sequence(),
                            "QueryKnight authorization is unavailable",
                        )
                        .await
                        .is_err()
                        {
                            return;
                        }
                        continue;
                    }
                };
                let permit = match outcome {
                    AuthorizationOutcome::Permitted(permit) => permit,
                    AuthorizationOutcome::Blocked(_) => {
                        if write_policy_error(
                            frontend,
                            message.next_sequence(),
                            "QueryKnight blocked this query",
                        )
                        .await
                        .is_err()
                        {
                            return;
                        }
                        continue;
                    }
                    AuthorizationOutcome::PendingApproval(pending) => {
                        let text =
                            format!("QueryKnight approval required ({})", pending.approval_id);
                        if write_policy_error(frontend, message.next_sequence(), &text)
                            .await
                            .is_err()
                        {
                            return;
                        }
                        continue;
                    }
                    AuthorizationOutcome::Failed(_) => {
                        if write_policy_error(
                            frontend,
                            message.next_sequence(),
                            "QueryKnight could not authorize this query",
                        )
                        .await
                        .is_err()
                        {
                            return;
                        }
                        continue;
                    }
                };
                if permit.dialect() != qk_sql::SqlDialect::MySql
                    || permit.scope().database != config.database_key
                {
                    if write_policy_error(
                        frontend,
                        message.next_sequence(),
                        "QueryKnight authorization scope mismatch",
                    )
                    .await
                    .is_err()
                    {
                        return;
                    }
                    continue;
                }
                let _ = write_history(&config, session_id, sql).await;
                drop(permit);
                if write_message(backend, message.sequence, &message.payload)
                    .await
                    .is_err()
                {
                    return;
                }
                if relay_response(
                    frontend,
                    backend,
                    message.next_sequence(),
                    backend_state,
                    false,
                )
                .await
                .is_err()
                {
                    return;
                }
            }
            _ => {
                if must_close_command(code) {
                    return;
                }
                if write_policy_error(
                    frontend,
                    message.next_sequence(),
                    "MySQL command is not supported by QueryKnight",
                )
                .await
                .is_err()
                {
                    return;
                }
            }
        }
    }
}

async fn authorize_request(
    config: Arc<ProxyConfig>,
    session_id: Option<String>,
    sql: String,
    params: Vec<qk_core::ExecutionParam>,
) -> Option<AuthorizationOutcome> {
    tokio::task::spawn_blocking(move || {
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
        let approval = ApprovalSetup {
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
            integration: "proxy_mysql".to_owned(),
            environment: config.environment.clone(),
            database: config.database_key.clone(),
            tool: "proxy_query".to_owned(),
            session_id,
        };
        let mut request = AuthorizationRequest::new(sql, params);
        request.require_supported_analysis = true;
        request.reject_operations.push(Operation::Unsupported);
        authorize_guarded(
            &CursorStore::new(),
            &GuardedAuthorizationCall {
                config: &config.db_config,
                connection_key: &config.connection_key,
                auth: &auth,
                approval: Some(&approval),
                policy: &config.policy,
            },
            &request,
            ResolveMode::ResolveApprovals,
        )
    })
    .await
    .ok()
}

async fn write_history(
    config: &ProxyConfig,
    session_id: Option<&str>,
    sql: &str,
) -> Result<(), ()> {
    let (Some(control_plane), Some(session_id)) =
        (config.control_plane.clone(), session_id.map(str::to_owned))
    else {
        return Ok(());
    };
    let connection_key = config.connection_key.clone();
    let sql = sql.to_owned();
    tokio::task::spawn_blocking(move || {
        control_plane.record_query(&session_id, &connection_key, "proxy", &sql)
    })
    .await
    .map_err(|_| ())?
    .map_err(|_| ())
}

async fn write_policy_error(
    frontend: &mut TcpStream,
    sequence: u8,
    message: &str,
) -> Result<(), ProtocolError> {
    let packet = encode_err(sequence, MYSQL_POLICY_ERROR, SQLSTATE_GENERAL, message);
    frontend
        .write_all(&packet)
        .await
        .map_err(|_| ProtocolError::Io)
}

fn is_no_response_command(code: u8) -> bool {
    matches!(
        code,
        COM_QUIT | COM_STMT_SEND_LONG_DATA | COM_STMT_CLOSE | COM_STATISTICS | COM_CONNECT
    )
}

fn is_known_request_response_command(code: u8) -> bool {
    matches!(
        code,
        COM_INIT_DB
            | COM_FIELD_LIST
            | COM_REFRESH
            | COM_SHUTDOWN
            | COM_PROCESS_INFO
            | COM_PROCESS_KILL
            | COM_DEBUG
            | COM_CHANGE_USER
            | COM_STMT_PREPARE
            | COM_STMT_EXECUTE
            | COM_STMT_RESET
            | COM_STMT_FETCH
            | COM_SET_OPTION
            | COM_RESET_CONNECTION
    )
}
fn must_close_command(code: u8) -> bool {
    code == COM_CHANGE_USER
        || is_no_response_command(code)
        || !is_known_request_response_command(code)
}

async fn relay_response(
    frontend: &mut TcpStream,
    backend: &mut TcpStream,
    first_sequence: u8,
    state: &mut BackendState,
    prepared_results: bool,
) -> Result<(), ProtocolError> {
    let mut expected_sequence = first_sequence;
    let supports_more_results = if prepared_results {
        state.capabilities.supports_prepared_multi_results()
    } else {
        state.capabilities.supports_multi_results()
    };
    loop {
        let first = read_response_packet(backend, expected_sequence).await?;
        expected_sequence = first.next_sequence();
        let payload = first.payload.as_slice();
        if payload.first() == Some(&0xfb) {
            // Never expose a LOCAL INFILE request to the client or relay file bytes.
            return Err(ProtocolError::Unsupported);
        }
        write_message(frontend, first.sequence, payload).await?;
        if is_err(payload) {
            return Ok(());
        }
        if is_ok(payload) {
            state.status_flags = server_status_from_ok(payload)?;
            if response_has_more_results(state.status_flags) {
                if !supports_more_results {
                    return Err(ProtocolError::Unsupported);
                }
                continue;
            }
            return Ok(());
        }
        let (column_count, _) = lenenc(payload, 0)?;
        if column_count == 0 || column_count > MAX_COLUMNS {
            return Err(ProtocolError::Malformed);
        }
        let mut field_error = false;
        for _ in 0..column_count {
            let field = read_response_packet(backend, expected_sequence).await?;
            expected_sequence = field.next_sequence();
            field_error = is_err(&field.payload);
            write_message(frontend, field.sequence, &field.payload).await?;
            if field_error {
                break;
            }
        }
        if field_error {
            return Ok(());
        }
        let metadata_end = read_response_packet(backend, expected_sequence).await?;
        expected_sequence = metadata_end.next_sequence();
        if is_err(&metadata_end.payload) {
            write_message(frontend, metadata_end.sequence, &metadata_end.payload).await?;
            return Ok(());
        }
        state.status_flags = server_status_from_eof(&metadata_end.payload)?;
        write_message(frontend, metadata_end.sequence, &metadata_end.payload).await?;
        loop {
            let row = read_response_packet(backend, expected_sequence).await?;
            expected_sequence = row.next_sequence();
            if is_err(&row.payload) {
                write_message(frontend, row.sequence, &row.payload).await?;
                return Ok(());
            }
            if is_eof(&row.payload) {
                state.status_flags = server_status_from_eof(&row.payload)?;
                write_message(frontend, row.sequence, &row.payload).await?;
                if response_has_more_results(state.status_flags) {
                    if !supports_more_results {
                        return Err(ProtocolError::Unsupported);
                    }
                    break;
                }
                return Ok(());
            }
            write_message(frontend, row.sequence, &row.payload).await?;
        }
    }
}

async fn read_response_packet(
    backend: &mut TcpStream,
    sequence: u8,
) -> Result<Message, ProtocolError> {
    read_message(backend, Some(sequence), MAX_LOGICAL_RESPONSE).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_allow_list_has_no_implicit_forwarding() {
        for command in [
            COM_INIT_DB,
            COM_FIELD_LIST,
            COM_REFRESH,
            COM_SHUTDOWN,
            COM_PROCESS_INFO,
            COM_PROCESS_KILL,
            COM_DEBUG,
            COM_CHANGE_USER,
            COM_STMT_PREPARE,
            COM_STMT_EXECUTE,
            COM_STMT_RESET,
            COM_STMT_FETCH,
            COM_SET_OPTION,
            COM_RESET_CONNECTION,
        ] {
            assert!(is_known_request_response_command(command));
            assert!(!is_no_response_command(command));
        }
        for command in [
            COM_STMT_SEND_LONG_DATA,
            COM_STMT_CLOSE,
            COM_STATISTICS,
            COM_CONNECT,
        ] {
            assert!(is_no_response_command(command));
        }
        assert!(!is_known_request_response_command(0xff));
        assert!(must_close_command(COM_CHANGE_USER));
        assert!(must_close_command(0xff));
    }
}
