use std::io::{Cursor, Read};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Identity, Server, ServerTlsConfig};

use crate::auth::{OpenShellAuthenticator, OpenShellJwtConfig, OpenShellRequestLayer};
use crate::proto::supervisor_middleware_server::SupervisorMiddlewareServer;
use crate::OpenShellService;

const MAX_GRPC_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const MAX_TLS_CERT_BYTES: usize = 1024 * 1024;
const MAX_TLS_KEY_BYTES: usize = 64 * 1024;

/// OpenShell transport mode for a network listener.
#[derive(Clone)]
enum TransportMode {
    Authenticated {
        tls_cert_path: PathBuf,
        tls_key_path: PathBuf,
        jwt: OpenShellJwtConfig,
    },
    InsecureLocal,
}

/// Typed network listener configuration.
///
/// Authenticated mode is the only mode that accepts non-loopback addresses.
#[derive(Clone)]
pub struct OpenShellServerConfig {
    listen: SocketAddr,
    mode: TransportMode,
    advertised_host: Option<String>,
}

impl OpenShellServerConfig {
    /// Configure HTTPS and strict OpenShell extension JWT authentication.
    pub fn authenticated(
        listen: SocketAddr,
        tls_cert_path: impl Into<PathBuf>,
        tls_key_path: impl Into<PathBuf>,
        jwt: OpenShellJwtConfig,
    ) -> Self {
        Self {
            listen,
            mode: TransportMode::Authenticated {
                tls_cert_path: tls_cert_path.into(),
                tls_key_path: tls_key_path.into(),
                jwt,
            },
            advertised_host: None,
        }
    }

    /// Configure explicitly unauthenticated loopback-only development mode.
    pub fn insecure_local(listen: SocketAddr) -> Self {
        Self {
            listen,
            mode: TransportMode::InsecureLocal,
            advertised_host: None,
        }
    }

    /// Record the hostname OpenShell will use to verify the service certificate.
    #[must_use]
    pub fn with_advertised_host(mut self, host: impl Into<String>) -> Self {
        self.advertised_host = Some(host.into());
        self
    }

    /// Configured TCP bind address.
    #[must_use]
    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// Whether the configured listener will require TLS and OpenShell JWTs.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        matches!(self.mode, TransportMode::Authenticated { .. })
    }
}

/// Non-secret results from local OpenShell server configuration checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenShellServerDiagnostics {
    /// HTTPS/JWT network mode is configured. No call has been authenticated by this check.
    pub authenticated_mode_configured: bool,
    /// TLS certificate, private key, and key pairing parsed successfully.
    pub tls_certificate_valid: bool,
    /// Configured OpenShell gateway identity, when authenticated mode is selected.
    pub expected_gateway_id: Option<String>,
    /// Exact audience configured independently on the service and gateway.
    pub expected_audience: Option<String>,
    /// Count of trusted Ed25519 signing keys loaded from the bounded local JWKS.
    pub trusted_jwks_keys: usize,
    /// Whether the leaf certificate SAN matches the supplied advertised hostname.
    pub advertised_host_san_matches: Option<bool>,
}

impl std::fmt::Debug for OpenShellServerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("OpenShellServerConfig");
        debug.field("listen", &self.listen);
        debug.field("advertised_host", &self.advertised_host);
        match &self.mode {
            TransportMode::Authenticated { jwt, .. } => {
                debug
                    .field("mode", &"OpenShellAuthenticated")
                    .field("tls_cert_path", &"<configured>")
                    .field("tls_key_path", &"<redacted path>")
                    .field("jwt", jwt);
            }
            TransportMode::InsecureLocal => {
                debug.field("mode", &"OpenShellInsecureLocal");
            }
        }
        debug.finish()
    }
}

/// Listener construction and serving errors. TLS/JWT errors never include key
/// material or bearer credentials.
#[derive(Debug)]
pub enum OpenShellServerError {
    /// Plaintext network mode attempted to bind a non-loopback address.
    NonLoopback,
    /// The service authentication audience and listener trust configuration differ.
    ServiceConfiguration,
    /// Authenticated mode could not load the server certificate or key.
    TlsMaterial,
    /// The TLS stack rejected the certificate, private key, or key pairing.
    TlsConfiguration,
    /// The leaf certificate is expired, not yet valid, or malformed.
    TlsCertificateInvalid,
    /// The leaf certificate SAN does not match the configured OpenShell host.
    TlsSanMismatch,
    /// The listener or Unix socket filesystem operation failed.
    Io(std::io::Error),
    /// The service task failed while serving or shutting down.
    Transport(tonic::transport::Error),
    /// The server task panicked or was canceled.
    Task(tokio::task::JoinError),
    /// The trusted OpenShell key configuration could not be loaded.
    Authentication(crate::OpenShellAuthConfigError),
}

impl std::fmt::Display for OpenShellServerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonLoopback => {
                formatter.write_str("OpenShellInsecureLocal listeners must use a loopback address")
            }
            Self::ServiceConfiguration => formatter
                .write_str("OpenShell service and listener authentication configuration differ"),
            Self::TlsMaterial => {
                formatter.write_str("OpenShell TLS certificate or private key could not be loaded")
            }
            Self::TlsConfiguration => formatter
                .write_str("OpenShell TLS certificate and private key are invalid or do not match"),
            Self::TlsCertificateInvalid => {
                formatter.write_str("OpenShell TLS certificate is not currently valid")
            }
            Self::TlsSanMismatch => formatter
                .write_str("OpenShell TLS certificate SAN does not match the advertised host"),
            Self::Io(_) => formatter.write_str("OpenShell listener I/O failed"),
            Self::Transport(_) => formatter.write_str("OpenShell gRPC transport failed"),
            Self::Task(_) => formatter.write_str("OpenShell server task failed"),
            Self::Authentication(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for OpenShellServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::Task(error) => Some(error),
            Self::Authentication(error) => Some(error),
            Self::NonLoopback
            | Self::ServiceConfiguration
            | Self::TlsMaterial
            | Self::TlsConfiguration
            | Self::TlsSanMismatch
            | Self::TlsCertificateInvalid => None,
        }
    }
}

/// OpenShell gRPC listener constructors.
pub struct OpenShellServer;

impl OpenShellServer {
    /// Validate listener, TLS, audience, and trusted-key configuration without
    /// binding a socket or sending a request.
    pub fn validate_configuration(
        config: &OpenShellServerConfig,
        service: &OpenShellService,
    ) -> Result<OpenShellServerDiagnostics, OpenShellServerError> {
        service
            .validate_server_configuration()
            .map_err(|_| OpenShellServerError::ServiceConfiguration)?;
        match &config.mode {
            TransportMode::Authenticated {
                tls_cert_path,
                tls_key_path,
                jwt,
            } => {
                if service.expected_audience() != Some(jwt.expected_audience()) {
                    return Err(OpenShellServerError::ServiceConfiguration);
                }
                let authenticator = OpenShellAuthenticator::load(jwt)
                    .map_err(OpenShellServerError::Authentication)?;
                let cert = read_tls_file(tls_cert_path, MAX_TLS_CERT_BYTES)?;
                let key = read_tls_file(tls_key_path, MAX_TLS_KEY_BYTES)?;
                let san_match =
                    inspect_server_certificate(&cert, config.advertised_host.as_deref())?;
                if san_match == Some(false) {
                    return Err(OpenShellServerError::TlsSanMismatch);
                }
                let tls = ServerTlsConfig::new().identity(Identity::from_pem(cert, key));
                Server::builder()
                    .tls_config(tls)
                    .map_err(|_| OpenShellServerError::TlsConfiguration)?;
                Ok(OpenShellServerDiagnostics {
                    authenticated_mode_configured: true,
                    tls_certificate_valid: true,
                    expected_gateway_id: Some(jwt.gateway_id().to_owned()),
                    expected_audience: Some(jwt.expected_audience().to_owned()),
                    trusted_jwks_keys: authenticator.trusted_key_count(),
                    advertised_host_san_matches: san_match,
                })
            }
            TransportMode::InsecureLocal => {
                if !config.listen.ip().is_loopback() {
                    return Err(OpenShellServerError::NonLoopback);
                }
                if service.expected_audience().is_some() || config.advertised_host.is_some() {
                    return Err(OpenShellServerError::ServiceConfiguration);
                }
                Ok(OpenShellServerDiagnostics {
                    authenticated_mode_configured: false,
                    tls_certificate_valid: false,
                    expected_gateway_id: None,
                    expected_audience: None,
                    trusted_jwks_keys: 0,
                    advertised_host_san_matches: None,
                })
            }
        }
    }

    /// Bind the configured authenticated HTTPS or insecure-local network mode.
    ///
    /// Authenticated mode verifies every OpenShell RPC before protobuf request
    /// decoding. It may bind a non-loopback address only when both TLS and
    /// extension JWT configuration are valid.
    pub async fn bind(
        config: OpenShellServerConfig,
        service: OpenShellService,
    ) -> Result<OpenShellServerHandle, OpenShellServerError> {
        service
            .validate_server_configuration()
            .map_err(|_| OpenShellServerError::ServiceConfiguration)?;
        let mut builder = Server::builder();
        let authenticator = match &config.mode {
            TransportMode::Authenticated {
                tls_cert_path,
                tls_key_path,
                jwt,
            } => {
                if service.expected_audience() != Some(jwt.expected_audience()) {
                    return Err(OpenShellServerError::ServiceConfiguration);
                }
                let authenticator = std::sync::Arc::new(
                    OpenShellAuthenticator::load(jwt)
                        .map_err(OpenShellServerError::Authentication)?,
                );
                let cert = read_tls_file(tls_cert_path, MAX_TLS_CERT_BYTES)?;
                let key = read_tls_file(tls_key_path, MAX_TLS_KEY_BYTES)?;
                if inspect_server_certificate(&cert, config.advertised_host.as_deref())?
                    == Some(false)
                {
                    return Err(OpenShellServerError::TlsSanMismatch);
                }
                let tls = ServerTlsConfig::new().identity(Identity::from_pem(cert, key));
                builder = builder
                    .tls_config(tls)
                    .map_err(|_| OpenShellServerError::TlsConfiguration)?;
                Some(authenticator)
            }
            TransportMode::InsecureLocal => {
                if !config.listen.ip().is_loopback() {
                    return Err(OpenShellServerError::NonLoopback);
                }
                if service.expected_audience().is_some() || config.advertised_host.is_some() {
                    return Err(OpenShellServerError::ServiceConfiguration);
                }
                eprintln!(
                    "WARNING OpenShellInsecureLocal is DEVELOPMENT / TRUSTED TRANSPORT ONLY; no TLS or caller authentication"
                );
                None
            }
        };
        let listener = TcpListener::bind(config.listen)
            .await
            .map_err(OpenShellServerError::Io)?;
        let local_addr = listener.local_addr().map_err(OpenShellServerError::Io)?;
        let incoming = TcpListenerStream::new(listener);
        let timeout = service.request_timeout();
        let tower_layer = OpenShellRequestLayer::new(authenticator, timeout);
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            builder
                .layer(tower_layer)
                .add_service(
                    SupervisorMiddlewareServer::new(service)
                        .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
                        .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES),
                )
                .serve_with_incoming_shutdown(incoming, async move {
                    let _ = receiver.await;
                })
                .await
        });
        Ok(OpenShellServerHandle {
            local_addr: Some(local_addr),
            shutdown: Some(shutdown),
            task: Some(task),
        })
    }

    /// Explicit plaintext development listener. Non-loopback addresses are
    /// rejected; use [`Self::bind`] with authenticated TLS for network use.
    pub async fn bind_tcp(
        address: SocketAddr,
        service: OpenShellService,
    ) -> Result<OpenShellServerHandle, OpenShellServerError> {
        Self::bind(OpenShellServerConfig::insecure_local(address), service).await
    }

    /// Bind a local Unix-domain listener and restrict its socket node to
    /// owner-only access. Unix sockets are not OpenShell v0.1.2's authenticated
    /// supervisor middleware deployment path.
    #[cfg(unix)]
    pub async fn bind_unix(
        path: impl AsRef<Path>,
        service: OpenShellService,
    ) -> Result<OpenShellServerHandle, OpenShellServerError> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use tokio::net::UnixListener;
        use tokio_stream::wrappers::UnixListenerStream;

        service
            .validate_server_configuration()
            .map_err(|_| OpenShellServerError::ServiceConfiguration)?;
        if service.expected_audience().is_some() {
            return Err(OpenShellServerError::ServiceConfiguration);
        }
        eprintln!(
            "WARNING OpenShell Unix socket mode is unauthenticated local integration; not the v0.1.2 network middleware deployment path"
        );
        let path = path.as_ref().to_path_buf();
        if !path.is_absolute() {
            return Err(OpenShellServerError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unix socket path must be absolute",
            )));
        }
        let listener = UnixListener::bind(&path).map_err(OpenShellServerError::Io)?;
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                drop(listener);
                return Err(OpenShellServerError::Io(error));
            }
        };
        let socket = SocketIdentity {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        if let Err(error) =
            std::fs::set_permissions(&socket.path, std::fs::Permissions::from_mode(0o600))
        {
            drop(listener);
            remove_owned_socket(&socket);
            return Err(OpenShellServerError::Io(error));
        }
        let incoming = UnixListenerStream::new(listener);
        let (shutdown, receiver) = oneshot::channel();
        let timeout = service.request_timeout();
        let task = tokio::spawn(async move {
            let result = Server::builder()
                .layer(OpenShellRequestLayer::new(None, timeout))
                .add_service(
                    SupervisorMiddlewareServer::new(service)
                        .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
                        .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES),
                )
                .serve_with_incoming_shutdown(incoming, async move {
                    let _ = receiver.await;
                })
                .await;
            remove_owned_socket(&socket);
            result
        });
        Ok(OpenShellServerHandle {
            local_addr: None,
            shutdown: Some(shutdown),
            task: Some(task),
        })
    }
}

fn read_tls_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, OpenShellServerError> {
    let file = std::fs::File::open(path).map_err(|_| OpenShellServerError::TlsMaterial)?;
    let mut bytes = Vec::with_capacity(4096);
    file.take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| OpenShellServerError::TlsMaterial)?;
    if bytes.len() > max_bytes {
        return Err(OpenShellServerError::TlsMaterial);
    }
    Ok(bytes)
}

fn inspect_server_certificate(
    certificate_pem: &[u8],
    advertised_host: Option<&str>,
) -> Result<Option<bool>, OpenShellServerError> {
    let certificates = rustls_pemfile::certs(&mut Cursor::new(certificate_pem))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| OpenShellServerError::TlsCertificateInvalid)?;
    let der = certificates
        .first()
        .ok_or(OpenShellServerError::TlsCertificateInvalid)?;
    let (remainder, certificate) = x509_parser::parse_x509_certificate(der.as_ref())
        .map_err(|_| OpenShellServerError::TlsCertificateInvalid)?;
    if !remainder.is_empty() {
        return Err(OpenShellServerError::TlsCertificateInvalid);
    }
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |time| time.as_secs()),
    )
    .unwrap_or(i64::MAX);
    let validity = certificate.validity();
    if now < validity.not_before.timestamp() || now > validity.not_after.timestamp() {
        return Err(OpenShellServerError::TlsCertificateInvalid);
    }
    let Some(host) = advertised_host else {
        return Ok(None);
    };
    if host.is_empty() || host.trim() != host || host.chars().any(char::is_control) {
        return Err(OpenShellServerError::ServiceConfiguration);
    }
    let san = certificate
        .subject_alternative_name()
        .map_err(|_| OpenShellServerError::TlsCertificateInvalid)?
        .map(|extension| extension.value.general_names.as_slice())
        .unwrap_or_default();
    let address = host.parse::<IpAddr>().ok();
    let matches = san.iter().any(|name| match name {
        x509_parser::extensions::GeneralName::DNSName(dns_name) if address.is_none() => {
            dns_name_matches(dns_name, host)
        }
        x509_parser::extensions::GeneralName::IPAddress(bytes) => match (address, bytes.len()) {
            (Some(IpAddr::V4(host)), 4) => host.octets().as_slice() == *bytes,
            (Some(IpAddr::V6(host)), 16) => host.octets().as_slice() == *bytes,
            _ => false,
        },
        _ => false,
    });
    Ok(Some(matches))
}

fn dns_name_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.');
    let host = host.trim_end_matches('.');
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host.split_once('.')
            .is_some_and(|(label, rest)| !label.is_empty() && rest.eq_ignore_ascii_case(suffix))
    } else {
        pattern.eq_ignore_ascii_case(host)
    }
}

#[cfg(unix)]
struct SocketIdentity {
    path: std::path::PathBuf,
    device: u64,
    inode: u64,
}

/// Running local server and its shutdown signal.
pub struct OpenShellServerHandle {
    local_addr: Option<SocketAddr>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), tonic::transport::Error>>>,
}

impl OpenShellServerHandle {
    /// Assigned TCP address, or `None` for a Unix-domain listener.
    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Request graceful shutdown and wait for the gRPC server task.
    pub async fn stop(mut self) -> Result<(), OpenShellServerError> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let result = match self.task.take() {
            Some(task) => task.await.map_err(OpenShellServerError::Task)?,
            None => Ok(()),
        };
        result.map_err(OpenShellServerError::Transport)
    }
}

#[cfg(unix)]
fn remove_owned_socket(socket: &SocketIdentity) {
    use std::os::unix::fs::MetadataExt;
    if let Ok(metadata) = std::fs::symlink_metadata(&socket.path) {
        if metadata.dev() == socket.device && metadata.ino() == socket.inode {
            let _ = std::fs::remove_file(&socket.path);
        }
    }
}

impl Drop for OpenShellServerHandle {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}
