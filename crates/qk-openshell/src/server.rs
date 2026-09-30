use std::net::SocketAddr;
use std::path::Path;

use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use crate::proto::supervisor_middleware_server::SupervisorMiddlewareServer;
use crate::OpenShellService;

/// Listener construction errors. Non-loopback TCP is refused because this
/// adapter does not implement OpenShell's remote HTTPS/JWT authentication.
#[derive(Debug)]
pub enum OpenShellServerError {
    /// TCP address is not loopback.
    NonLoopback,
    /// Listener or Unix socket filesystem operation failed.
    Io(std::io::Error),
    /// Tonic transport failed while serving or shutting down.
    Transport(tonic::transport::Error),
    /// The server task panicked or was canceled.
    Task(tokio::task::JoinError),
}

impl std::fmt::Display for OpenShellServerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonLoopback => formatter.write_str("OpenShell TCP listeners must use loopback"),
            Self::Io(_) => formatter.write_str("OpenShell listener I/O failed"),
            Self::Transport(_) => formatter.write_str("OpenShell gRPC transport failed"),
            Self::Task(_) => formatter.write_str("OpenShell server task failed"),
        }
    }
}

impl std::error::Error for OpenShellServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::Task(error) => Some(error),
            Self::NonLoopback => None,
        }
    }
}

/// Local listener constructors for the generated OpenShell service.
pub struct OpenShellServer;

impl OpenShellServer {
    /// Bind a loopback-only TCP listener. Port zero is supported; inspect
    /// [`OpenShellServerHandle::local_addr`] for the assigned port.
    pub async fn bind_tcp(
        address: SocketAddr,
        service: OpenShellService,
    ) -> Result<OpenShellServerHandle, OpenShellServerError> {
        if !address.ip().is_loopback() {
            return Err(OpenShellServerError::NonLoopback);
        }
        let listener = TcpListener::bind(address)
            .await
            .map_err(OpenShellServerError::Io)?;
        let local_addr = listener.local_addr().map_err(OpenShellServerError::Io)?;
        let incoming = TcpListenerStream::new(listener);
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            Server::builder()
                .add_service(
                    SupervisorMiddlewareServer::new(service)
                        .max_decoding_message_size(4 * 1024 * 1024),
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

    /// Bind a Unix-domain listener and restrict its socket node to owner-only
    /// access. The parent directory must already exist and be trusted.
    #[cfg(unix)]
    pub async fn bind_unix(
        path: impl AsRef<Path>,
        service: OpenShellService,
    ) -> Result<OpenShellServerHandle, OpenShellServerError> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use tokio::net::UnixListener;
        use tokio_stream::wrappers::UnixListenerStream;

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
        let task = tokio::spawn(async move {
            let result = Server::builder()
                .add_service(
                    SupervisorMiddlewareServer::new(service)
                        .max_decoding_message_size(4 * 1024 * 1024),
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
