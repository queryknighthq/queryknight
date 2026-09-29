use std::fmt::{self, Debug, Display, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;

use qk_control_plane::ControlPlaneClient;
use qk_core::PolicyFile;
use qk_db::{DbConfig, SecretUrl};
use tokio_postgres::config::{Host, SslMode};

/// Bounded proxy configuration error. No backend URL, username/password,
/// policy SQL, or control-plane token is included in its display surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyConfigError {
    /// Backend URL is not a valid PostgreSQL URL.
    InvalidBackend,
    /// URL selects a non-PostgreSQL database.
    NotPostgres,
    /// Backend URL does not identify exactly one TCP host.
    UnsupportedBackendTarget,
    /// Backend URL requests TLS, unsupported by this plaintext wire transport.
    BackendTlsUnsupported,
    /// Backend role or database identity is absent.
    MissingBackendIdentity,
    /// Backend URL includes trusted startup options which this proxy refuses.
    BackendOptionsUnsupported,
}

impl Display for ProxyConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidBackend => "invalid PostgreSQL backend configuration",
            Self::NotPostgres => "the PostgreSQL proxy requires a PostgreSQL backend URL",
            Self::UnsupportedBackendTarget => "PostgreSQL proxy supports one TCP backend host only",
            Self::BackendTlsUnsupported => {
                "PostgreSQL backend TLS is requested but unsupported by this proxy"
            }
            Self::MissingBackendIdentity => {
                "PostgreSQL backend configuration must identify a user and database"
            }
            Self::BackendOptionsUnsupported => {
                "PostgreSQL backend startup options are unsupported by this proxy"
            }
        })
    }
}

impl std::error::Error for ProxyConfigError {}

/// One trusted PostgreSQL backend address and startup identity.
#[derive(Clone)]
pub(crate) struct BackendConfig {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) user: String,
    pub(crate) database: String,
}

impl BackendConfig {
    fn from_db_config(config: &DbConfig) -> Result<Self, ProxyConfigError> {
        let url = match config {
            DbConfig::Postgres(url) => url,
            DbConfig::Mysql(_) | DbConfig::Sqlite(_) => return Err(ProxyConfigError::NotPostgres),
        };
        Self::from_url(url)
    }

    fn from_url(url: &SecretUrl) -> Result<Self, ProxyConfigError> {
        let parsed: tokio_postgres::Config = url
            .expose()
            .parse()
            .map_err(|_| ProxyConfigError::InvalidBackend)?;
        if parsed.get_ssl_mode() != SslMode::Disable {
            return Err(ProxyConfigError::BackendTlsUnsupported);
        }
        if parsed
            .get_options()
            .is_some_and(|options| !options.is_empty())
        {
            return Err(ProxyConfigError::BackendOptionsUnsupported);
        }
        let [Host::Tcp(host)] = parsed.get_hosts() else {
            return Err(ProxyConfigError::UnsupportedBackendTarget);
        };
        let user = parsed
            .get_user()
            .filter(|user| !user.is_empty())
            .ok_or(ProxyConfigError::MissingBackendIdentity)?
            .to_owned();
        let database = parsed
            .get_dbname()
            .filter(|database| !database.is_empty())
            .unwrap_or(&user)
            .to_owned();
        if parsed.get_ports().len() > 1 {
            return Err(ProxyConfigError::UnsupportedBackendTarget);
        }
        Ok(Self {
            host: host.clone(),
            port: parsed.get_ports().first().copied().unwrap_or(5432),
            user,
            database,
        })
    }
}

/// One listener's immutable trusted policy/backend context. Every accepted
/// frontend receives a distinct backend session and approval session id.
#[derive(Clone)]
pub struct ProxyConfig {
    pub(crate) listen: SocketAddr,
    pub(crate) backend: BackendConfig,
    pub(crate) db_config: DbConfig,
    pub(crate) connection_key: String,
    pub(crate) environment: String,
    pub(crate) database: String,
    pub(crate) policy: Arc<PolicyFile>,
    pub(crate) control_plane: Option<ControlPlaneClient>,
}

impl ProxyConfig {
    /// Build a loopback PostgreSQL listener using trusted connection and
    /// policy configuration. The only listener option exposed here is a port;
    /// callers cannot accidentally select a remote bind address.
    pub fn new(
        listen_port: u16,
        db_config: DbConfig,
        connection_key: String,
        environment: String,
        database: String,
        policy: PolicyFile,
        control_plane: Option<ControlPlaneClient>,
    ) -> Result<Self, ProxyConfigError> {
        let backend = BackendConfig::from_db_config(&db_config)?;
        Ok(Self {
            listen: SocketAddr::from(([127, 0, 0, 1], listen_port)),
            backend,
            db_config,
            connection_key,
            environment,
            database,
            policy: Arc::new(policy),
            control_plane,
        })
    }

    /// Trusted listener target, always loopback.
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen
    }

    /// Secret-free backend label safe for diagnostics.
    pub fn backend_label(&self) -> &'static str {
        "configured PostgreSQL backend"
    }
}

impl Debug for ProxyConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("listen", &self.listen)
            .field("backend", &"configured PostgreSQL backend")
            .field("environment", &self.environment)
            .field("database", &self.database)
            .field("control_plane", &self.control_plane)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_tls_modes_are_never_silently_downgraded() {
        for mode in ["prefer", "require"] {
            let url =
                format!("postgres://qk:backend-secret@127.0.0.1:5432/queryknight?sslmode={mode}");
            let config = DbConfig::from_url(&url).expect("PostgreSQL URL");
            assert!(
                matches!(
                    BackendConfig::from_db_config(&config),
                    Err(ProxyConfigError::BackendTlsUnsupported)
                ),
                "sslmode={mode}"
            );
        }
        for mode in ["verify-ca", "verify-full"] {
            let url =
                format!("postgres://qk:backend-secret@127.0.0.1:5432/queryknight?sslmode={mode}");
            let config = DbConfig::from_url(&url).expect("PostgreSQL URL");
            assert!(
                matches!(
                    BackendConfig::from_db_config(&config),
                    Err(ProxyConfigError::InvalidBackend)
                ),
                "sslmode={mode}"
            );
        }
        let config = DbConfig::from_url(
            "postgres://qk:backend-secret@127.0.0.1:5432/queryknight?sslmode=disable",
        )
        .expect("PostgreSQL URL");
        assert!(BackendConfig::from_db_config(&config).is_ok());
    }
}
