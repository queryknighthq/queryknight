use std::fmt::{self, Debug, Display, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;

use mysql_async::Opts;
use qk_control_plane::ControlPlaneClient;
use qk_core::PolicyFile;
use qk_db::DbConfig;

/// Configuration failures deliberately avoid embedding the URL or credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyConfigError {
    /// The trusted backend URL is malformed or not a MySQL URL.
    InvalidBackend,
    /// Backend TLS, compression, local socket, or startup commands are unsupported.
    UnsupportedBackendMode,
    /// The trusted MySQL username or database is missing.
    MissingBackendIdentity,
    /// The configured database variant is not MySQL.
    NotMysql,
}

impl Display for ProxyConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidBackend => "invalid MySQL backend configuration",
            Self::UnsupportedBackendMode => "unsupported MySQL backend mode",
            Self::MissingBackendIdentity => "MySQL backend username and database are required",
            Self::NotMysql => "backend URL does not select MySQL",
        })
    }
}

impl std::error::Error for ProxyConfigError {}

#[derive(Clone)]
pub(crate) struct BackendConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub database: String,
}

impl BackendConfig {
    fn from_db_config(config: &DbConfig) -> Result<Self, ProxyConfigError> {
        let DbConfig::Mysql(url) = config else {
            return Err(ProxyConfigError::NotMysql);
        };
        let options = Opts::from_url(url.expose()).map_err(|_| ProxyConfigError::InvalidBackend)?;
        if options.ssl_opts().is_some()
            || options.socket().is_some()
            || options.compression().is_some()
            || options.enable_cleartext_plugin()
            || !options.init().is_empty()
            || !options.setup().is_empty()
        {
            return Err(ProxyConfigError::UnsupportedBackendMode);
        }
        let user = options
            .user()
            .filter(|user| !user.is_empty())
            .ok_or(ProxyConfigError::MissingBackendIdentity)?;
        let database = options
            .db_name()
            .filter(|database| !database.is_empty())
            .ok_or(ProxyConfigError::MissingBackendIdentity)?;
        Ok(Self {
            host: options.ip_or_hostname().to_owned(),
            port: options.tcp_port(),
            user: user.to_owned(),
            database: database.to_owned(),
        })
    }
}

/// Immutable, trusted configuration for one loopback MySQL listener.
/// Each frontend receives its own backend socket and approval session.
#[derive(Clone)]
pub struct ProxyConfig {
    pub(crate) listen: SocketAddr,
    pub(crate) backend: BackendConfig,
    pub(crate) db_config: DbConfig,
    pub(crate) connection_key: String,
    pub(crate) environment: String,
    pub(crate) database_key: String,
    pub(crate) policy: Arc<PolicyFile>,
    pub(crate) control_plane: Option<ControlPlaneClient>,
}

impl ProxyConfig {
    /// Build a loopback MySQL proxy using trusted startup configuration.
    /// The listener host is deliberately fixed to IPv4 loopback.
    pub fn new(
        listen_port: u16,
        db_config: DbConfig,
        connection_key: String,
        environment: String,
        database_key: String,
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
            database_key,
            policy: Arc::new(policy),
            control_plane,
        })
    }

    /// Configured loopback listener address.
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen
    }

    /// Secret-free backend label safe for startup diagnostics.
    pub fn backend_label(&self) -> &'static str {
        "configured MySQL backend"
    }
}

impl Debug for ProxyConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("listen", &self.listen)
            .field("backend", &"configured MySQL backend")
            .field("environment", &self.environment)
            .field("database", &self.database_key)
            .field("control_plane", &self.control_plane)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qk_db::SecretUrl;

    fn mysql(url: &str) -> DbConfig {
        DbConfig::Mysql(SecretUrl::new(url).expect("secret URL"))
    }

    fn policy() -> PolicyFile {
        qk_core::parse_policy(
            "version: 1\ndefaults:\n  decision: deny\n  on_parse_error: deny\n  on_unknown: deny\nenvironments: {}\n",
        )
        .expect("policy")
    }

    fn config(url: &str) -> Result<ProxyConfig, ProxyConfigError> {
        ProxyConfig::new(
            3308,
            mysql(url),
            "mysql://qk@127.0.0.1/qk".to_owned(),
            "development".to_owned(),
            "main".to_owned(),
            policy(),
            None,
        )
    }

    #[test]
    fn binds_only_loopback_and_redacts_credentials() {
        let config =
            config("mysql://qk:MYSQL_BACKEND_SECRET_12345@localhost:3310/qk").expect("config");
        assert_eq!(
            config.listen_addr(),
            SocketAddr::from(([127, 0, 0, 1], 3308))
        );
        assert!(!format!("{config:?}").contains("MYSQL_BACKEND_SECRET_12345"));
        let secret = SecretUrl::new("mysql://qk:MYSQL_BACKEND_SECRET_12345@localhost:3310/qk")
            .expect("secret URL");
        assert!(!format!("{secret:?}").contains("MYSQL_BACKEND_SECRET_12345"));
        assert!(!secret.to_string().contains("MYSQL_BACKEND_SECRET_12345"));
        assert_eq!(config.backend.host, "localhost");
        assert_eq!(config.backend.port, 3310);
        assert_eq!(config.backend.user, "qk");
        assert_eq!(config.backend.database, "qk");
    }

    #[test]
    fn rejects_tls_compression_sockets_and_missing_database() {
        let error = config("mysql://qk:MYSQL_BACKEND_SECRET_12345@localhost/qk?require_ssl=true")
            .expect_err("TLS must be refused");
        assert!(!error.to_string().contains("MYSQL_BACKEND_SECRET_12345"));
        assert!(!format!("{error:?}").contains("MYSQL_BACKEND_SECRET_12345"));
        assert!(matches!(
            config("mysql://qk:secret@localhost/qk?require_ssl=true"),
            Err(ProxyConfigError::UnsupportedBackendMode)
        ));
        assert!(matches!(
            config("mysql://qk:secret@localhost/qk?compression=fast"),
            Err(ProxyConfigError::UnsupportedBackendMode)
        ));
        assert!(matches!(
            config("mysql://qk:secret@localhost/qk?socket=%2Ftmp%2Fmysql.sock"),
            Err(ProxyConfigError::UnsupportedBackendMode)
        ));
        assert!(matches!(
            config("mysql://qk:secret@localhost/"),
            Err(ProxyConfigError::MissingBackendIdentity)
        ));
    }
}
