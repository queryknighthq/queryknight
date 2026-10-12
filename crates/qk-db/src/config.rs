//! Typed connection configuration. Credentials live in URL strings
//! supplied from trusted configuration (environment, CLI); they are
//! wrapped in [`SecretUrl`] (redacted `Debug`/`Display`) and never
//! appear in errors, logs, or outcomes.

use std::fmt::{self, Debug, Display, Formatter};
use std::path::PathBuf;

use crate::error::{DbError, DbErrorKind};
use crate::tls::PostgresTransport;

/// Operator-selected PostgreSQL TLS trust configuration.
///
/// `ca_path` names a PEM CA bundle that becomes the *only* trust anchor
/// for a verified-TLS connection. `None` uses the platform native store.
/// The path is trusted configuration, never agent input, and its contents
/// are never logged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PostgresTlsOptions {
    /// PEM CA bundle path, or `None` for the platform native store.
    pub ca_path: Option<PathBuf>,
}

/// A database URL whose credentials are redacted on every surface.
/// `Display`/`Debug` render `password → ***` (frozen `redact()`
/// behavior); the raw text is available only to adapter internals via
/// [`SecretUrl::expose`].
#[derive(Clone, PartialEq, Eq)]
pub struct SecretUrl {
    raw: String,
    // Cached from the drivers' typed URL parsers so authorization can
    // reject unsupported modes without reparsing or inspecting URL text.
    mysql_url_options: MysqlUrlOptions,
    postgres_transport: PostgresSslState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MysqlUrlOptions {
    OtherEngine,
    Plaintext,
    Tls,
    Invalid,
}

/// Resolved PostgreSQL transport state for one trusted URL.
///
/// The variant is derived from the URL's `sslmode` plus the operator's
/// [`PostgresTlsOptions`]; agents never select it.
#[derive(Clone, PartialEq, Eq)]
enum PostgresSslState {
    /// `sslmode=disable`: explicit plaintext.
    Plaintext,
    /// `sslmode=require`: TLS that must verify.
    TlsVerified { ca_path: Option<PathBuf> },
    /// `sslmode=prefer` (or any non-verifying mode): rejected. QueryKnight
    /// never downgrades to plaintext.
    DowngradeRejected,
    /// The URL is not a parseable PostgreSQL configuration.
    Invalid,
}

impl SecretUrl {
    /// Wrap a URL. Empty strings are rejected (fail fast on missing
    /// configuration, not on first connect).
    pub fn new(url: impl Into<String>) -> Result<Self, DbError> {
        Self::new_with_tls(url, PostgresTlsOptions::default())
    }

    /// Wrap a URL with operator TLS trust configuration.
    pub fn new_with_tls(url: impl Into<String>, tls: PostgresTlsOptions) -> Result<Self, DbError> {
        let url = url.into();
        if url.trim().is_empty() {
            return Err(DbError::new(DbErrorKind::Connection, "empty database URL"));
        }
        let mysql_url_options = if is_other_engine_url(&url) {
            MysqlUrlOptions::OtherEngine
        } else {
            match mysql_async::Opts::from_url(&url) {
                Ok(opts) if opts.ssl_opts().is_some() => MysqlUrlOptions::Tls,
                Ok(_) => MysqlUrlOptions::Plaintext,
                Err(_) => MysqlUrlOptions::Invalid,
            }
        };
        let postgres_transport = if is_postgres_config_form(&url) {
            match url.parse::<tokio_postgres::Config>() {
                Ok(config) => match config.get_ssl_mode() {
                    tokio_postgres::config::SslMode::Disable => PostgresSslState::Plaintext,
                    tokio_postgres::config::SslMode::Require => PostgresSslState::TlsVerified {
                        ca_path: tls.ca_path,
                    },
                    // `prefer` (and any future non-verifying mode) is never
                    // accepted: QueryKnight has no plaintext downgrade.
                    tokio_postgres::config::SslMode::Prefer => PostgresSslState::DowngradeRejected,
                    _ => PostgresSslState::DowngradeRejected,
                },
                Err(_) => PostgresSslState::Invalid,
            }
        } else {
            PostgresSslState::Invalid
        };
        Ok(Self {
            raw: url,
            mysql_url_options,
            postgres_transport,
        })
    }

    /// Raw URL for driver use only. Callers must never log, format
    /// into errors, or serialize the result.
    pub fn expose(&self) -> &str {
        &self.raw
    }

    /// Password-redacted form (`//user:***@host/...`).
    pub fn redacted(&self) -> String {
        redact_password(&self.raw)
    }

    /// Resolve the PostgreSQL transport mode for this URL.
    pub fn postgres_transport(&self) -> Result<PostgresTransport, DbError> {
        match &self.postgres_transport {
            PostgresSslState::Plaintext => Ok(PostgresTransport::Plaintext),
            PostgresSslState::TlsVerified { ca_path } => Ok(PostgresTransport::TlsVerified {
                ca_path: ca_path.clone(),
            }),
            PostgresSslState::DowngradeRejected => Err(unsupported_postgres_tls()),
            PostgresSslState::Invalid => Err(invalid_postgres_url()),
        }
    }

    fn validate_mysql_options(&self) -> Result<(), DbError> {
        match self.mysql_url_options {
            MysqlUrlOptions::Tls => Err(unsupported_mysql_tls()),
            MysqlUrlOptions::Invalid | MysqlUrlOptions::OtherEngine => Err(DbError::new(
                DbErrorKind::Connection,
                "invalid MySQL database URL",
            )),
            MysqlUrlOptions::Plaintext => Ok(()),
        }
    }

    fn validate_postgres_options(&self) -> Result<(), DbError> {
        self.postgres_transport().map(|_| ())
    }
}

fn is_other_engine_url(url: &str) -> bool {
    let url = url.trim_start();
    ["sqlite:", "postgres:", "postgresql:"]
        .iter()
        .any(|scheme| {
            url.get(..scheme.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(scheme))
        })
}

fn is_postgres_config_form(url: &str) -> bool {
    let url = url.trim_start();
    ["postgres:", "postgresql:"].iter().any(|scheme| {
        url.get(..scheme.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(scheme))
    }) || (!url.contains("://") && !is_other_engine_url(url))
}

fn unsupported_mysql_tls() -> DbError {
    DbError::new(
        DbErrorKind::Unsupported,
        "MySQL TLS is not supported by this QueryKnight build",
    )
}

fn unsupported_postgres_tls() -> DbError {
    DbError::new(
        DbErrorKind::Unsupported,
        "PostgreSQL sslmode=prefer/allow is not supported; use sslmode=disable for explicitly trusted plaintext or sslmode=require for verified TLS",
    )
}

fn invalid_postgres_url() -> DbError {
    DbError::new(DbErrorKind::Connection, "invalid PostgreSQL database URL")
}

/// Parse a trusted PostgreSQL URL and resolve its transport mode.
///
/// Returns the parsed driver config plus the transport the adapter must
/// use. `sslmode=prefer`/`allow` and malformed URLs fail here, before any
/// network activity.
pub(crate) fn parse_postgres_config(
    url: &SecretUrl,
) -> Result<(tokio_postgres::Config, PostgresTransport), DbError> {
    let config = url
        .expose()
        .parse::<tokio_postgres::Config>()
        .map_err(|_| invalid_postgres_url())?;
    let transport = url.postgres_transport()?;
    Ok((config, transport))
}

pub(crate) fn parse_mysql_opts(url: &SecretUrl) -> Result<mysql_async::Opts, DbError> {
    let opts = mysql_async::Opts::from_url(url.expose()).map_err(|error| {
        DbError::new(
            DbErrorKind::Connection,
            format!("invalid database URL: {error}"),
        )
    })?;
    if opts.ssl_opts().is_some() {
        return Err(unsupported_mysql_tls());
    }
    Ok(opts)
}

/// Strip a `user:password@` userinfo password, mirroring the frozen
/// `redact()` helper. Non-URL strings pass through without a password
/// shape untouched.
fn redact_password(url: &str) -> String {
    // Match `//user:password@` (first `@` terminates userinfo).
    let Some(scheme_end) = url.find("://") else {
        return url.to_owned();
    };
    let after_scheme = &url[scheme_end + 3..];
    let Some(at) = after_scheme.find('@') else {
        return url.to_owned();
    };
    let userinfo = &after_scheme[..at];
    let Some(colon) = userinfo.find(':') else {
        return url.to_owned();
    };
    format!(
        "{}://{}:***@{}",
        &url[..scheme_end],
        &userinfo[..colon],
        &after_scheme[at + 1..]
    )
}

impl Debug for SecretUrl {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "SecretUrl({})", self.redacted())
    }
}

impl Display for SecretUrl {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.redacted())
    }
}

/// Trusted connection configuration. The variant determines the SQL
/// dialect used for evaluation (INV-036); agents never select it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbConfig {
    /// `postgres://` or `postgresql://`.
    Postgres(SecretUrl),
    /// `mysql://`, `mariadb://`, or anything unrecognized (frozen
    /// `createAdapter` default: unknown schemes are MySQL).
    Mysql(SecretUrl),
    /// `sqlite:` path or `:memory:`.
    Sqlite(SecretUrl),
}

impl DbConfig {
    /// Parse a connection URL with the frozen selection rule: `sqlite:`
    /// → sqlite, `postgres(ql):` → postgres, anything else → mysql.
    /// Matching is ASCII case-insensitive on the scheme.
    pub fn from_url(url: &str) -> Result<Self, DbError> {
        Self::from_url_with_tls(url, PostgresTlsOptions::default())
    }

    /// Parse a connection URL with operator TLS trust configuration.
    ///
    /// `tls.ca_path` supplies the PostgreSQL CA bundle; it applies only to
    /// `postgres(ql):` URLs. Selection rule matches [`DbConfig::from_url`].
    pub fn from_url_with_tls(url: &str, tls: PostgresTlsOptions) -> Result<Self, DbError> {
        let secret = SecretUrl::new_with_tls(url, tls)?;
        let lower = url.trim_start().to_ascii_lowercase();
        if lower.starts_with("sqlite:") {
            Ok(Self::Sqlite(secret))
        } else if lower.starts_with("postgres:") || lower.starts_with("postgresql:") {
            Ok(Self::Postgres(secret))
        } else {
            Ok(Self::Mysql(secret))
        }
    }

    /// Reject connection modes unsupported by the selected adapter.
    /// This check is cheap after `SecretUrl` construction and runs before
    /// authorization can create or consume an approval.
    pub fn validate_supported_transport(&self) -> Result<(), DbError> {
        match self {
            Self::Mysql(url) => url.validate_mysql_options(),
            Self::Postgres(url) => url.validate_postgres_options(),
            Self::Sqlite(_) => Ok(()),
        }
    }

    pub(crate) fn validate_mysql_transport(&self) -> Result<(), DbError> {
        match self {
            Self::Mysql(url) => url.validate_mysql_options(),
            Self::Postgres(_) | Self::Sqlite(_) => Ok(()),
        }
    }

    /// Resolve the PostgreSQL transport mode for a `postgres(ql):` URL.
    ///
    /// Fails for non-PostgreSQL configurations.
    pub fn postgres_transport(&self) -> Result<PostgresTransport, DbError> {
        match self {
            Self::Postgres(url) => url.postgres_transport(),
            Self::Mysql(_) | Self::Sqlite(_) => Err(DbError::new(
                DbErrorKind::Connection,
                "configured database URL is not PostgreSQL",
            )),
        }
    }

    /// The SQL dialect evaluation must use for this connection.
    pub fn dialect(&self) -> qk_sql::SqlDialect {
        match self {
            Self::Postgres(_) => qk_sql::SqlDialect::PostgreSql,
            Self::Mysql(_) => qk_sql::SqlDialect::MySql,
            Self::Sqlite(_) => qk_sql::SqlDialect::Sqlite,
        }
    }

    /// The redacted URL (safe for diagnostics).
    pub fn redacted_url(&self) -> String {
        match self {
            Self::Postgres(url) | Self::Mysql(url) | Self::Sqlite(url) => url.redacted(),
        }
    }
}

/// Resolve a `sqlite:` URL to a filesystem path or `:memory:`
/// (frozen `pathFromUrl` semantics).
pub fn sqlite_path(url: &str) -> String {
    // Strip the scheme case-insensitively without touching the path.
    let stripped = strip_scheme_prefix(url, "sqlite:");
    if stripped.is_empty() || stripped == ":memory:" {
        return ":memory:".to_owned();
    }
    stripped.to_owned()
}

fn strip_scheme_prefix<'a>(url: &'a str, scheme: &str) -> &'a str {
    let trimmed = url.trim_start();
    if trimmed.len() >= scheme.len() && trimmed[..scheme.len()].eq_ignore_ascii_case(scheme) {
        // Also accept `sqlite://` (strip one optional `//` pair).
        let rest = &trimmed[scheme.len()..];
        rest.strip_prefix("//").unwrap_or(rest)
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_matches_reference_default() {
        assert!(matches!(
            DbConfig::from_url("sqlite:/tmp/x.db").expect("sqlite"),
            DbConfig::Sqlite(_)
        ));
        assert!(matches!(
            DbConfig::from_url("SQLITE::memory:").expect("sqlite upper"),
            DbConfig::Sqlite(_)
        ));
        assert!(matches!(
            DbConfig::from_url("postgres://u@h/db").expect("pg"),
            DbConfig::Postgres(_)
        ));
        assert!(matches!(
            DbConfig::from_url("postgresql://u@h/db").expect("pgql"),
            DbConfig::Postgres(_)
        ));
        // Frozen default: anything else is MySQL.
        assert!(matches!(
            DbConfig::from_url("mysql://u@h/db").expect("mysql"),
            DbConfig::Mysql(_)
        ));
        assert!(matches!(
            DbConfig::from_url("mariadb://u@h/db").expect("maria"),
            DbConfig::Mysql(_)
        ));
        assert!(matches!(
            DbConfig::from_url("weird://u@h/db").expect("weird"),
            DbConfig::Mysql(_)
        ));
        assert!(DbConfig::from_url("   ").is_err());
    }

    #[test]
    fn dialects_come_from_connection() {
        assert_eq!(
            DbConfig::from_url("postgres://u@h/db")
                .expect("u")
                .dialect(),
            qk_sql::SqlDialect::PostgreSql
        );
        assert_eq!(
            DbConfig::from_url("mysql://u@h/db").expect("u").dialect(),
            qk_sql::SqlDialect::MySql
        );
        assert_eq!(
            DbConfig::from_url("sqlite::memory:").expect("u").dialect(),
            qk_sql::SqlDialect::Sqlite
        );
    }
    #[test]
    fn mysql_tls_validation_uses_driver_options_and_duplicate_order() {
        let tls_urls = [
            "mysql://u:p@localhost/db?require_ssl=true",
            "mysql://u:p@localhost/db?require_ssl=true&verify_ca=false",
            "mysql://u:p@localhost/db?require_ssl=true&verify_identity=false",
            "mysql://u:p@localhost/db?require_ssl=true&built_in_roots=false",
            "mysql://u:p@localhost/db?require_ssl=true&verify_ca=false&verify_identity=false&built_in_roots=false",
            "mysql://u:p@localhost/db?require_ssl=false&require_ssl=true",
        ];
        for url in tls_urls {
            let config = DbConfig::from_url(url).expect("URL config");
            let error = config
                .validate_supported_transport()
                .expect_err("TLS must be rejected");
            assert_eq!(error.kind(), &DbErrorKind::Unsupported, "{url}");
        }

        let plaintext_urls = [
            "mysql://u:p@localhost/db",
            "mysql://u:p@localhost/db?require_ssl=false",
            "mysql://u:p@localhost/db?require_ssl=true&require_ssl=false",
            "mysql://u:p@localhost/db?require_ssl=false&verify_ca=false&verify_identity=false&built_in_roots=false",
            "mysql://u:p@localhost/db?verify_ca=true&verify_identity=true&built_in_roots=true",
        ];
        for url in plaintext_urls {
            DbConfig::from_url(url)
                .expect("URL config")
                .validate_supported_transport()
                .expect("plaintext TLS options are not enabled");
        }
    }

    #[test]
    fn mysql_tls_error_is_static_and_redacted() {
        let url = "mysql://qk:MYSQL_TLS_SECRET_12345@localhost/db?require_ssl=true";
        let config = DbConfig::from_url(url).expect("URL config");
        let error = config
            .validate_supported_transport()
            .expect_err("TLS must be rejected");
        assert_eq!(error.kind(), &DbErrorKind::Unsupported);
        assert!(error.message().contains("MySQL TLS is not supported"));
        assert!(!error.to_string().contains("MYSQL_TLS_SECRET_12345"));
        assert!(!format!("{error:?}").contains("MYSQL_TLS_SECRET_12345"));
        assert!(!format!("{config:?}").contains("MYSQL_TLS_SECRET_12345"));
    }

    #[test]
    fn postgres_ssl_modes_use_tokio_postgres_config_semantics() {
        // Non-verifying modes are rejected; there is no plaintext downgrade.
        let downgrade_urls = [
            "postgres://u:p@localhost/db",
            "postgresql://u:p@localhost/db",
            "postgres://u:p@localhost/db?sslmode=prefer",
            "postgres://u:p@localhost/db?sslmode=require&sslmode=prefer",
        ];
        for url in downgrade_urls {
            let error = DbConfig::from_url(url)
                .expect("URL config")
                .validate_supported_transport()
                .expect_err("non-verifying modes must fail closed");
            assert_eq!(error.kind(), &DbErrorKind::Unsupported, "{url}");
        }
        for connection_string in [
            "host=localhost dbname=db",
            "host=localhost dbname=db sslmode=prefer",
        ] {
            let config = DbConfig::Postgres(SecretUrl::new(connection_string).expect("config"));
            let error = config
                .validate_supported_transport()
                .expect_err("keyword config must use tokio-postgres defaults");
            assert_eq!(error.kind(), &DbErrorKind::Unsupported);
        }

        let plaintext_urls = [
            "postgres://u:p@localhost/db?sslmode=disable",
            "postgresql://u:p@localhost/db?sslmode=disable",
            "postgres://u:p@localhost/db?sslmode=require&sslmode=disable",
            "postgres://u:p@localhost/db?sslmode=disable&sslnegotiation=direct",
            "host=localhost dbname=db sslmode=disable",
        ];
        for url in plaintext_urls {
            let config = DbConfig::Postgres(SecretUrl::new(url).expect("URL"));
            config
                .validate_supported_transport()
                .expect("explicit disable is supported");
            assert!(
                !config.postgres_transport().expect("transport").is_tls(),
                "{url} must stay plaintext"
            );
        }

        // Verified TLS is now supported via sslmode=require.
        for url in [
            "postgres://u:p@localhost/db?sslmode=require",
            "postgres://u:p@localhost/db?sslmode=disable&sslmode=require",
            "host=localhost dbname=db sslmode=require",
        ] {
            let config = DbConfig::Postgres(SecretUrl::new(url).expect("URL"));
            config
                .validate_supported_transport()
                .expect("verified TLS is supported");
            assert!(config.postgres_transport().expect("transport").is_tls());
        }

        for url in [
            "postgres://u:p@localhost/db?sslmode=verify-ca",
            "postgres://u:p@localhost/db?sslmode=verify-full",
            "postgres://u:p@localhost/db?sslmode=allow",
        ] {
            let error = DbConfig::from_url(url)
                .expect("URL config")
                .validate_supported_transport()
                .expect_err("tokio-postgres rejects this sslmode");
            assert_eq!(error.kind(), &DbErrorKind::Connection, "{url}");
        }
    }

    #[test]
    fn postgres_tls_error_is_typed_and_redacted() {
        let config =
            DbConfig::from_url("postgres://user:PG_TLS_SECRET_12345@localhost/db?sslmode=prefer")
                .expect("URL config");
        let error = config
            .validate_supported_transport()
            .expect_err("non-verifying mode is unsupported");
        assert_eq!(error.kind(), &DbErrorKind::Unsupported);
        assert!(error.message().contains("sslmode=disable"));
        assert!(!error.to_string().contains("PG_TLS_SECRET_12345"));
        assert!(!format!("{error:?}").contains("PG_TLS_SECRET_12345"));
        assert!(!format!("{config:?}").contains("PG_TLS_SECRET_12345"));
    }

    #[test]
    fn credentials_redacted_everywhere() {
        let url = SecretUrl::new("mysql://qk:s3cret@127.0.0.1:3307/queryknight").expect("url");
        assert_eq!(url.redacted(), "mysql://qk:***@127.0.0.1:3307/queryknight");
        assert!(!format!("{url:?}").contains("s3cret"));
        assert!(!format!("{url}").contains("s3cret"));
        assert_eq!(url.expose(), "mysql://qk:s3cret@127.0.0.1:3307/queryknight");
        // No-password URLs pass through.
        assert_eq!(
            SecretUrl::new("sqlite:/tmp/x.db").expect("u").redacted(),
            "sqlite:/tmp/x.db"
        );
    }

    #[test]
    fn sqlite_paths() {
        assert_eq!(sqlite_path("sqlite:/tmp/x.db"), "/tmp/x.db");
        assert_eq!(sqlite_path("sqlite:///tmp/x.db"), "/tmp/x.db");
        assert_eq!(sqlite_path("sqlite::memory:"), ":memory:");
        assert_eq!(sqlite_path("sqlite:"), ":memory:");
    }
}
