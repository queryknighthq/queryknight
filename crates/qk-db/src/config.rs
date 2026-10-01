//! Typed connection configuration. Credentials live in URL strings
//! supplied from trusted configuration (environment, CLI); they are
//! wrapped in [`SecretUrl`] (redacted `Debug`/`Display`) and never
//! appear in errors, logs, or outcomes.

use std::fmt::{self, Debug, Display, Formatter};

use crate::error::{DbError, DbErrorKind};

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
    postgres_ssl_mode: PostgresSslMode,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MysqlUrlOptions {
    OtherEngine,
    Plaintext,
    Tls,
    Invalid,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PostgresSslMode {
    Parsed(tokio_postgres::config::SslMode),
    Invalid,
}

impl SecretUrl {
    /// Wrap a URL. Empty strings are rejected (fail fast on missing
    /// configuration, not on first connect).
    pub fn new(url: impl Into<String>) -> Result<Self, DbError> {
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
        let postgres_ssl_mode = if is_postgres_config_form(&url) {
            match url.parse::<tokio_postgres::Config>() {
                Ok(config) => PostgresSslMode::Parsed(config.get_ssl_mode()),
                Err(_) => PostgresSslMode::Invalid,
            }
        } else {
            PostgresSslMode::Invalid
        };
        Ok(Self {
            raw: url,
            mysql_url_options,
            postgres_ssl_mode,
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
        match self.postgres_ssl_mode {
            PostgresSslMode::Parsed(tokio_postgres::config::SslMode::Disable) => Ok(()),
            PostgresSslMode::Parsed(_) => Err(unsupported_postgres_tls()),
            PostgresSslMode::Invalid => Err(invalid_postgres_url()),
        }
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
        "PostgreSQL TLS is not supported by this QueryKnight build; use sslmode=disable only for explicitly trusted plaintext connections",
    )
}

fn invalid_postgres_url() -> DbError {
    DbError::new(DbErrorKind::Connection, "invalid PostgreSQL database URL")
}

pub(crate) fn parse_postgres_config(url: &SecretUrl) -> Result<tokio_postgres::Config, DbError> {
    let config = url
        .expose()
        .parse::<tokio_postgres::Config>()
        .map_err(|_| invalid_postgres_url())?;
    if config.get_ssl_mode() != tokio_postgres::config::SslMode::Disable {
        return Err(unsupported_postgres_tls());
    }
    Ok(config)
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
        let secret = SecretUrl::new(url)?;
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
        let unsupported_urls = [
            "postgres://u:p@localhost/db",
            "postgresql://u:p@localhost/db",
            "postgres://u:p@localhost/db?sslmode=prefer",
            "postgres://u:p@localhost/db?sslmode=require",
            "postgres://u:p@localhost/db?sslmode=disable&sslmode=require",
        ];
        for url in unsupported_urls {
            let error = DbConfig::from_url(url)
                .expect("URL config")
                .validate_supported_transport()
                .expect_err("TLS modes must fail closed");
            assert_eq!(error.kind(), &DbErrorKind::Unsupported, "{url}");
        }
        for connection_string in [
            "host=localhost dbname=db",
            "host=localhost dbname=db sslmode=prefer",
            "host=localhost dbname=db sslmode=require",
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
            DbConfig::from_url("postgres://user:PG_TLS_SECRET_12345@localhost/db?sslmode=require")
                .expect("URL config");
        let error = config
            .validate_supported_transport()
            .expect_err("TLS is unsupported");
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
