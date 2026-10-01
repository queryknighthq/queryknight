//! MCP startup configuration: one bound connection, trusted context
//! derivation, and daemon discovery. Tool arguments never influence
//! anything here (INV-037).

use qk_db::DbConfig;

use crate::error::{protocol_error, ErrorKind};

/// Frozen environment names; anything else is `unknown`.
pub fn environment_from_env() -> String {
    match std::env::var("QUERYKNIGHT_ENV").as_deref() {
        Ok("production" | "staging" | "development") => {
            std::env::var("QUERYKNIGHT_ENV").expect("checked")
        }
        _ => "unknown".to_owned(),
    }
}

/// Database key for policy scope (`QUERYKNIGHT_DATABASE` override or
/// the password-stripped connection key, frozen `databaseKeyFor`).
pub fn database_key_for(connection_key: &str) -> String {
    match std::env::var("QUERYKNIGHT_DATABASE") {
        Ok(key) if !key.trim().is_empty() => key,
        _ => connection_key.to_owned(),
    }
}

/// Password-stripped connection key (frozen `connectionKeyFromUrl`):
/// `protocol//user@host/path` (no password, no query). Falls back to
/// a regex-equivalent strip when the URL does not parse.
pub fn connection_key_from_url(url: &str) -> String {
    // Scheme-relative parse without a URL crate: split userinfo.
    if let Some(scheme_end) = url.find("://") {
        let scheme = &url[..scheme_end];
        let rest = &url[scheme_end + 3..];
        // Authority ends at the first /, ?, or #.
        let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, remainder) = rest.split_at(auth_end);
        // Strip password from userinfo (keep the username).
        let clean_authority = match authority.rfind('@') {
            Some(at) => {
                let userinfo = &authority[..at];
                let host = &authority[at + 1..];
                match userinfo.find(':') {
                    Some(colon) => format!("{}@{}", &userinfo[..colon], host),
                    None => authority.to_owned(),
                }
            }
            None => authority.to_owned(),
        };
        // Keep the path, drop query/fragment (frozen shape keeps path).
        let path = remainder.split(['?', '#']).next().unwrap_or("");
        return format!("{scheme}://{clean_authority}{path}");
    }
    // Non-URL fallback: strip `//user:password@` like the reference.
    strip_userinfo_fallback(url)
}

fn strip_userinfo_fallback(url: &str) -> String {
    let bytes = url.as_bytes();
    if let Some(slash) = find_double_slash(bytes) {
        if let Some(at) = url[slash + 2..].find('@') {
            let at = slash + 2 + at;
            let userinfo = &url[slash + 2..at];
            if let Some(colon) = userinfo.find(':') {
                return format!(
                    "{}//{}@{}",
                    &url[..slash],
                    &userinfo[..colon],
                    &url[at + 1..]
                );
            }
        }
    }
    url.to_owned()
}

fn find_double_slash(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|w| w == b"//")
}

/// Trusted MCP connection: typed config, stripped key, policy keys.
/// Built once at startup from the bound URL + trusted environment.
#[derive(Debug, Clone)]
pub struct McpConnection {
    /// Typed connection (owns credentials opaquely; dialect source).
    pub config: DbConfig,
    /// Password-stripped key (cursor binding, history, policy).
    pub connection_key: String,
    /// Policy database scope.
    pub database_key: String,
    /// Policy environment scope.
    pub environment: String,
}

impl McpConnection {
    /// Resolve the bound connection URL into trusted configuration.
    /// Raw URLs come from startup configuration only, never from tool
    /// arguments.
    pub fn from_url(url: &str) -> Result<Self, rmcp::ErrorData> {
        let config = DbConfig::from_url(url).map_err(|error| {
            protocol_error(ErrorKind::Internal(format!(
                "invalid database URL: {error}"
            )))
        })?;
        config.validate_supported_transport().map_err(|error| {
            protocol_error(ErrorKind::Internal(format!(
                "invalid database URL: {error}"
            )))
        })?;
        let connection_key = connection_key_from_url(url);
        Ok(Self {
            database_key: database_key_for(&connection_key),
            environment: environment_from_env(),
            config,
            connection_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_stripping_matches_reference() {
        assert_eq!(
            connection_key_from_url("mysql://qk:s3cret@127.0.0.1:3307/queryknight"),
            "mysql://qk@127.0.0.1:3307/queryknight"
        );
        assert_eq!(
            connection_key_from_url("postgres://u:p@h:5432/db?sslmode=require"),
            "postgres://u@h:5432/db"
        );
        assert_eq!(
            connection_key_from_url("sqlite:/tmp/x.db"),
            "sqlite:/tmp/x.db"
        );
        // Fallback shape mirrors the reference regex path.
        assert_eq!(
            connection_key_from_url("weird//u:p@host/db"),
            "weird//u@host/db"
        );
    }

    #[test]
    fn trusted_derivation() {
        let conn = McpConnection::from_url("mysql://qk:pw@127.0.0.1:3307/qk").expect("conn");
        assert_eq!(conn.connection_key, "mysql://qk@127.0.0.1:3307/qk");
        assert_eq!(conn.config.dialect(), qk_sql::SqlDialect::MySql);
        assert!(!format!("{conn:?}").contains("pw"));
    }

    #[test]
    fn unsupported_mysql_tls_returns_redacted_mcp_protocol_error() {
        let error = McpConnection::from_url(
            "mysql://qk:MYSQL_TLS_SECRET_12345@localhost/db?require_ssl=true",
        )
        .expect_err("unsupported TLS must fail while binding configuration");
        let rendered = format!("{error:?}");
        assert!(rendered.contains("MySQL TLS is not supported"));
        assert!(!rendered.contains("MYSQL_TLS_SECRET_12345"));
    }
}
