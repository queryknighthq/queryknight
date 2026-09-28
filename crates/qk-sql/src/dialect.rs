//! QueryKnight-owned SQL dialect model. `sqlparser-rs` dialect types never
//! cross the crate boundary.

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use crate::error::SqlAnalysisError;

/// SQL dialects QueryKnight analyzes. Exactly the three shipped engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SqlDialect {
    /// PostgreSQL (`postgres`, `postgresql`).
    PostgreSql,
    /// MySQL and MariaDB (`mysql`, `mariadb`).
    MySql,
    /// SQLite (`sqlite`).
    Sqlite,
}

impl Display for SqlDialect {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::PostgreSql => write!(f, "postgresql"),
            Self::MySql => write!(f, "mysql"),
            Self::Sqlite => write!(f, "sqlite"),
        }
    }
}

impl FromStr for SqlDialect {
    type Err = SqlAnalysisError;

    /// Parse an external dialect name. Case-insensitive; surrounding
    /// whitespace is ignored. Anything else is [`SqlAnalysisError::UnsupportedDialect`].
    ///
    /// Accepted aliases mirror the reference implementation: `postgres` and
    /// `postgresql`; `mysql` and `mariadb`; `sqlite`.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_dialect(input)
    }
}

/// Parse an external dialect name into [`SqlDialect`].
pub fn parse_dialect(input: &str) -> Result<SqlDialect, SqlAnalysisError> {
    match input.trim().to_lowercase().as_str() {
        "postgres" | "postgresql" => Ok(SqlDialect::PostgreSql),
        "mysql" | "mariadb" => Ok(SqlDialect::MySql),
        "sqlite" => Ok(SqlDialect::Sqlite),
        _ => Err(SqlAnalysisError::UnsupportedDialect(input.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_dialect;
    use super::SqlDialect;

    #[test]
    fn aliases() {
        assert_eq!(parse_dialect("postgres"), Ok(SqlDialect::PostgreSql));
        assert_eq!(parse_dialect("PostgreSQL"), Ok(SqlDialect::PostgreSql));
        assert_eq!(parse_dialect("  mysql  "), Ok(SqlDialect::MySql));
        assert_eq!(parse_dialect("MariaDB"), Ok(SqlDialect::MySql));
        assert_eq!(parse_dialect("SQLITE"), Ok(SqlDialect::Sqlite));
        assert!(parse_dialect("mssql").is_err());
        assert!(parse_dialect("").is_err());
        assert!(parse_dialect("generic").is_err());
    }
}
