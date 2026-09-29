//! SQLite user-database adapter (rusqlite). This is execution against
//! USER databases — never the internal `qk-store` state DB: every
//! operation opens its own connection and closes it. Blocking calls
//! run on the blocking pool, never on Tokio workers.

use crate::adapter::{Capabilities, DatabaseAdapter, Param};
use crate::config::{sqlite_path, SecretUrl};
use crate::error::{classify_driver_message, DbError, DbErrorKind};
use crate::result::{
    ColumnInfo, ForeignKeyInfo, IndexInfo, PingResult, RawResult, TableInfo, TableKind, TableRef,
};
use crate::value::DbValue;

const CAPABILITIES: Capabilities = Capabilities {
    schemas: false,
    explain: true,
    explain_writes: false,
    sampling: true,
};

/// User-database SQLite adapter. Stateless across operations (each
/// operation opens and closes its own connection): `:memory:` databases
/// are therefore single-operation scoped by design.
#[derive(Debug, Default, Clone, Copy)]
pub struct SqliteAdapter;

fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Frozen read-statement detection
/// (`/^\s*(select|explain|with|pragma|values|show|desc)\b/i`).
fn is_read(sql: &str) -> bool {
    [
        "select", "explain", "with", "pragma", "values", "show", "desc",
    ]
    .iter()
    .any(|keyword| crate::adapter::starts_with_word(sql, keyword))
}

fn to_sqlite_value(param: &Param) -> Result<rusqlite::types::Value, DbError> {
    use rusqlite::types::Value;
    match param {
        Param::Null => Ok(Value::Null),
        Param::Bool(value) => Ok(Value::Integer(i64::from(*value))),
        Param::Int(value) => Ok(Value::Integer(*value)),
        // rusqlite has no uint: out-of-range magnitudes are an error
        // rather than a silent wrap (fail closed on conversion).
        Param::UInt(value) => i64::try_from(*value)
            .map(Value::Integer)
            .map_err(|_| DbError::new(DbErrorKind::Query, "integer parameter out of range")),
        Param::Float(value) => Ok(Value::Real(*value)),
        Param::Text(text) => Ok(Value::Text(text.clone())),
        Param::Bytes(bytes) => Ok(Value::Blob(bytes.clone())),
    }
}

fn to_db_value(value: rusqlite::types::Value) -> DbValue {
    use rusqlite::types::Value;
    match value {
        Value::Null => DbValue::Null,
        Value::Integer(value) => DbValue::Int(value),
        Value::Real(value) => DbValue::Float(value),
        Value::Text(text) => DbValue::Text(text),
        Value::Blob(bytes) => DbValue::Bytes(bytes),
    }
}

/// Already-EXPLAIN detection (`/^\s*explain\b/i`, frozen).
fn starts_with_explain(sql: &str) -> bool {
    crate::adapter::starts_with_word(sql, "explain")
}

fn db_error(error: rusqlite::Error) -> DbError {
    let message = short_rusqlite_message(&error);
    DbError::new(classify_driver_message(&message), message)
}

/// rusqlite `Debug` can include SQL text; keep only the short variant
/// name plus embedded message (bounded by `DbError` regardless).
fn short_rusqlite_message(error: &rusqlite::Error) -> String {
    match error {
        rusqlite::Error::SqliteFailure(code, detail) => {
            format!(
                "sqlite failure {}: {}",
                code.code as i32,
                detail.as_deref().unwrap_or("")
            )
        }
        other => format!("{other:?}"),
    }
}

impl SqliteAdapter {
    fn open(url: &SecretUrl) -> Result<rusqlite::Connection, DbError> {
        let path = sqlite_path(url.expose());
        if path == ":memory:" {
            rusqlite::Connection::open_in_memory()
        } else {
            rusqlite::Connection::open(&path)
        }
        .map_err(db_error)
    }

    async fn blocking<F, T>(operation: F) -> Result<T, DbError>
    where
        F: FnOnce() -> Result<T, DbError> + Send + 'static,
        T: Send + 'static,
    {
        tokio::task::spawn_blocking(operation)
            .await
            .map_err(|_| DbError::new(DbErrorKind::Internal, "database task failed"))?
    }
}

#[async_trait::async_trait]
impl DatabaseAdapter for SqliteAdapter {
    fn engine(&self) -> &'static str {
        "sqlite"
    }

    fn capabilities(&self) -> Capabilities {
        CAPABILITIES
    }

    async fn test_connection(&self, url: &SecretUrl) -> Result<PingResult, DbError> {
        let url = url.clone();
        let started = std::time::Instant::now();
        Self::blocking(move || {
            let conn = Self::open(&url)?;
            conn.execute_batch("SELECT 1").map_err(db_error)?;
            Ok(())
        })
        .await?;
        Ok(PingResult {
            ok: true,
            latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            server_version: Some(format!("rusqlite/{}", rusqlite::version())),
        })
    }

    async fn execute(
        &self,
        url: &SecretUrl,
        sql: &str,
        params: &[Param],
    ) -> Result<RawResult, DbError> {
        let sql = sql.to_owned();
        let params: Vec<rusqlite::types::Value> = params
            .iter()
            .map(to_sqlite_value)
            .collect::<Result<_, _>>()?;
        let url = url.clone();
        Self::blocking(move || {
            let conn = Self::open(&url)?;
            // Defense in depth (the service rejects multi-statement
            // first): rusqlite prepares the first statement only, so a
            // batch reaching here executes partially — refuse instead.
            if crate::budget::is_multi_statement(&sql) {
                return Err(DbError::new(
                    DbErrorKind::Query,
                    "multiple statements are not allowed",
                ));
            }
            if is_read(&sql) {
                let mut statement = conn.prepare(&sql).map_err(db_error)?;
                let columns: Vec<String> = statement
                    .column_names()
                    .iter()
                    .map(|name| name.to_string())
                    .collect();
                // Positional duplicates preserved (documented vs the
                // reference driver objects).
                let mut rows = Vec::new();
                let mut cursor = statement
                    .query(rusqlite::params_from_iter(params))
                    .map_err(db_error)?;
                while let Some(row) = cursor.next().map_err(db_error)? {
                    let mut values = Vec::with_capacity(columns.len());
                    for index in 0..columns.len() {
                        values.push(to_db_value(
                            row.get::<_, rusqlite::types::Value>(index)
                                .map_err(db_error)?,
                        ));
                    }
                    rows.push(values);
                }
                Ok(RawResult {
                    columns,
                    rows,
                    rows_affected: None,
                })
            } else {
                let changed = conn
                    .execute(&sql, rusqlite::params_from_iter(params))
                    .map_err(db_error)?;
                Ok(RawResult {
                    columns: Vec::new(),
                    rows: Vec::new(),
                    rows_affected: Some(changed as u64),
                })
            }
        })
        .await
    }

    async fn explain(
        &self,
        url: &SecretUrl,
        sql: &str,
        params: &[Param],
    ) -> Result<String, DbError> {
        let planned = if starts_with_explain(sql) {
            sql.to_owned()
        } else {
            format!("EXPLAIN QUERY PLAN {sql}")
        };
        let result = self.execute(url, &planned, params).await?;
        // Frozen shape: `detail` lines joined with `\n`.
        let detail = result
            .columns
            .iter()
            .position(|name| name == "detail")
            .unwrap_or(0);
        Ok(result
            .rows
            .iter()
            .map(|row| match row.get(detail) {
                Some(DbValue::Text(text)) => text.clone(),
                Some(DbValue::Int(value)) => value.to_string(),
                _ => String::new(),
            })
            .collect::<Vec<_>>()
            .join("\n"))
    }

    async fn list_schemas(&self, _url: &SecretUrl) -> Result<Vec<String>, DbError> {
        Ok(vec!["main".to_owned()])
    }

    async fn list_tables(
        &self,
        url: &SecretUrl,
        _schema: Option<&str>,
    ) -> Result<Vec<TableRef>, DbError> {
        let result = self
            .execute(
                url,
                "SELECT name, type FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY name",
                &[],
            )
            .await?;
        Ok(result
            .rows
            .iter()
            .map(|row| {
                let name = match row.first() {
                    Some(DbValue::Text(text)) => text.clone(),
                    _ => String::new(),
                };
                let kind = match row.get(1) {
                    Some(DbValue::Text(text)) if text == "view" => TableKind::View,
                    _ => TableKind::Table,
                };
                TableRef {
                    schema: Some("main".to_owned()),
                    name,
                    kind,
                }
            })
            .collect())
    }

    async fn describe_table(
        &self,
        url: &SecretUrl,
        _schema: Option<&str>,
        name: &str,
    ) -> Result<TableInfo, DbError> {
        let table = quote_ident(name);
        let url = url.clone();
        let name = name.to_owned();
        Self::blocking(move || {
            let conn = Self::open(&url)?;
            let mut columns = Vec::new();
            let mut primary_key_ordered: Vec<(i64, String)> = Vec::new();
            {
                let mut statement = conn
                    .prepare(&format!("PRAGMA table_info({table})"))
                    .map_err(db_error)?;
                let mut cursor = statement.query([]).map_err(db_error)?;
                while let Some(row) = cursor.next().map_err(db_error)? {
                    let col_name: String = row.get("name").map_err(db_error)?;
                    let col_type: String = row
                        .get::<_, Option<String>>("type")
                        .map_err(db_error)?
                        .unwrap_or_default();
                    let notnull: i64 = row.get("notnull").map_err(db_error)?;
                    let default: Option<String> = row.get("dflt_value").map_err(db_error)?;
                    let pk: i64 = row.get("pk").map_err(db_error)?;
                    if pk > 0 {
                        primary_key_ordered.push((pk, col_name.clone()));
                    }
                    columns.push(ColumnInfo {
                        name: col_name,
                        data_type: col_type,
                        nullable: notnull == 0,
                        default,
                    });
                }
            }
            if columns.is_empty() {
                return Err(DbError::new(
                    DbErrorKind::Query,
                    format!("table not found: {name}"),
                ));
            }
            primary_key_ordered.sort_by_key(|(order, _)| *order);
            let primary_key = primary_key_ordered
                .into_iter()
                .map(|(_, name)| name)
                .collect();
            // User indexes (internal sqlite_autoindex_* backends skipped).
            let mut indexes = Vec::new();
            {
                let mut statement = conn
                    .prepare(&format!("PRAGMA index_list({table})"))
                    .map_err(db_error)?;
                let mut cursor = statement.query([]).map_err(db_error)?;
                while let Some(row) = cursor.next().map_err(db_error)? {
                    let index_name: String = row.get("name").map_err(db_error)?;
                    if index_name.starts_with("sqlite_autoindex") {
                        continue;
                    }
                    let unique: i64 = row.get("unique").map_err(db_error)?;
                    let mut cols = Vec::new();
                    {
                        let mut info = conn
                            .prepare(&format!("PRAGMA index_info({})", quote_ident(&index_name)))
                            .map_err(db_error)?;
                        let mut info_cursor = info.query([]).map_err(db_error)?;
                        while let Some(info_row) = info_cursor.next().map_err(db_error)? {
                            cols.push(info_row.get::<_, String>("name").map_err(db_error)?);
                        }
                    }
                    indexes.push(IndexInfo {
                        name: index_name,
                        columns: cols,
                        unique: unique == 1,
                    });
                }
            }
            // Foreign keys grouped by id (synthesized `fk_<table>_<id>` names).
            let mut foreign_keys = Vec::new();
            {
                let mut statement = conn
                    .prepare(&format!("PRAGMA foreign_key_list({table})"))
                    .map_err(db_error)?;
                let mut cursor = statement.query([]).map_err(db_error)?;
                let mut grouped: Vec<(i64, String, Vec<String>, Vec<String>)> = Vec::new();
                while let Some(row) = cursor.next().map_err(db_error)? {
                    let id: i64 = row.get("id").map_err(db_error)?;
                    let ref_table: String = row.get("table").map_err(db_error)?;
                    let from: String = row.get("from").map_err(db_error)?;
                    let to: String = row.get("to").map_err(db_error)?;
                    match grouped.iter_mut().find(|(gid, _, _, _)| *gid == id) {
                        Some((_, _, cols, refs)) => {
                            cols.push(from);
                            refs.push(to);
                        }
                        None => grouped.push((id, ref_table, vec![from], vec![to])),
                    }
                }
                for (id, ref_table, cols, refs) in grouped {
                    foreign_keys.push(ForeignKeyInfo {
                        name: format!("fk_{ref_table}_{id}"),
                        columns: cols,
                        referenced_schema: None,
                        referenced_table: ref_table,
                        referenced_columns: refs,
                    });
                }
            }
            Ok(TableInfo {
                schema: Some("main".to_owned()),
                name,
                kind: TableKind::Table,
                columns,
                primary_key,
                indexes,
                foreign_keys,
            })
        })
        .await
    }

    async fn dump_schema(
        &self,
        url: &SecretUrl,
        _schema: Option<&str>,
        name: &str,
    ) -> Result<String, DbError> {
        let result = self
            .execute(
                url,
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1 LIMIT 1",
                &[Param::Text(name.to_owned())],
            )
            .await?;
        match result.rows.first().and_then(|row| row.first()) {
            Some(DbValue::Text(ddl)) if !ddl.is_empty() => Ok(if ddl.ends_with(';') {
                ddl.clone()
            } else {
                format!("{ddl};")
            }),
            _ => Err(DbError::new(
                DbErrorKind::Query,
                format!("table not found: {name}"),
            )),
        }
    }

    fn sample_sql(&self, _schema: Option<&str>, name: &str, limit: usize) -> String {
        let n = limit.max(1);
        format!(
            "SELECT * FROM {} ORDER BY RANDOM() LIMIT {n}",
            quote_ident(name)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_detection_matches_reference() {
        for sql in [
            "SELECT 1",
            "  select a",
            "EXPLAIN SELECT 1",
            "WITH x AS (SELECT 1) SELECT * FROM x",
            "PRAGMA table_info(t)",
            "VALUES (1)",
            "SHOW TABLES",
            "DESC t",
            "SELECT",
        ] {
            assert!(is_read(sql), "{sql}");
        }
        for sql in [
            "UPDATE t SET a = 1",
            "DELETE FROM t",
            "INSERT INTO t VALUES (1)",
            "SELECTED 1",
        ] {
            assert!(!is_read(sql), "{sql}");
        }
    }
}
