//! MySQL/MariaDB adapter (mysql_async, plaintext local connections).
//! Per-operation connections (connect → operate → disconnect); no pool,
//! multi-statements never enabled. Value decoding preserves DECIMAL
//! text precision and distinguishes binary blobs from text.

use mysql_async::consts::ColumnType;
use mysql_async::prelude::*;
use mysql_async::{Column, Conn, Params};

use crate::adapter::{looks_like_read, Capabilities, DatabaseAdapter, Param};
use crate::config::{parse_mysql_opts, SecretUrl};
use crate::error::{classify_driver_message, DbError, DbErrorKind};
use crate::result::{
    ColumnInfo, ForeignKeyInfo, ImpactEstimate, IndexInfo, PingResult, RawResult, TableInfo,
    TableKind, TableRef,
};
use crate::value::{json_value, DbValue};

const CAPABILITIES: Capabilities = Capabilities {
    schemas: true,
    explain: true,
    explain_writes: true,
    sampling: true,
};

/// MySQL/MariaDB adapter. Stateless across operations.
#[derive(Debug, Default, Clone, Copy)]
pub struct MysqlAdapter;

fn driver_error(error: mysql_async::Error) -> DbError {
    let message = error.to_string();
    DbError::new(classify_driver_message(&message), message)
}

fn connect_error(error: mysql_async::Error) -> DbError {
    let message = error.to_string();
    let kind = match classify_driver_message(&message) {
        DbErrorKind::Authentication => DbErrorKind::Authentication,
        _ => DbErrorKind::Connection,
    };
    DbError::new(kind, message)
}

async fn connect(url: &SecretUrl) -> Result<Conn, DbError> {
    let opts = parse_mysql_opts(url)?;
    // Defense in depth: the service rejects multi-statement batches
    // first, and every operation below uses the binary prepared-statement
    // protocol (`exec_iter`), which the server refuses for multi
    // statements — batches can never partially execute.
    Conn::new(opts).await.map_err(connect_error)
}

fn to_mysql_value(param: &Param) -> mysql_async::Value {
    use mysql_async::Value;
    match param {
        Param::Null => Value::NULL,
        Param::Bool(value) => Value::Int(i64::from(*value)),
        Param::Int(value) => Value::Int(*value),
        Param::UInt(value) => Value::UInt(*value),
        Param::Float(value) => Value::Double(*value),
        Param::Text(text) => Value::Bytes(text.as_bytes().to_vec()),
        Param::Bytes(bytes) => Value::Bytes(bytes.clone()),
    }
}

/// True for explicit binary column types (never character data, even
/// when the bytes happen to be valid UTF-8). Deliberately NOT the
/// binary charset flag: binary-collation `VARCHAR`s (including
/// `information_schema` text) are still character data and stay text
/// when valid UTF-8 (reference parity); `VARBINARY` with non-UTF-8
/// bytes still falls back to bytes via the text attempt below.
fn is_binary_column(column: &Column) -> bool {
    use ColumnType::*;
    matches!(
        column.column_type(),
        MYSQL_TYPE_BLOB
            | MYSQL_TYPE_TINY_BLOB
            | MYSQL_TYPE_MEDIUM_BLOB
            | MYSQL_TYPE_LONG_BLOB
            | MYSQL_TYPE_BIT
            | MYSQL_TYPE_VECTOR
    )
}

fn convert_value(value: mysql_async::Value, column: &Column) -> DbValue {
    let column_type = column.column_type();
    if is_binary_column(column) && !matches!(column_type, ColumnType::MYSQL_TYPE_JSON) {
        // Binary is binary even when the bytes happen to be valid
        // UTF-8 (a `UNHEX('0001')` blob must not become text).
        return match value {
            mysql_async::Value::NULL => DbValue::Null,
            mysql_async::Value::Bytes(bytes) => DbValue::Bytes(bytes),
            mysql_async::Value::Int(value) => DbValue::Int(value),
            mysql_async::Value::UInt(value) => DbValue::UInt(value),
            mysql_async::Value::Float(value) => DbValue::Float(f64::from(value)),
            mysql_async::Value::Double(value) => DbValue::Float(value),
            // Temporal values never arrive binary-flagged; fall through
            // to the typed arms below if they ever do.
            other => convert_typed(other, column_type),
        };
    }
    convert_typed(value, column_type)
}

fn convert_typed(value: mysql_async::Value, column_type: ColumnType) -> DbValue {
    use mysql_async::Value;
    match value {
        Value::NULL => DbValue::Null,
        Value::Int(value) => DbValue::Int(value),
        Value::UInt(value) => DbValue::UInt(value),
        Value::Float(value) => DbValue::Float(f64::from(value)),
        Value::Double(value) => DbValue::Float(value),
        Value::Date(year, month, day, hour, minute, second, micros) => DbValue::DateTime(
            format_datetime(year, month, day, hour, minute, second, micros),
        ),
        Value::Time(negative, days, hour, minute, second, micros) => {
            let hours = u64::from(days) * 24 + u64::from(hour);
            let sign = if negative { "-" } else { "" };
            let frac = if micros == 0 {
                String::new()
            } else {
                format!(".{}", format!("{micros:06}").trim_end_matches('0'))
            };
            DbValue::DateTime(format!("{sign}{hours:02}:{minute:02}:{second:02}{frac}"))
        }
        Value::Bytes(bytes) => convert_bytes(&bytes, column_type),
    }
}

fn format_datetime(
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    micros: u32,
) -> String {
    let base = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}");
    if micros == 0 {
        base
    } else {
        format!("{base}.{}", format!("{micros:06}").trim_end_matches('0'))
    }
}

fn convert_bytes(bytes: &[u8], column_type: ColumnType) -> DbValue {
    use ColumnType::*;
    let text = std::str::from_utf8(bytes);
    match column_type {
        MYSQL_TYPE_DECIMAL | MYSQL_TYPE_NEWDECIMAL => match text {
            Ok(text) => DbValue::Decimal(text.to_owned()),
            Err(_) => DbValue::Bytes(bytes.to_vec()),
        },
        MYSQL_TYPE_JSON => match text {
            Ok(text) => json_value(text),
            Err(_) => DbValue::Bytes(bytes.to_vec()),
        },
        _ => match text {
            // Binary blobs that happen to be valid UTF-8 stay text
            // (frozen driver behavior surfaces strings); anything else
            // keeps an explicit binary encoding.
            Ok(text) => DbValue::Text(text.to_owned()),
            Err(_) => DbValue::Bytes(bytes.to_vec()),
        },
    }
}

fn quote_mysql(identifier: &str) -> String {
    format!("`{}`", identifier.replace('`', "``"))
}

impl MysqlAdapter {
    async fn run<F, T>(&self, url: &SecretUrl, operation: F) -> Result<T, DbError>
    where
        F: FnOnce(
            Conn,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(Conn, T), DbError>> + Send>,
        >,
    {
        let conn = connect(url).await?;
        let (conn, result) = operation(conn).await?;
        conn.disconnect().await.map_err(driver_error)?;
        Ok(result)
    }
}

#[async_trait::async_trait]
impl DatabaseAdapter for MysqlAdapter {
    fn engine(&self) -> &'static str {
        "mysql"
    }

    fn capabilities(&self) -> Capabilities {
        CAPABILITIES
    }

    async fn test_connection(&self, url: &SecretUrl) -> Result<PingResult, DbError> {
        let started = std::time::Instant::now();
        let version: Option<String> = self
            .run(url, |mut conn| {
                Box::pin(async move {
                    let version: Option<String> = conn
                        .query_first("SELECT VERSION() AS version")
                        .await
                        .map_err(driver_error)?;
                    Ok((conn, version))
                })
            })
            .await?;
        Ok(PingResult {
            ok: true,
            latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            server_version: version.filter(|version| !version.is_empty()),
        })
    }

    async fn execute(
        &self,
        url: &SecretUrl,
        sql: &str,
        params: &[Param],
    ) -> Result<RawResult, DbError> {
        let sql = sql.to_owned();
        let params: Vec<mysql_async::Value> = params.iter().map(to_mysql_value).collect();
        let read = looks_like_read(&sql);
        self.run(url, |mut conn| {
            Box::pin(async move {
                let driver_params = if params.is_empty() {
                    Params::Empty
                } else {
                    Params::Positional(params)
                };
                if read {
                    let mut result = conn
                        .exec_iter(sql, driver_params)
                        .await
                        .map_err(driver_error)?;
                    // Owned snapshot first: `columns()` borrows the
                    // stream, `next()` needs it mutably.
                    let columns: Vec<Column> = result
                        .columns()
                        .map(|columns| columns.iter().cloned().collect())
                        .unwrap_or_default();
                    let names: Vec<String> = columns
                        .iter()
                        .map(|col| col.name_str().into_owned())
                        .collect();
                    let mut rows = Vec::new();
                    while let Some(row) = result.next().await.map_err(driver_error)? {
                        let values = row.unwrap();
                        rows.push(
                            values
                                .into_iter()
                                .enumerate()
                                .map(|(index, value)| match columns.get(index) {
                                    Some(col) => convert_value(value, col),
                                    None => convert_typed(value, ColumnType::MYSQL_TYPE_VAR_STRING),
                                })
                                .collect(),
                        );
                    }
                    drop(result);
                    Ok((
                        conn,
                        RawResult {
                            columns: names,
                            rows,
                            rows_affected: None,
                        },
                    ))
                } else {
                    let result = conn
                        .exec_iter(sql, driver_params)
                        .await
                        .map_err(driver_error)?;
                    let affected = result.affected_rows();
                    drop(result);
                    Ok((
                        conn,
                        RawResult {
                            columns: Vec::new(),
                            rows: Vec::new(),
                            rows_affected: Some(affected),
                        },
                    ))
                }
            })
        })
        .await
    }

    async fn explain(
        &self,
        url: &SecretUrl,
        sql: &str,
        params: &[Param],
    ) -> Result<String, DbError> {
        let planned = if crate::adapter::starts_with_word(sql, "explain") {
            sql.to_owned()
        } else {
            format!("EXPLAIN {sql}")
        };
        let result = self.execute(url, &planned, params).await?;
        // Frozen shape: header tab-joined, then tab-joined rows.
        let header = result.columns.join("\t");
        let mut lines = vec![header];
        for row in &result.rows {
            lines.push(
                row.iter()
                    .map(|value| match value {
                        DbValue::Null => "null".to_owned(),
                        DbValue::Text(text) => text.clone(),
                        DbValue::Bool(value) => value.to_string(),
                        DbValue::Int(value) => value.to_string(),
                        DbValue::UInt(value) => value.to_string(),
                        DbValue::Float(value) => value.to_string(),
                        DbValue::Decimal(text)
                        | DbValue::DateTime(text)
                        | DbValue::JsonText(text) => text.clone(),
                        DbValue::Bytes(bytes) => {
                            use base64::Engine as _;
                            base64::engine::general_purpose::STANDARD.encode(bytes)
                        }
                        DbValue::Json(value) => serde_json::to_string(value).unwrap_or_default(),
                    })
                    .collect::<Vec<_>>()
                    .join("\t"),
            );
        }
        Ok(lines.join("\n"))
    }

    async fn list_schemas(&self, url: &SecretUrl) -> Result<Vec<String>, DbError> {
        let result = self
            .execute(
                url,
                "SELECT SCHEMA_NAME AS name FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys') ORDER BY SCHEMA_NAME",
                &[],
            )
            .await?;
        Ok(result
            .rows
            .iter()
            .filter_map(|row| match row.first() {
                Some(DbValue::Text(name)) => Some(name.clone()),
                _ => None,
            })
            .collect())
    }

    async fn list_tables(
        &self,
        url: &SecretUrl,
        schema: Option<&str>,
    ) -> Result<Vec<TableRef>, DbError> {
        let (sql, params) = match schema {
            Some(schema) => (
                "SELECT TABLE_SCHEMA AS db, TABLE_NAME AS name, TABLE_TYPE AS kind FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME".to_owned(),
                vec![Param::Text(schema.to_owned())],
            ),
            None => (
                "SELECT TABLE_SCHEMA AS db, TABLE_NAME AS name, TABLE_TYPE AS kind FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() ORDER BY TABLE_NAME".to_owned(),
                vec![],
            ),
        };
        let result = self.execute(url, &sql, &params).await?;
        let text = |row: &[DbValue], index: usize| match row.get(index) {
            Some(DbValue::Text(value)) => value.clone(),
            _ => String::new(),
        };
        Ok(result
            .rows
            .iter()
            .filter_map(|row| match text(row, 2).as_str() {
                "BASE TABLE" => Some(TableRef {
                    schema: Some(text(row, 0)),
                    name: text(row, 1),
                    kind: TableKind::Table,
                }),
                "VIEW" => Some(TableRef {
                    schema: Some(text(row, 0)),
                    name: text(row, 1),
                    kind: TableKind::View,
                }),
                _ => None,
            })
            .collect())
    }

    async fn describe_table(
        &self,
        url: &SecretUrl,
        schema: Option<&str>,
        name: &str,
    ) -> Result<TableInfo, DbError> {
        let schema = match schema {
            Some(schema) => schema.to_owned(),
            None => {
                let result = self.execute(url, "SELECT DATABASE() AS name", &[]).await?;
                match result.rows.first().and_then(|row| row.first()) {
                    Some(DbValue::Text(schema)) if !schema.is_empty() => schema.clone(),
                    _ => {
                        return Err(DbError::new(DbErrorKind::Query, "no database selected"));
                    }
                }
            }
        };
        let name = name.to_owned();
        let url = url.clone();
        let adapter = *self;
        async move {
            let columns = adapter
                .execute(
                    &url,
                    "SELECT COLUMN_NAME AS name, COLUMN_TYPE AS type, IS_NULLABLE AS nullable, COLUMN_DEFAULT AS def FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION",
                    &[Param::Text(schema.clone()), Param::Text(name.clone())],
                )
                .await?;
            if columns.rows.is_empty() {
                return Err(DbError::new(
                    DbErrorKind::Query,
                    format!("table not found: {schema}.{name}"),
                ));
            }
            let text = |row: &[DbValue], index: usize| match row.get(index) {
                Some(DbValue::Text(value)) => value.clone(),
                Some(DbValue::Null) | None => String::new(),
                Some(other) => serde_json::to_string(other).unwrap_or_default(),
            };
            let stats = adapter
                .execute(
                    &url,
                    "SELECT INDEX_NAME AS name, COLUMN_NAME AS col, SEQ_IN_INDEX AS seq, NON_UNIQUE AS nonUnique FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? ORDER BY INDEX_NAME, SEQ_IN_INDEX",
                    &[Param::Text(schema.clone()), Param::Text(name.clone())],
                )
                .await?;
            let fks = adapter
                .execute(
                    &url,
                    "SELECT rc.CONSTRAINT_NAME AS name, kcu.COLUMN_NAME AS col, kcu.ORDINAL_POSITION AS seq, kcu.REFERENCED_TABLE_SCHEMA AS refDb, kcu.REFERENCED_TABLE_NAME AS refTable, kcu.REFERENCED_COLUMN_NAME AS refCol FROM information_schema.REFERENTIAL_CONSTRAINTS rc JOIN information_schema.KEY_COLUMN_USAGE kcu ON rc.CONSTRAINT_SCHEMA = kcu.CONSTRAINT_SCHEMA AND rc.CONSTRAINT_NAME = kcu.CONSTRAINT_NAME AND rc.TABLE_NAME = kcu.TABLE_NAME WHERE rc.CONSTRAINT_SCHEMA = ? AND rc.TABLE_NAME = ? ORDER BY rc.CONSTRAINT_NAME, kcu.ORDINAL_POSITION",
                    &[Param::Text(schema.clone()), Param::Text(name.clone())],
                )
                .await?;
            // Group index rows preserving SEQ_IN_INDEX order.
            let mut index_infos: Vec<IndexInfo> = Vec::new();
            for row in &stats.rows {
                let index_name = text(row, 0);
                let unique = !matches!(row.get(3), Some(DbValue::Int(0)) | Some(DbValue::UInt(0)));
                match index_infos.iter_mut().find(|info| info.name == index_name) {
                    Some(info) => info.columns.push(text(row, 1)),
                    None => index_infos.push(IndexInfo {
                        name: index_name,
                        columns: vec![text(row, 1)],
                        unique,
                    }),
                }
            }
            let primary_key = index_infos
                .iter()
                .find(|info| info.name == "PRIMARY")
                .map(|info| info.columns.clone())
                .unwrap_or_default();
            // Group FK rows by constraint name.
            let mut fk_infos: Vec<ForeignKeyInfo> = Vec::new();
            for row in &fks.rows {
                let fk_name = text(row, 0);
                match fk_infos.iter_mut().find(|info| info.name == fk_name) {
                    Some(info) => {
                        info.columns.push(text(row, 1));
                        info.referenced_columns.push(text(row, 5));
                    }
                    None => fk_infos.push(ForeignKeyInfo {
                        name: fk_name,
                        columns: vec![text(row, 1)],
                        referenced_schema: Some(text(row, 3)),
                        referenced_table: text(row, 4),
                        referenced_columns: vec![text(row, 5)],
                    }),
                }
            }
            Ok(TableInfo {
                schema: Some(schema.clone()),
                name: name.clone(),
                kind: TableKind::Table,
                columns: columns
                    .rows
                    .iter()
                    .map(|row| ColumnInfo {
                        name: text(row, 0),
                        data_type: text(row, 1),
                        nullable: text(row, 2) == "YES",
                        default: match row.get(3) {
                            Some(DbValue::Null) | None => None,
                            Some(DbValue::Text(def)) => Some(def.clone()),
                            Some(other) => Some(serde_json::to_string(other).unwrap_or_default()),
                        },
                    })
                    .collect(),
                primary_key,
                indexes: index_infos,
                foreign_keys: fk_infos,
            })
        }
        .await
    }

    async fn dump_schema(
        &self,
        url: &SecretUrl,
        schema: Option<&str>,
        name: &str,
    ) -> Result<String, DbError> {
        let schema = match schema {
            Some(schema) => schema.to_owned(),
            None => {
                let result = self.execute(url, "SELECT DATABASE() AS name", &[]).await?;
                match result.rows.first().and_then(|row| row.first()) {
                    Some(DbValue::Text(schema)) if !schema.is_empty() => schema.clone(),
                    _ => {
                        return Err(DbError::new(DbErrorKind::Query, "no database selected"));
                    }
                }
            }
        };
        let qualified = format!("{}.{}", quote_mysql(&schema), quote_mysql(name));
        let result = self
            .execute(url, &format!("SHOW CREATE TABLE {qualified}"), &[])
            .await?;
        // `SHOW CREATE TABLE` returns (Table, Create Table): pick the
        // second string value (the DDL), mirroring the reference.
        let ddl = result.rows.first().and_then(|row| {
            row.iter()
                .filter_map(|value| match value {
                    DbValue::Text(text) if text != name => Some(text.clone()),
                    _ => None,
                })
                .nth(1)
                .or_else(|| {
                    row.iter()
                        .filter_map(|value| match value {
                            DbValue::Text(text) => Some(text.clone()),
                            _ => None,
                        })
                        .nth(1)
                })
        });
        match ddl {
            Some(ddl) if !ddl.is_empty() => Ok(if ddl.ends_with(';') {
                ddl
            } else {
                format!("{ddl};")
            }),
            _ => Err(DbError::new(
                DbErrorKind::Query,
                format!("table not found: {schema}.{name}"),
            )),
        }
    }

    fn sample_sql(&self, schema: Option<&str>, name: &str, limit: usize) -> String {
        let table = match schema {
            Some(schema) => format!("{}.{}", quote_mysql(schema), quote_mysql(name)),
            None => quote_mysql(name),
        };
        let n = limit.max(1);
        format!("SELECT * FROM {table} ORDER BY RAND() LIMIT {n}")
    }

    async fn estimate_impact(
        &self,
        url: &SecretUrl,
        sql: &str,
        params: &[Param],
    ) -> Result<Option<ImpactEstimate>, DbError> {
        use crate::adapter::starts_with_word;
        if !starts_with_word(sql, "update") && !starts_with_word(sql, "delete") {
            return Ok(None);
        }
        let result = self.explain(url, sql, params).await;
        let planned = match result {
            Ok(plan) => plan,
            Err(_) => return Ok(None),
        };
        // The `rows` column bounds the jackpot: take the max over
        // finite non-negative estimates.
        let mut best: Option<u64> = None;
        for line in planned.lines().skip(1) {
            for cell in line.split('\t') {
                if let Ok(value) = cell.trim().parse::<u64>() {
                    best = Some(best.map_or(value, |best: u64| best.max(value)));
                }
            }
        }
        // Only meaningful when a `rows` column exists.
        let has_rows_column = planned
            .lines()
            .next()
            .is_some_and(|header| header.split('\t').any(|cell| cell.trim() == "rows"));
        Ok(if has_rows_column {
            best.map(|estimated_rows| ImpactEstimate { estimated_rows })
        } else {
            None
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_formatting() {
        assert_eq!(
            format_datetime(2026, 9, 30, 12, 0, 0, 0),
            "2026-09-30T12:00:00"
        );
        assert_eq!(
            format_datetime(2026, 9, 30, 12, 0, 0, 500_000),
            "2026-09-30T12:00:00.5"
        );
    }

    #[test]
    fn blob_vs_text_vs_decimal() {
        assert_eq!(
            convert_bytes(b"19.99", ColumnType::MYSQL_TYPE_NEWDECIMAL),
            DbValue::Decimal("19.99".to_owned())
        );
        assert_eq!(
            convert_bytes(b"hello", ColumnType::MYSQL_TYPE_VAR_STRING),
            DbValue::Text("hello".to_owned())
        );
        assert_eq!(
            convert_bytes(&[0, 255, 0], ColumnType::MYSQL_TYPE_BLOB),
            DbValue::Bytes(vec![0, 255, 0])
        );
        assert_eq!(
            convert_bytes(b"{\"a\":1}", ColumnType::MYSQL_TYPE_JSON),
            DbValue::Json(serde_json::json!({"a": 1}))
        );
    }
}
