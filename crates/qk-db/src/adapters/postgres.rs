//! PostgreSQL adapter (tokio-postgres, plaintext local connections).
//! Per-operation connections (connect → operate → close); no pool.
//! Value decoding is explicit per wire type so DECIMAL precision,
//! 64-bit integers, and timestamps survive exactly.

use tokio_postgres::types::{FromSql, Type};
use tokio_postgres::{Client, NoTls};

use crate::adapter::{Capabilities, DatabaseAdapter, Param};
use crate::config::{parse_postgres_config, SecretUrl};
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

/// PostgreSQL adapter. Stateless across operations.
#[derive(Debug, Default, Clone, Copy)]
pub struct PostgresAdapter;

fn connect_error(error: tokio_postgres::Error) -> DbError {
    let message = error.to_string();
    // Connect-phase failures are connection-level unless the server
    // explicitly rejected credentials.
    let kind = match classify_driver_message(&message) {
        DbErrorKind::Authentication => DbErrorKind::Authentication,
        _ => DbErrorKind::Connection,
    };
    DbError::new(kind, message)
}

fn query_error(error: tokio_postgres::Error) -> DbError {
    let message = error.to_string();
    DbError::new(classify_driver_message(&message), message)
}

async fn connect(url: &SecretUrl) -> Result<Client, DbError> {
    let config = parse_postgres_config(url)?;
    let (client, connection) = config.connect(NoTls).await.map_err(connect_error)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

fn to_sql_param(
    param: &Param,
) -> Result<Box<dyn tokio_postgres::types::ToSql + Sync + Send>, DbError> {
    use tokio_postgres::types::ToSql;
    match param {
        Param::Null => Ok(Box::new(None::<i32>) as Box<dyn ToSql + Sync + Send>),
        Param::Bool(value) => Ok(Box::new(*value)),
        Param::Int(value) => Ok(Box::new(*value)),
        Param::UInt(value) => i64::try_from(*value)
            .map(|value| Box::new(value) as Box<dyn ToSql + Sync + Send>)
            .map_err(|_| DbError::new(DbErrorKind::Query, "integer parameter out of range")),
        Param::Float(value) => Ok(Box::new(*value)),
        Param::Text(text) => Ok(Box::new(text.clone())),
        Param::Bytes(bytes) => Ok(Box::new(bytes.clone())),
    }
}

/// Raw wire bytes regardless of declared type (orphan-rule-safe
/// local wrapper with an open `accepts` gate). Used for NUMERIC,
/// dates, times, and UUIDs, whose binary formats decode manually.
struct Raw<'a>(&'a [u8]);

impl<'a> FromSql<'a> for Raw<'a> {
    fn from_sql(_: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        Ok(Self(raw))
    }

    fn accepts(_: &Type) -> bool {
        true
    }
}

/// JSON/JSONB document text: JSON arrives as plain UTF-8; JSONB
/// carries a leading version byte (always `0x01`) before the text.
/// Accept exactly those types (orphan-rule-safe local wrapper).
struct JsonText(String);

impl<'a> FromSql<'a> for JsonText {
    fn from_sql(
        ty: &Type,
        raw: &'a [u8],
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        let text = match *ty {
            Type::JSON => raw,
            Type::JSONB => raw.strip_prefix(&[1]).ok_or("bad jsonb version")?,
            _ => return Err("unexpected type for JSON text".into()),
        };
        std::str::from_utf8(text)
            .map(|text| Self(text.to_owned()))
            .map_err(|error| Box::new(error) as _)
    }

    fn accepts(ty: &Type) -> bool {
        matches!(*ty, Type::JSON | Type::JSONB)
    }
}

/// Decode postgres binary NUMERIC into exact decimal text
/// (base-10000 digits; never via float). `None` means malformed.
/// NaN maps to [`DbValue::Float`] NaN (which serializes as null,
///
/// matching `JSON.stringify`).
fn decode_numeric(raw: &[u8]) -> Option<DbValue> {
    if raw.len() < 8 || !(raw.len() - 8).is_multiple_of(2) {
        return None;
    }
    let int16 = |at: usize| i16::from_be_bytes([raw[at], raw[at + 1]]);
    let uint16 = |at: usize| u16::from_be_bytes([raw[at], raw[at + 1]]);
    let ndigits = int16(0);
    let weight = int16(2);
    let sign = uint16(4);
    let dscale = uint16(6);
    if sign == 0xC000 {
        return Some(DbValue::Float(f64::NAN));
    }
    if sign != 0x0000 && sign != 0x4000 {
        return None;
    }
    if ndigits < 0 {
        return None;
    }
    let mut digits: Vec<u16> = Vec::with_capacity(ndigits as usize);
    for i in 0..ndigits as usize {
        digits.push(uint16(8 + 2 * i));
        if digits[i] >= 10_000 {
            return None;
        }
    }
    if digits.iter().all(|digit| *digit == 0) {
        return Some(DbValue::Decimal("0".to_owned()));
    }
    // Integer part: (weight+1) base-10000 groups from the left.
    let int_groups = (weight + 1).max(0) as usize;
    let mut out = String::new();
    if sign == 0x4000 {
        out.push('-');
    }
    if int_groups == 0 {
        out.push('0');
    }
    for (i, group) in digits.iter().enumerate().take(int_groups) {
        if i == 0 {
            out.push_str(&group.to_string());
        } else {
            out.push_str(&format!("{group:04}"));
        }
    }
    for _ in digits.len()..int_groups {
        out.push_str("0000");
    }
    // Fractional part: remaining groups zero-padded then cut to
    // dscale (dscale is authoritative for NUMERIC text form — psql
    // prints trailing zeros to dscale).
    if dscale > 0 {
        let mut frac = String::new();
        for group in digits.iter().skip(int_groups) {
            frac.push_str(&format!("{group:04}"));
        }
        while frac.len() < dscale as usize {
            frac.push('0');
        }
        frac.truncate(dscale as usize);
        out.push('.');
        out.push_str(&frac);
    }
    Some(DbValue::Decimal(out))
}

/// Days since civil 1970-01-01 → (year, month, day) (Hinnant algorithm).
fn civil_from_days(days: i64) -> Option<(i32, u32, u32)> {
    let days = days.checked_add(719_468)?;
    let era = days.div_euclid(146_097);
    let doe = days.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    Some((
        (if month <= 2 { year + 1 } else { year }) as i32,
        month,
        day,
    ))
}

fn two(value: u32) -> String {
    format!("{value:02}")
}

/// Postgres date/time binary decoders (microsecond/int32 offsets from
/// the 2000-01-01 epoch) → ISO-8601 text.
mod pg_time {
    use super::civil_from_days;

    /// Days from 2000-01-01 (civil) for date decoding.
    const PG_EPOCH_DAYS_UNIX: i64 = 10_957; // 2000-01-01 - 1970-01-01

    pub fn date(days_since_2000: i32) -> Option<String> {
        let (year, month, day) = civil_from_days(i64::from(days_since_2000) + PG_EPOCH_DAYS_UNIX)?;
        Some(format!(
            "{year:04}-{}-{}",
            super::two(month),
            super::two(day)
        ))
    }

    fn split_micros(micros: i64) -> (i64, u32, u32, u32, u32) {
        let secs = micros.div_euclid(1_000_000);
        let sub = micros.rem_euclid(1_000_000) as u32;
        let day_secs = secs.rem_euclid(86_400);
        let (hour, minute, second) = (
            (day_secs / 3_600) as u32,
            ((day_secs / 60) % 60) as u32,
            (day_secs % 60) as u32,
        );
        (secs.div_euclid(86_400), hour, minute, second, sub)
    }

    fn frac(sub: u32) -> String {
        if sub == 0 {
            String::new()
        } else {
            format!(".{sub:06}").trim_end_matches('0').to_owned()
        }
    }

    pub fn timestamp(micros_since_2000: i64) -> Option<String> {
        let (days, hour, minute, second, sub) = split_micros(micros_since_2000);
        let (year, month, day) = civil_from_days(days + PG_EPOCH_DAYS_UNIX)?;
        Some(format!(
            "{year:04}-{}-{}T{}:{}:{}{}",
            super::two(month),
            super::two(day),
            super::two(hour),
            super::two(minute),
            super::two(second),
            frac(sub)
        ))
    }

    pub fn time(micros_since_midnight: i64) -> Option<String> {
        let (_, hour, minute, second, sub) = split_micros(micros_since_midnight);
        if hour > 23 {
            return None;
        }
        Some(format!(
            "{}:{}:{}{}",
            super::two(hour),
            super::two(minute),
            super::two(second),
            frac(sub)
        ))
    }
}

/// Typed nullable getter: `Ok(None)` on SQL NULL (the `Option`
/// impl short-circuits null before consulting the inner type), `Err`
/// on genuine conversion failures.
fn opt<T>(row: &tokio_postgres::Row, index: usize) -> Result<Option<T>, DbError>
where
    T: for<'a> FromSql<'a>,
{
    row.try_get(index).map_err(|error| {
        DbError::new(
            DbErrorKind::Query,
            format!("cannot read column {index}: {error}"),
        )
    })
}

/// Shared timestamp/timestamptz decoder (int64 micros since
/// 2000-01-01, big-endian; `utc` appends the `Z` designator).
fn decode_timestamp(
    row: &tokio_postgres::Row,
    index: usize,
    bad: &impl Fn(String) -> DbError,
    utc: bool,
) -> Result<DbValue, DbError> {
    let raw: Option<Raw<'_>> = row
        .try_get(index)
        .map_err(|error| bad(format!("cannot read column {index}: {error}")))?;
    match raw.map(|raw| raw.0) {
        None => Ok(DbValue::Null),
        Some(bytes) if bytes.len() == 8 => {
            let micros = i64::from_be_bytes(bytes.try_into().expect("len 8"));
            pg_time::timestamp(micros)
                .map(|text| DbValue::DateTime(if utc { format!("{text}Z") } else { text }))
                .ok_or_else(|| bad(format!("cannot decode timestamp column {index}")))
        }
        _ => Err(bad(format!("cannot decode timestamp column {index}"))),
    }
}

fn decode_value(row: &tokio_postgres::Row, index: usize) -> Result<DbValue, DbError> {
    let ty = row.columns()[index].type_().clone();
    let bad = |detail: String| DbError::new(DbErrorKind::Query, detail);
    macro_rules! load {
        ($t:ty) => {
            match opt::<$t>(row, index)? {
                None => return Ok(DbValue::Null),
                Some(value) => value,
            }
        };
    }
    match ty {
        Type::BOOL => Ok(DbValue::Bool(load!(bool))),
        Type::CHAR => Ok(DbValue::Int(i64::from(load!(i8)))),
        Type::INT2 => Ok(DbValue::Int(i64::from(load!(i16)))),
        Type::INT4 => Ok(DbValue::Int(i64::from(load!(i32)))),
        Type::INT8 => Ok(DbValue::Int(load!(i64))),
        Type::OID => Ok(DbValue::UInt(u64::from(load!(u32)))),
        Type::FLOAT4 => Ok(DbValue::Float(f64::from(load!(f32)))),
        Type::FLOAT8 => Ok(DbValue::Float(load!(f64))),
        Type::NUMERIC => {
            // NUMERIC binary decodes exactly; text fallback covers
            // unknown-declared columns. `None` is SQL NULL.
            let raw: Option<Raw<'_>> = row.try_get(index).map_err(|e| bad(e.to_string()))?;
            match raw.map(|raw| raw.0) {
                None => Ok(DbValue::Null),
                Some(bytes) => decode_numeric(bytes).map_or_else(
                    || {
                        std::str::from_utf8(bytes)
                            .map(|text| DbValue::Decimal(text.to_owned()))
                            .map_err(|_| bad(format!("cannot decode numeric column {index}")))
                    },
                    Ok,
                ),
            }
        }
        Type::VARCHAR | Type::TEXT | Type::NAME | Type::BPCHAR | Type::UNKNOWN => {
            Ok(DbValue::Text(load!(String)))
        }
        Type::BYTEA => Ok(DbValue::Bytes(load!(Vec<u8>))),
        Type::JSON | Type::JSONB => match opt::<JsonText>(row, index)? {
            None => Ok(DbValue::Null),
            Some(JsonText(text)) => Ok(json_value(&text)),
        },
        Type::DATE => {
            // int32 days since 2000-01-01 (binary, big-endian).
            let raw: Option<Raw<'_>> = row.try_get(index).map_err(|e| bad(e.to_string()))?;
            match raw.map(|raw| raw.0) {
                None => Ok(DbValue::Null),
                Some(bytes) if bytes.len() == 4 => {
                    let days = i32::from_be_bytes(bytes.try_into().expect("len 4"));
                    pg_time::date(days)
                        .map(DbValue::DateTime)
                        .ok_or_else(|| bad(format!("cannot decode date column {index}")))
                }
                _ => Err(bad(format!("cannot decode date column {index}"))),
            }
        }
        Type::TIMESTAMP => decode_timestamp(row, index, &bad, false),
        Type::TIMESTAMPTZ => decode_timestamp(row, index, &bad, true),
        Type::TIME | Type::TIMETZ => {
            // int64 microseconds since midnight (binary, big-endian).
            let raw: Option<Raw<'_>> = row.try_get(index).map_err(|e| bad(e.to_string()))?;
            match raw.map(|raw| raw.0) {
                None => Ok(DbValue::Null),
                Some(bytes) if bytes.len() == 8 => {
                    let micros = i64::from_be_bytes(bytes.try_into().expect("len 8"));
                    pg_time::time(micros)
                        .map(DbValue::DateTime)
                        .ok_or_else(|| bad(format!("cannot decode time column {index}")))
                }
                _ => Err(bad(format!("cannot decode time column {index}"))),
            }
        }
        Type::UUID => {
            let raw: Option<Raw<'_>> = row.try_get(index).map_err(|e| bad(e.to_string()))?;
            match raw.map(|raw| raw.0) {
                None => Ok(DbValue::Null),
                Some(bytes) if bytes.len() == 16 => Ok(DbValue::Text(format!(
                    "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
                    bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
                    bytes[12], bytes[13], bytes[14], bytes[15]
                ))),
                _ => Err(bad(format!("cannot decode uuid column {index}"))),
            }
        }
        other => Err(DbError::new(
            DbErrorKind::Query,
            format!("unsupported column type: {}", other.name()),
        )),
    }
}

impl PostgresAdapter {
    async fn run<F, T>(&self, url: &SecretUrl, operation: F) -> Result<T, DbError>
    where
        F: FnOnce(
            Client,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, DbError>> + Send>,
        >,
    {
        let client = connect(url).await?;
        let result = operation(client).await;
        // Client drops here (connection closes); the spawned
        // connection task ends with it.
        result
    }
}

#[async_trait::async_trait]
impl DatabaseAdapter for PostgresAdapter {
    fn engine(&self) -> &'static str {
        "postgres"
    }

    fn capabilities(&self) -> Capabilities {
        CAPABILITIES
    }

    async fn test_connection(&self, url: &SecretUrl) -> Result<PingResult, DbError> {
        let started = std::time::Instant::now();
        let client = connect(url).await?;
        let row = client
            .query_one("SELECT version() AS version", &[])
            .await
            .map_err(query_error)?;
        let version: Option<String> = row
            .try_get("version")
            .map_err(|error| DbError::new(DbErrorKind::Protocol, error.to_string()))?;
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
        let params: Vec<Param> = params.to_vec();
        self.run(url, |client| {
            Box::pin(async move {
                let bound: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> =
                    params.iter().map(to_sql_param).collect::<Result<_, _>>()?;
                let refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
                    bound.iter().map(|param| param.as_ref() as _).collect();
                if crate::adapter::looks_like_read(&sql) {
                    let rows = client.query(&sql, &refs).await.map_err(query_error)?;
                    let columns: Vec<String> = rows
                        .first()
                        .map(|row| {
                            row.columns()
                                .iter()
                                .map(|col| col.name().to_owned())
                                .collect()
                        })
                        .unwrap_or_default();
                    let mut out = Vec::with_capacity(rows.len());
                    for row in &rows {
                        let mut values = Vec::with_capacity(columns.len());
                        for index in 0..columns.len() {
                            values.push(decode_value(row, index)?);
                        }
                        out.push(values);
                    }
                    Ok(RawResult {
                        columns,
                        rows: out,
                        rows_affected: None,
                    })
                } else {
                    // Extended protocol rejects multi-statement batches
                    // at the server (never silent partial execution).
                    let affected = client.execute(&sql, &refs).await.map_err(query_error)?;
                    Ok(RawResult {
                        columns: Vec::new(),
                        rows: Vec::new(),
                        rows_affected: Some(affected),
                    })
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
        // Frozen shape: per-row space-joined values, rows joined `\n`.
        Ok(result
            .rows
            .iter()
            .map(|row| {
                row.iter()
                    .map(|value| match value {
                        DbValue::Null => String::new(),
                        DbValue::Text(text) => text.clone(),
                        other => serde_json::to_string(other).unwrap_or_default(),
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>()
            .join("\n"))
    }

    async fn list_schemas(&self, url: &SecretUrl) -> Result<Vec<String>, DbError> {
        let result = self
            .execute(
                url,
                "SELECT schema_name AS name FROM information_schema.schemata WHERE schema_name NOT IN ('pg_catalog', 'information_schema', 'pg_toast') AND schema_name NOT LIKE 'pg_temp%' AND schema_name NOT LIKE 'pg_toast_temp%' ORDER BY schema_name",
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
                "SELECT table_schema AS db, table_name AS name, table_type AS kind FROM information_schema.tables WHERE table_schema = $1 ORDER BY table_name".to_owned(),
                vec![Param::Text(schema.to_owned())],
            ),
            None => (
                "SELECT table_schema AS db, table_name AS name, table_type AS kind FROM information_schema.tables WHERE table_schema = current_schema() ORDER BY table_name".to_owned(),
                vec![],
            ),
        };
        let result = self.execute(url, &sql, &params).await?;
        Ok(result
            .rows
            .iter()
            .filter_map(|row| {
                let text = |index: usize| match row.get(index) {
                    Some(DbValue::Text(value)) => value.clone(),
                    _ => String::new(),
                };
                match text(2).as_str() {
                    "BASE TABLE" => Some(TableRef {
                        schema: Some(text(0)),
                        name: text(1),
                        kind: TableKind::Table,
                    }),
                    "VIEW" => Some(TableRef {
                        schema: Some(text(0)),
                        name: text(1),
                        kind: TableKind::View,
                    }),
                    _ => None,
                }
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
                let result = self
                    .execute(url, "SELECT current_schema() AS name", &[])
                    .await?;
                match result.rows.first().and_then(|row| row.first()) {
                    Some(DbValue::Text(schema)) => schema.clone(),
                    _ => {
                        return Err(DbError::new(DbErrorKind::Query, "no schema selected"));
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
                    "SELECT column_name AS name, data_type AS type, is_nullable AS nullable, column_default AS def FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2 ORDER BY ordinal_position",
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
            let pk = adapter
                .execute(
                    &url,
                    "SELECT kcu.column_name AS name FROM information_schema.table_constraints tc JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema WHERE tc.constraint_type = 'PRIMARY KEY' AND tc.table_schema = $1 AND tc.table_name = $2 ORDER BY kcu.ordinal_position",
                    &[Param::Text(schema.clone()), Param::Text(name.clone())],
                )
                .await?;
            let indexes = adapter
                .execute(
                    &url,
                    "SELECT i.relname AS name, a.attname AS col, ix.indisunique AS uniq FROM pg_class t JOIN pg_namespace n ON n.oid = t.relnamespace JOIN pg_index ix ON t.oid = ix.indrelid JOIN pg_class i ON i.oid = ix.indexrelid JOIN LATERAL unnest(ix.indkey) WITH ORDINALITY AS k(attnum, ord) ON true JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum WHERE n.nspname = $1 AND t.relname = $2 ORDER BY i.relname, k.ord",
                    &[Param::Text(schema.clone()), Param::Text(name.clone())],
                )
                .await?;
            let fks = adapter
                .execute(
                    &url,
                    "SELECT tc.constraint_name AS name, kcu.column_name AS col, ccu.table_schema AS ref_db, ccu.table_name AS ref_table, ccu.column_name AS ref_col FROM information_schema.table_constraints tc JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema JOIN information_schema.constraint_column_usage ccu ON ccu.constraint_name = tc.constraint_name AND ccu.table_schema = tc.table_schema WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = $1 AND tc.table_name = $2 ORDER BY tc.constraint_name, kcu.ordinal_position",
                    &[Param::Text(schema.clone()), Param::Text(name.clone())],
                )
                .await?;
            // Group index (name, col, uniq) rows preserving ordinal order.
            let mut index_infos: Vec<IndexInfo> = Vec::new();
            for row in &indexes.rows {
                let index_name = text(row, 0);
                match index_infos.iter_mut().find(|info| info.name == index_name) {
                    Some(info) => info.columns.push(text(row, 1)),
                    None => index_infos.push(IndexInfo {
                        name: index_name,
                        columns: vec![text(row, 1)],
                        unique: matches!(row.get(2), Some(DbValue::Bool(true))),
                    }),
                }
            }
            // Group FK rows by constraint name.
            let mut fk_infos: Vec<ForeignKeyInfo> = Vec::new();
            for row in &fks.rows {
                let fk_name = text(row, 0);
                match fk_infos.iter_mut().find(|info| info.name == fk_name) {
                    Some(info) => {
                        info.columns.push(text(row, 1));
                        info.referenced_columns.push(text(row, 4));
                    }
                    None => fk_infos.push(ForeignKeyInfo {
                        name: fk_name,
                        columns: vec![text(row, 1)],
                        referenced_schema: Some(text(row, 2)),
                        referenced_table: text(row, 3),
                        referenced_columns: vec![text(row, 4)],
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
                primary_key: pk.rows.iter().map(|row| text(row, 0)).collect(),
                indexes: index_infos,
                foreign_keys: fk_infos,
            })
        }
        .await
    }

    fn sample_sql(&self, schema: Option<&str>, name: &str, limit: usize) -> String {
        let table = match schema {
            Some(schema) => format!("{}.{}", quote_pg(schema), quote_pg(name)),
            None => quote_pg(name),
        };
        let n = limit.max(1);
        format!("SELECT * FROM {table} ORDER BY random() LIMIT {n}")
    }

    async fn estimate_impact(
        &self,
        url: &SecretUrl,
        sql: &str,
        params: &[Param],
    ) -> Result<Option<ImpactEstimate>, DbError> {
        // Only UPDATE/DELETE are worth estimating; EXPLAIN never
        // executes the write.
        if !crate::adapter::starts_with_word(sql, "update")
            && !crate::adapter::starts_with_word(sql, "delete")
        {
            return Ok(None);
        }
        let plan = self.explain(url, sql, params).await?;
        // The top write node reports rows=0; the scan below holds the
        // real affected estimate — take the max over all matches.
        let mut best: Option<u64> = None;
        let bytes = plan.as_bytes();
        let mut i = 0;
        while i + 5 <= bytes.len() {
            if bytes[i..].starts_with(b"rows=") {
                let mut j = i + 5;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                let mut value: u64 = 0;
                let mut digits = 0;
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    value = value
                        .saturating_mul(10)
                        .saturating_add(u64::from(bytes[j] - b'0'));
                    digits += 1;
                    j += 1;
                }
                if digits > 0 {
                    best = Some(best.map_or(value, |best: u64| best.max(value)));
                }
                i = j;
            } else {
                i += 1;
            }
        }
        Ok(best.map(|estimated_rows| ImpactEstimate { estimated_rows }))
    }
}

fn quote_pg(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::{decode_numeric, pg_time};
    use crate::value::DbValue;

    #[test]
    fn numeric_precision() {
        // 19.99: ndigits=2, weight=0, sign=0, dscale=2, digits=[19, 9900].
        let raw = [0u8, 2, 0, 0, 0, 0, 0, 2, 0, 19, 38, 172];
        assert_eq!(
            decode_numeric(&raw),
            Some(DbValue::Decimal("19.99".to_owned()))
        );
        // 0.30000000000000004 cannot be float-exact; text must survive.
        // weight=-1, digits=[3000, 0, 0, 0, 4000], dscale=17 (the
        // 17th decimal falls in the fifth base-10000 group as 4000).
        let raw = [
            0, 5, 255, 255, 0, 0, 0, 17, 11, 184, 0, 0, 0, 0, 0, 0, 15, 160,
        ];
        assert_eq!(
            decode_numeric(&raw),
            Some(DbValue::Decimal("0.30000000000000004".to_owned()))
        );
        // Integer 42: ndigits=1, weight=0, dscale=0, digits=[42].
        let raw = [0, 1, 0, 0, 0, 0, 0, 0, 0, 42];
        assert_eq!(
            decode_numeric(&raw),
            Some(DbValue::Decimal("42".to_owned()))
        );
        // Negative -7.
        let raw = [0, 1, 0, 0, 0x40, 0, 0, 0, 0, 7];
        assert_eq!(
            decode_numeric(&raw),
            Some(DbValue::Decimal("-7".to_owned()))
        );
        // NaN.
        let raw = [0, 0, 0, 0, 0xC0, 0, 0, 0];
        assert!(matches!(decode_numeric(&raw), Some(DbValue::Float(_))));
        // Malformed.
        assert_eq!(decode_numeric(&[0, 1]), None);
    }

    #[test]
    fn date_time_decoders() {
        assert_eq!(pg_time::date(0), Some("2000-01-01".to_owned()));
        assert_eq!(pg_time::date(9_752), Some("2026-09-13".to_owned()));
        assert_eq!(
            pg_time::timestamp(0),
            Some("2000-01-01T00:00:00".to_owned())
        );
        assert_eq!(
            pg_time::timestamp(1_000_000),
            Some("2000-01-01T00:00:01".to_owned())
        );
        assert_eq!(pg_time::time(3_723_000_000), Some("01:02:03".to_owned()));
    }
}
