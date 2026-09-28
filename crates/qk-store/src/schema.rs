//! Schema versions and migrations. Single mechanism: `PRAGMA user_version`.
//!
//! - Version 1 is the TypeScript schema verbatim (six tables, no indexes,
//!   no version tracking — the reference never sets `user_version`, so
//!   legacy databases read as 0).
//! - Version 2 adds QueryKnight-Rust columns and lookup indexes.
//! - Fresh databases are created at version 2 in one transaction.
//! - Legacy databases (version 0 *with* tables) migrate 0 -> 2 directly.
//! - Version 0 *without* tables means a fresh file: create at version 2.
//! - Anything above [`SCHEMA_VERSION`] is refused (`SchemaMismatch`).
//!
//! Every step is idempotent in effect: `CREATE TABLE IF NOT EXISTS`,
//! column-exists checks before `ADD COLUMN`, `CREATE INDEX IF NOT
//! EXISTS`. The whole migration runs in one transaction, so a crash can
//! never leave a half-applied schema behind the version stamp.

/// Current schema version written by this crate.
pub const SCHEMA_VERSION: u32 = 2;

/// Version 1 DDL: the TypeScript daemon schema, byte-for-byte in spirit
/// (whitespace normalized). Includes the historically-added columns
/// (`approvals.schema_ddl`, `approvals.schema_diff`, `query_events.sql`):
/// a fresh database must not depend on the tolerant upgrade path.
const SCHEMA_V1: &str = "
CREATE TABLE IF NOT EXISTS connections (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  engine TEXT NOT NULL,
  environment TEXT NOT NULL DEFAULT 'unknown',
  source TEXT NOT NULL,
  database TEXT,
  host_label TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  connection_id TEXT NOT NULL,
  agent TEXT,
  started_at INTEGER NOT NULL,
  ended_at INTEGER,
  source TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS query_events (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  source TEXT NOT NULL,
  sql_fingerprint TEXT NOT NULL,
  sql TEXT,
  query_class TEXT NOT NULL,
  risk TEXT NOT NULL,
  decision TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  duration_ms INTEGER,
  rows_returned INTEGER,
  rows_affected INTEGER,
  bytes_returned INTEGER,
  estimated_tokens_returned INTEGER,
  estimated_tokens_avoided INTEGER,
  error_code TEXT
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  session_id TEXT,
  connection_id TEXT,
  fingerprint TEXT NOT NULL,
  status TEXT NOT NULL,
  reason TEXT NOT NULL,
  risk TEXT NOT NULL,
  operation_summary TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  decided_at INTEGER,
  decision_source TEXT,
  scope TEXT,
  schema_ddl TEXT,
  schema_diff TEXT
);
CREATE TABLE IF NOT EXISTS session_allows (
  session_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  PRIMARY KEY (session_id, fingerprint)
);
";

/// Version 2 additions. Each is `None`-able so legacy rows stay readable;
/// absence carries authorization meaning (see `store.rs` reader).
const APPROVAL_V2_COLUMNS: &[(&str, &str)] = &[
    // Full-strength token binding. NULL on legacy rows: never eligible
    // for exact-token replay (a NULL digest can never equal a request).
    ("exact_digest", "BLOB"),
    // Scope dimensions for hardened matching. NULL on legacy rows means
    // "unknown": legacy session-shape grants keep frozen
    // session+fingerprint matching instead of failing outright.
    ("integration", "TEXT"),
    ("environment", "TEXT"),
    ("database_name", "TEXT"),
    ("agent_id", "TEXT"),
    ("tool", "TEXT"),
    // Frozen reason code and decisive policy path for display/audit.
    ("reason_code", "TEXT"),
    ("matched_policy", "TEXT"),
    // Who recorded the decision (frozen vocabulary); NULL until decided.
    ("decided_by", "TEXT"),
];

/// Indexes driven by actual lookups (nothing speculative): session-grant
/// scans and per-session event listings.
const INDEXES: &[(&str, &str)] = &[
    (
        "approvals_session_fingerprint",
        "CREATE INDEX IF NOT EXISTS approvals_session_fingerprint ON approvals (session_id, fingerprint)",
    ),
    (
        "query_events_session_started",
        "CREATE INDEX IF NOT EXISTS query_events_session_started ON query_events (session_id, started_at)",
    ),
];

/// Read `PRAGMA user_version`.
pub(crate) fn user_version(conn: &rusqlite::Connection) -> Result<u32, rusqlite::Error> {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
}

/// True when the database already holds the version-1 tables (i.e. it is a
/// migrated TypeScript database rather than a fresh file). Test support:
/// migration itself is table-presence agnostic by construction.
#[cfg(test)]
fn has_v1_tables(conn: &rusqlite::Connection) -> Result<bool, rusqlite::Error> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN \
         ('connections', 'sessions', 'query_events', 'settings', 'approvals', 'session_allows')",
        [],
        |row| row.get(0),
    )?;
    Ok(count == 6)
}

fn table_columns(
    conn: &rusqlite::Connection,
    table: &str,
) -> Result<std::collections::HashSet<String>, rusqlite::Error> {
    let mut statement = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = statement.query_map([], |row| row.get::<_, String>(1))?;
    names.collect()
}

/// Bring any database to [`SCHEMA_VERSION`] inside one transaction.
/// Created for `Store::open`; see module docs for the version policy.
pub(crate) fn migrate(conn: &mut rusqlite::Connection) -> Result<(), crate::StoreError> {
    use crate::StoreError;
    let version = user_version(conn).map_err(|e| StoreError::Migration(e.to_string()))?;
    if version > SCHEMA_VERSION {
        return Err(StoreError::SchemaMismatch(format!(
            "database schema version {version} is newer than supported {SCHEMA_VERSION}"
        )));
    }
    if version == SCHEMA_VERSION {
        return Ok(());
    }
    let transaction = conn
        .transaction()
        .map_err(|e| StoreError::Migration(e.to_string()))?;
    // Version 1 base (idempotent): covers fresh files and any database
    // predating a table.
    transaction
        .execute_batch(SCHEMA_V1)
        .map_err(|e| StoreError::Migration(e.to_string()))?;
    // Tolerant column repair, mirroring the reference `PRAGMA table_info`
    // checks: a partially migrated database gains exactly the missing
    // columns, and pre-existing columns are never touched. This also
    // backfills the historically added columns (`schema_ddl`,
    // `schema_diff`, `sql`) on databases predating them.
    for (table, columns) in [
        ("approvals", ["schema_ddl", "schema_diff"].as_slice()),
        ("query_events", ["sql"].as_slice()),
    ] {
        let present =
            table_columns(&transaction, table).map_err(|e| StoreError::Migration(e.to_string()))?;
        for column in columns {
            if !present.contains(*column) {
                transaction
                    .execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} TEXT"))
                    .map_err(|e| StoreError::Migration(e.to_string()))?;
            }
        }
    }
    // Version 2 additions, same tolerant pattern.
    let present = table_columns(&transaction, "approvals")
        .map_err(|e| StoreError::Migration(e.to_string()))?;
    for (column, column_type) in APPROVAL_V2_COLUMNS {
        if !present.contains(*column) {
            transaction
                .execute_batch(&format!(
                    "ALTER TABLE approvals ADD COLUMN {column} {column_type}"
                ))
                .map_err(|e| StoreError::Migration(e.to_string()))?;
        }
    }
    for (_, ddl) in INDEXES {
        transaction
            .execute_batch(ddl)
            .map_err(|e| StoreError::Migration(e.to_string()))?;
    }
    migrate_orphan_session_grants(&transaction)?;
    transaction
        .execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))
        .map_err(|e| StoreError::Migration(e.to_string()))?;
    transaction
        .commit()
        .map_err(|e| StoreError::Migration(e.to_string()))?;
    Ok(())
}

/// Adopt orphaned legacy session grants: `session_allows` rows with no
/// matching approved session approval row become synthetic approved
/// session grants (frozen session-shape semantics preserved). Deterministic
/// ids make the step idempotent; rows that already resolve are skipped.
/// New columns stay NULL, so synthetics validate as `legacy_shape_only`
/// (shape matching only, never exact-token replay). `expires_at` uses
/// `i64::MAX`: the reference never expires these rows.
fn migrate_orphan_session_grants(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), crate::StoreError> {
    use crate::StoreError;
    transaction
        .execute_batch(
            "INSERT INTO approvals (
               id, session_id, fingerprint, status, reason, risk,
               operation_summary, created_at, expires_at, scope
             )
             SELECT 'qkam-' || session_id || '-' || fingerprint,
                    session_id, fingerprint, 'approved',
                    'migrated session grant', '', '', 0, 9223372036854775807, 'session'
             FROM session_allows
             WHERE length(fingerprint) = 16
               AND NOT EXISTS (
                 SELECT 1 FROM approvals AS existing
                 WHERE existing.session_id = session_allows.session_id
                   AND existing.fingerprint = session_allows.fingerprint
                   AND existing.status = 'approved'
                   AND existing.scope = 'session'
               )",
        )
        .map_err(|e| StoreError::Migration(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{has_v1_tables, migrate, user_version, SCHEMA_VERSION};

    fn memory_db() -> rusqlite::Connection {
        rusqlite::Connection::open_in_memory().expect("memory db")
    }

    #[test]
    fn fresh_database_reaches_current_version() {
        let mut conn = memory_db();
        assert!(!has_v1_tables(&conn).expect("inspect"));
        migrate(&mut conn).expect("migrate");
        assert_eq!(user_version(&conn).expect("version"), SCHEMA_VERSION);
        assert!(has_v1_tables(&conn).expect("inspect"));
        // Idempotent: second run is a no-op.
        migrate(&mut conn).expect("migrate again");
        assert_eq!(user_version(&conn).expect("version"), SCHEMA_VERSION);
    }

    #[test]
    fn newer_schema_is_refused() {
        let mut conn = memory_db();
        conn.execute_batch("PRAGMA user_version = 99")
            .expect("stamp");
        let error = migrate(&mut conn).expect_err("must refuse");
        assert!(error.to_string().contains("newer than supported"));
    }
}
