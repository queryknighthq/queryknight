//! Typed SQLite store: approvals, sessions, query events, connections.
//!
//! Ownership: one `rusqlite::Connection` behind a `Mutex` (connections are
//! `Send`; the mutex makes shared use `Sync`). Critical sections hold
//! single statements or short explicit transactions. No pool, no
//! connection leakage into other crates.
//!
//! Authorization reads validate every row (`InvalidRow` on malformed
//! content, never a live grant). Point lookups (`get_grant`) report
//! invalid rows explicitly; scans (`list_grants`, session lookup) skip
//! them — skipped rows can never authorize anything either way.

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use qk_approval::{ApprovalId, ApprovalScope, DecisionSource, GrantStatus, Scope, StoredGrant};
use qk_core::{parse_reason_code, ExactRequestDigest, QueryShapeFingerprint, ReasonCode};
use rusqlite::{params, OptionalExtension};

use crate::error::{classify_rusqlite, StoreError};
use crate::events::EventView;
use crate::schema::{migrate, user_version};
use crate::sessions::{ConnectionRecord, SessionRecord};

/// Default query-event cap, mirroring the reference (oldest rows trimmed
/// past this many events).
pub const DEFAULT_EVENT_CAP: usize = 5000;

/// Default lock-wait bound. The reference sets no busy timeout (fail-fast
/// on contention); a bounded wait is required for daemon concurrency, so
/// contention surfaces as typed `Busy` instead of hanging forever.
pub const DEFAULT_BUSY_TIMEOUT_MS: u64 = 5000;

/// Typed SQLite state.
#[derive(Debug)]
pub struct Store {
    conn: Mutex<rusqlite::Connection>,
    event_cap: usize,
}

impl Store {
    /// Open (creating parent directories and the file as needed), apply
    /// PRAGMAs, and migrate to [`SCHEMA_VERSION`].
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| StoreError::Open(format!("cannot create state dir: {e}")))?;
            }
        }
        let mut conn =
            rusqlite::Connection::open(path).map_err(|e| StoreError::Open(trim_debug(e)))?;
        // Reference parity: WAL for daemon read concurrency.
        conn.execute_batch("PRAGMA journal_mode = WAL")
            .map_err(|e| StoreError::Open(trim_debug(e)))?;
        conn.busy_timeout(Duration::from_millis(DEFAULT_BUSY_TIMEOUT_MS))
            .map_err(|e| StoreError::Open(trim_debug(e)))?;
        migrate(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            event_cap: DEFAULT_EVENT_CAP,
        })
    }

    /// Open an in-memory database (tests and ephemeral use).
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let mut conn =
            rusqlite::Connection::open_in_memory().map_err(|e| StoreError::Open(trim_debug(e)))?;
        migrate(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            event_cap: DEFAULT_EVENT_CAP,
        })
    }

    /// Adjust the lock-wait bound (also a test hook for fast Busy paths).
    pub fn set_busy_timeout(&self, timeout: Duration) -> Result<(), StoreError> {
        self.conn
            .lock()
            .map_err(|_| StoreError::Database("store lock poisoned".to_owned()))?
            .busy_timeout(timeout)
            .map_err(|e| StoreError::Database(trim_debug(e)))
    }

    /// Adjust the query-event cap.
    pub fn set_event_cap(&mut self, cap: usize) {
        self.event_cap = cap;
    }

    /// Current on-disk schema version.
    pub fn schema_version(&self) -> Result<u32, StoreError> {
        let conn = self.lock()?;
        user_version(&conn).map_err(|e| StoreError::Database(trim_debug(e)))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>, StoreError> {
        self.conn
            .lock()
            .map_err(|_| StoreError::Database("store lock poisoned".to_owned()))
    }

    // ------------------------------------------------------------------
    // Approvals.
    // ------------------------------------------------------------------

    /// Persist a grant row with an explicit creation timestamp (no clock
    /// reads inside the store). Duplicate ids are a `Conflict`, never an
    /// overwrite.
    pub fn insert_grant(&self, grant: &StoredGrant, now_ms: u64) -> Result<(), StoreError> {
        let conn = self.lock()?;
        let changed = conn
            .execute(
                "INSERT INTO approvals (
                   id, session_id, fingerprint, status, reason, risk,
                   operation_summary, created_at, expires_at, decided_at,
                   decision_source, scope, exact_digest, integration,
                   environment, database_name, agent_id, tool, reason_code,
                   matched_policy, decided_by
                 ) VALUES (
                   ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                   ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21
                 )",
                params![
                    grant.id.as_str(),
                    grant.scope.session_id,
                    grant.shape.as_str(),
                    grant_status_text(grant.status),
                    grant.message,
                    // Risk and operation summary are daemon display fields
                    // with no authorization role; stored empty for schema
                    // compatibility with readers expecting NOT NULL.
                    "",
                    "",
                    now_ms as i64,
                    grant.expires_at_ms as i64,
                    grant.decided_at_ms.map(|t| t as i64),
                    grant.decided_by.map(|source| source.as_str()),
                    grant.reuse.as_str(),
                    &grant.exact.as_bytes()[..],
                    grant.scope.integration,
                    grant.scope.environment,
                    grant.scope.database,
                    grant.scope.agent_id,
                    grant.scope.tool,
                    grant.reason_code.as_str(),
                    grant.matched_policy,
                    grant.decided_by.map(|source| source.as_str()),
                ],
            )
            .map_err(classify_rusqlite)?;
        debug_assert_eq!(changed, 1);
        Ok(())
    }

    /// Fetch one grant by id. `None` means absent; malformed rows are
    /// `InvalidRow` (explicit, never a live grant).
    pub fn get_grant(&self, id: &str) -> Result<Option<StoredGrant>, StoreError> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare(
                "SELECT id, session_id, fingerprint, status, reason, created_at,
                        expires_at, decided_at, decision_source, scope,
                        exact_digest, integration, environment, database_name,
                        agent_id, tool, reason_code, matched_policy, decided_by
                 FROM approvals WHERE id = ?1",
            )
            .map_err(classify_rusqlite)?;
        let row: Option<GrantRow> = statement
            .query_row([id], GrantRow::read)
            .optional()
            .map_err(classify_rusqlite)?;
        row.map(|row| row.validate()).transpose()
    }

    /// List grants newest-first, flipping lazily-expired rows like the
    /// reference read path (explicit `now_ms`, no clock reads). Invalid
    /// rows are skipped (never grants).
    pub fn list_grants(&self, now_ms: u64) -> Result<Vec<StoredGrant>, StoreError> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare(
                "SELECT id, session_id, fingerprint, status, reason, created_at,
                        expires_at, decided_at, decision_source, scope,
                        exact_digest, integration, environment, database_name,
                        agent_id, tool, reason_code, matched_policy, decided_by
                 FROM approvals ORDER BY created_at DESC",
            )
            .map_err(classify_rusqlite)?;
        let rows = statement
            .query_map([], GrantRow::read)
            .map_err(classify_rusqlite)?;
        let mut grants = Vec::new();
        let mut expired_ids = Vec::new();
        for row in rows {
            let row = row.map_err(classify_rusqlite)?;
            match row.validate() {
                Ok(grant) => {
                    if grant.status == GrantStatus::Waiting && now_ms >= grant.expires_at_ms {
                        expired_ids.push(grant.id.as_str().to_owned());
                    }
                    grants.push(grant);
                }
                Err(StoreError::InvalidRow(_)) => continue,
                Err(error) => return Err(error),
            }
        }
        drop(statement);
        for id in expired_ids {
            conn.execute(
                "UPDATE approvals SET status = 'expired' WHERE id = ?1 AND status = 'waiting'",
                [id],
            )
            .map_err(classify_rusqlite)?;
        }
        Ok(grants)
    }

    /// Record a human decision. Exactly one concurrent decider wins: the
    /// conditional update is atomic under SQLite write serialization, and
    /// losers observe `NotWaiting`/`Expired`/`NotFound` deterministically.
    pub fn decide_grant(
        &self,
        id: &str,
        status: GrantStatus,
        reuse: Scope,
        source: DecisionSource,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        if status == GrantStatus::Waiting {
            return Err(StoreError::Database(
                "cannot transition a grant to waiting".to_owned(),
            ));
        }
        let conn = self.lock()?;
        let changed = conn
            .execute(
                "UPDATE approvals SET status = ?1, decided_at = ?2, decision_source = ?3, scope = ?4
                 WHERE id = ?5 AND status = 'waiting' AND expires_at > ?6",
                params![
                    grant_status_text(status),
                    now_ms as i64,
                    source.as_str(),
                    reuse.as_str(),
                    id,
                    now_ms as i64,
                ],
            )
            .map_err(classify_rusqlite)?;
        if changed == 1 {
            return Ok(());
        }
        // Deterministic loser classification (no timing assumptions).
        let row: Option<GrantRow> = conn
            .prepare("SELECT id, session_id, fingerprint, status, reason, created_at, expires_at, decided_at, decision_source, scope, exact_digest, integration, environment, database_name, agent_id, tool, reason_code, matched_policy, decided_by FROM approvals WHERE id = ?1")
            .map_err(classify_rusqlite)?
            .query_row([id], GrantRow::read)
            .optional()
            .map_err(classify_rusqlite)?;
        match row {
            None => Err(StoreError::NotFound(format!("approval {id}"))),
            Some(row) => {
                let expired = row.expires_at.is_negative() || (row.expires_at as u64) <= now_ms;
                if row.status == "waiting" && expired {
                    Err(StoreError::Expired(format!("approval {id}")))
                } else {
                    Err(StoreError::NotWaiting(format!("approval {id}")))
                }
            }
        }
    }

    /// Find a live session-scoped grant for session, shape, and scope.
    /// SQL prefilters on the indexed status/reuse/session/shape columns
    /// (`reuse` lives in the frozen `scope` column); scope dimensions,
    /// liveness, and row validity are enforced in Rust. Invalid rows are
    /// skipped (never grants).
    pub fn find_session_grant(
        &self,
        session_id: &str,
        shape: &qk_core::QueryShapeFingerprint,
        scope: &qk_approval::ApprovalScope,
        now_ms: u64,
    ) -> Result<Option<StoredGrant>, StoreError> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare(
                "SELECT id, session_id, fingerprint, status, reason, created_at,
                        expires_at, decided_at, decision_source, scope,
                        exact_digest, integration, environment, database_name,
                        agent_id, tool, reason_code, matched_policy, decided_by
                 FROM approvals
                 WHERE status = 'approved' AND scope = 'session'
                   AND session_id = ?1 AND fingerprint = ?2
                 ORDER BY created_at DESC",
            )
            .map_err(classify_rusqlite)?;
        let rows = statement
            .query_map(params![session_id, shape.as_str()], GrantRow::read)
            .map_err(classify_rusqlite)?;
        for row in rows {
            let row = row.map_err(classify_rusqlite)?;
            let grant = match row.validate() {
                Ok(grant) => grant,
                Err(StoreError::InvalidRow(_)) => continue,
                Err(error) => return Err(error),
            };
            if now_ms >= grant.expires_at_ms {
                continue;
            }
            if grant.legacy_shape_only || grant.scope.matches(scope) {
                return Ok(Some(grant));
            }
        }
        Ok(None)
    }

    /// Flip due waiting rows to expired. Returns the flipped count.
    pub fn expire_due(&self, now_ms: u64) -> Result<usize, StoreError> {
        let conn = self.lock()?;
        let changed = conn
            .execute(
                "UPDATE approvals SET status = 'expired'
                 WHERE status = 'waiting' AND expires_at <= ?1",
                [now_ms as i64],
            )
            .map_err(classify_rusqlite)?;
        Ok(changed)
    }

    // ------------------------------------------------------------------
    // Sessions, events, connections.
    // ------------------------------------------------------------------

    /// Insert a session row. Duplicate ids are a `Conflict`.
    pub fn insert_session(&self, session: &SessionRecord) -> Result<(), StoreError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO sessions (id, connection_id, agent, started_at, ended_at, source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                session.id,
                session.connection_id,
                session.agent,
                session.started_at_ms as i64,
                session.ended_at_ms.map(|t| t as i64),
                session.source,
            ],
        )
        .map_err(classify_rusqlite)?;
        Ok(())
    }

    /// Mark a session ended. Missing ids are a silent no-op (reference parity).
    pub fn end_session(&self, id: &str, now_ms: u64) -> Result<(), StoreError> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE sessions SET ended_at = ?1 WHERE id = ?2",
            params![now_ms as i64, id],
        )
        .map_err(classify_rusqlite)?;
        Ok(())
    }

    /// Fetch one session row. Malformed rows are `InvalidRow`.
    pub fn get_session(&self, id: &str) -> Result<Option<SessionRecord>, StoreError> {
        let conn = self.lock()?;
        let row: Option<RawSessionRow> = conn
            .prepare(
                "SELECT id, connection_id, agent, started_at, ended_at, source
                 FROM sessions WHERE id = ?1",
            )
            .map_err(classify_rusqlite)?
            .query_row([id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })
            .optional()
            .map_err(classify_rusqlite)?;
        row.map(|(id, connection_id, agent, started_at, ended_at, source)| {
            Ok(SessionRecord {
                id,
                connection_id,
                agent,
                started_at_ms: as_u64(started_at, "sessions.started_at")?,
                ended_at_ms: as_opt_u64(ended_at, "sessions.ended_at")?,
                source,
            })
        })
        .transpose()
    }

    /// List sessions newest-first. Malformed rows are skipped (display
    /// data, never authorization state).
    pub fn list_sessions(&self) -> Result<Vec<SessionRecord>, StoreError> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare(
                "SELECT id, connection_id, agent, started_at, ended_at, source
                 FROM sessions ORDER BY started_at DESC",
            )
            .map_err(classify_rusqlite)?;
        let rows = statement
            .query_map([], |row| {
                Ok::<_, rusqlite::Error>((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(classify_rusqlite)?;
        let mut sessions = Vec::new();
        for row in rows {
            let Ok((id, connection_id, agent, started_at, ended_at, source)) = row else {
                continue;
            };
            let (Ok(started_at_ms), Ok(ended_at_ms)) = (
                as_u64(started_at, "sessions.started_at"),
                as_opt_u64(ended_at, "sessions.ended_at"),
            ) else {
                continue;
            };
            sessions.push(SessionRecord {
                id,
                connection_id,
                agent,
                started_at_ms,
                ended_at_ms,
                source,
            });
        }
        Ok(sessions)
    }

    /// Record one event and trim past the cap, atomically.
    pub fn record_event(&self, event: &crate::events::SessionEvent) -> Result<(), StoreError> {
        let mut conn = self.lock()?;
        let transaction = conn
            .transaction()
            .map_err(|e| StoreError::Database(trim_debug(e)))?;
        transaction
            .execute(
                "INSERT INTO query_events (
                   id, session_id, connection_id, source, sql_fingerprint, sql,
                   query_class, risk, decision, started_at, duration_ms,
                   rows_returned, rows_affected, bytes_returned,
                   estimated_tokens_returned, estimated_tokens_avoided, error_code
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
                params![
                    event.id,
                    event.session_id,
                    event.connection_id,
                    event.source,
                    event.fingerprint,
                    event.sql,
                    event.query_class,
                    event.risk,
                    event.decision,
                    event.started_at_ms as i64,
                    event.duration_ms.map(|t| t as i64),
                    event.rows_returned,
                    event.rows_affected,
                    event.bytes_returned,
                    event.estimated_tokens_returned,
                    event.estimated_tokens_avoided,
                    event.error_code,
                ],
            )
            .map_err(classify_rusqlite)?;
        if self.event_cap > 0 {
            let count: i64 = transaction
                .query_row("SELECT COUNT(*) FROM query_events", [], |row| row.get(0))
                .map_err(classify_rusqlite)?;
            let extra = count - self.event_cap as i64;
            if extra > 0 {
                transaction
                    .execute(
                        "DELETE FROM query_events WHERE rowid IN (
                           SELECT rowid FROM query_events ORDER BY rowid ASC LIMIT ?1
                         )",
                        [extra],
                    )
                    .map_err(classify_rusqlite)?;
            }
        }
        transaction
            .commit()
            .map_err(|e| StoreError::Database(trim_debug(e)))?;
        Ok(())
    }

    /// List events newest-first with an explicit limit. Malformed rows are
    /// skipped (display data, never authorization state).
    pub fn list_events(&self, limit: usize) -> Result<Vec<EventView>, StoreError> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare(
                "SELECT id, session_id, source, sql_fingerprint, sql, query_class, risk, decision,
                        started_at, rows_returned, rows_affected, bytes_returned, error_code
                 FROM query_events ORDER BY started_at DESC LIMIT ?1",
            )
            .map_err(classify_rusqlite)?;
        let mut rows = statement.query([limit as i64]).map_err(classify_rusqlite)?;
        let mut views = Vec::new();
        while let Some(row) = rows.next().map_err(classify_rusqlite)? {
            match EventView::read(row) {
                Ok(view) => views.push(view),
                Err(StoreError::InvalidRow(_)) => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(views)
    }

    /// List one session's events in chronological order (reference orders
    /// newest-first then reverses).
    pub fn list_session_events(
        &self,
        session_id: &str,
        limit: usize,
    ) -> Result<Vec<EventView>, StoreError> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare(
                "SELECT id, session_id, source, sql_fingerprint, sql, query_class, risk, decision,
                        started_at, rows_returned, rows_affected, bytes_returned, error_code
                 FROM query_events WHERE session_id = ?1
                 ORDER BY started_at DESC, rowid DESC LIMIT ?2",
            )
            .map_err(classify_rusqlite)?;
        let mut rows = statement
            .query(params![session_id, limit as i64])
            .map_err(classify_rusqlite)?;
        let mut views = Vec::new();
        while let Some(row) = rows.next().map_err(classify_rusqlite)? {
            match EventView::read(row) {
                Ok(view) => views.push(view),
                Err(StoreError::InvalidRow(_)) => continue,
                Err(error) => return Err(error),
            }
        }
        views.reverse();
        Ok(views)
    }

    /// Insert-or-ignore a connection row (race-safe; reference parity for
    /// the stored shape, deterministic under concurrency unlike the
    /// reference SELECT-then-INSERT).
    pub fn upsert_connection(&self, connection: &ConnectionRecord) -> Result<(), StoreError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR IGNORE INTO connections
             (id, name, engine, environment, source, database, host_label)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                connection.id,
                connection.name,
                connection.engine,
                connection.environment,
                connection.source,
                connection.database,
                connection.host_label,
            ],
        )
        .map_err(classify_rusqlite)?;
        Ok(())
    }

    /// Fetch one connection row.
    pub fn get_connection(
        &self,
        id: &str,
    ) -> Result<Option<crate::sessions::ConnectionRecord>, StoreError> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare(
                "SELECT id, name, engine, environment, source, database, host_label
                 FROM connections WHERE id = ?1",
            )
            .map_err(classify_rusqlite)?;
        statement
            .query_row([id], |row| {
                Ok(crate::sessions::ConnectionRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    engine: row.get(2)?,
                    environment: row.get(3)?,
                    source: row.get(4)?,
                    database: row.get(5)?,
                    host_label: row.get(6)?,
                })
            })
            .optional()
            .map_err(classify_rusqlite)
    }
}

fn trim_debug(error: rusqlite::Error) -> String {
    let message = error.to_string();
    if message.len() <= 300 {
        return message;
    }
    message.chars().take(300).collect()
}

/// Raw session row as read from SQLite, before timestamp validation.
type RawSessionRow = (String, String, Option<String>, i64, Option<i64>, String);

fn grant_status_text(status: GrantStatus) -> &'static str {
    match status {
        GrantStatus::Waiting => "waiting",
        GrantStatus::Approved => "approved",
        GrantStatus::Denied => "denied",
    }
}

/// Non-negative epoch milliseconds; negatives are corrupt rows. Errors
/// surface as `InvalidRow` at the call site, never as panics.
pub(crate) fn as_u64(value: i64, what: &str) -> Result<u64, StoreError> {
    u64::try_from(value)
        .map_err(|_| StoreError::InvalidRow(format!("negative timestamp in {what}")))
}

fn as_opt_u64(value: Option<i64>, what: &str) -> Result<Option<u64>, StoreError> {
    value.map(|v| as_u64(v, what)).transpose()
}

// ---------------------------------------------------------------------------
// Row readers. Every persisted authorization row is validated here: bad
// digests, unknown enums, bad timestamps, and missing required fields
// become `InvalidRow`, never live grants.
// ---------------------------------------------------------------------------

/// Raw approval row: all columns nullable at the type level so validation
/// is explicit rather than delegated to rusqlite conversions.
struct GrantRow {
    id: String,
    session_id: Option<String>,
    fingerprint: String,
    status: String,
    reason: String,
    expires_at: i64,
    decided_at: Option<i64>,
    decision_source: Option<String>,
    scope: Option<String>,
    exact_digest: Option<Vec<u8>>,
    integration: Option<String>,
    environment: Option<String>,
    database_name: Option<String>,
    agent_id: Option<String>,
    tool: Option<String>,
    reason_code: Option<String>,
    matched_policy: Option<String>,
    decided_by: Option<String>,
}

impl GrantRow {
    fn read(row: &rusqlite::Row<'_>) -> Result<Self, rusqlite::Error> {
        Ok(Self {
            id: row.get(0)?,
            session_id: row.get(1)?,
            fingerprint: row.get(2)?,
            status: row.get(3)?,
            reason: row.get(4)?,
            expires_at: row.get(6)?,
            decided_at: row.get(7)?,
            decision_source: row.get(8)?,
            scope: row.get(9)?,
            exact_digest: row.get(10)?,
            integration: row.get(11)?,
            environment: row.get(12)?,
            database_name: row.get(13)?,
            agent_id: row.get(14)?,
            tool: row.get(15)?,
            reason_code: row.get(16)?,
            matched_policy: row.get(17)?,
            decided_by: row.get(18)?,
        })
    }

    /// Validate into a typed grant. Legacy rows (missing exact digest or
    /// scope dimensions) validate with `legacy_shape_only` set: they keep
    /// frozen session+shape matching but can never satisfy strict scope
    /// comparison or exact-token replay.
    fn validate(self) -> Result<StoredGrant, StoreError> {
        if self.fingerprint.len() != 16 || !self.fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(StoreError::InvalidRow(format!(
                "approval {}: bad shape fingerprint",
                self.id
            )));
        }
        let exact = match self.exact_digest {
            Some(bytes) => {
                if bytes.len() != 32 {
                    return Err(StoreError::InvalidRow(format!(
                        "approval {}: bad exact digest length {}",
                        self.id,
                        bytes.len()
                    )));
                }
                let mut digest = [0u8; 32];
                digest.copy_from_slice(&bytes);
                Some(ExactRequestDigest::from_bytes(digest))
            }
            None => None,
        };
        let status = match self.status.as_str() {
            "waiting" => GrantStatus::Waiting,
            "approved" => GrantStatus::Approved,
            "denied" => GrantStatus::Denied,
            // Stored `expired` rows predate in-Rust reads; liveness gates
            // them identically through `expires_at_ms`.
            "expired" => GrantStatus::Waiting,
            other => {
                return Err(StoreError::InvalidRow(format!(
                    "approval {}: unknown status {other:?}",
                    self.id
                )));
            }
        };
        let reuse = match self.scope.as_deref() {
            None | Some("once") => Scope::Once,
            Some("session") => Scope::Session,
            Some(other) => {
                return Err(StoreError::InvalidRow(format!(
                    "approval {}: unknown scope {other:?}",
                    self.id
                )));
            }
        };
        let decided_by = match self.decided_by.or(self.decision_source) {
            None => None,
            Some(source) => Some(match source.as_str() {
                "tui" => DecisionSource::Tui,
                "cli" => DecisionSource::Cli,
                "ui" => DecisionSource::Ui,
                "mcp" => DecisionSource::Mcp,
                "policy" => DecisionSource::Policy,
                other => {
                    return Err(StoreError::InvalidRow(format!(
                        "approval {}: unknown decision source {other:?}",
                        self.id
                    )));
                }
            }),
        };
        let reason_code = match self.reason_code {
            None => ReasonCode::RequireApproval,
            Some(code) => parse_reason_code(&code).ok_or_else(|| {
                StoreError::InvalidRow(format!("approval {}: unknown reason {code:?}", self.id))
            })?,
        };
        let legacy_shape_only = exact.is_none()
            || self.integration.is_none()
            || self.environment.is_none()
            || self.database_name.is_none()
            || self.agent_id.is_none()
            || self.tool.is_none();
        Ok(StoredGrant {
            id: ApprovalId::new(self.id),
            shape: QueryShapeFingerprint::new(self.fingerprint),
            exact: exact.unwrap_or_else(ExactRequestDigest::unmatchable),
            legacy_shape_only,
            scope: ApprovalScope {
                session_id: self.session_id,
                integration: self.integration.unwrap_or_default(),
                environment: self.environment.unwrap_or_default(),
                database: self.database_name.unwrap_or_default(),
                agent_id: self.agent_id.unwrap_or_default(),
                tool: self.tool.unwrap_or_default(),
            },
            status,
            reuse,
            expires_at_ms: as_u64(self.expires_at, "approvals.expires_at")?,
            reason_code,
            message: self.reason,
            matched_policy: self.matched_policy,
            decided_at_ms: as_opt_u64(self.decided_at, "approvals.decided_at")?,
            decided_by,
        })
    }
}
