//! SQLite persistence tests: schema, migration, approvals, sessions,
//! events, concurrency, and hostile inputs. Deterministic: fixed
//! timestamps, no sleeps, no wall-clock reads.

use std::path::PathBuf;
use std::sync::Arc;

use qk_approval::{ApprovalId, ApprovalScope, GrantStatus, Scope, StoredGrant};
use qk_core::ReasonCode;
use qk_sql::SqlDialect;
use qk_store::{ConnectionRecord, SessionEvent, SessionRecord, Store, StoreError};

const NOW: u64 = 1_000_000;
const FAR_FUTURE: u64 = 9_999_999_999_999;

fn temp_path(name: &str) -> PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "qk-store-{}-{}-{name}.db",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_file(&path);
    path
}

fn scope() -> ApprovalScope {
    ApprovalScope {
        session_id: Some("session-1".to_owned()),
        integration: "mcp".to_owned(),
        environment: "production".to_owned(),
        database: "main".to_owned(),
        agent_id: "agent-1".to_owned(),
        tool: "db_query".to_owned(),
    }
}

fn grant(id: &str) -> StoredGrant {
    StoredGrant {
        id: ApprovalId::new(id.to_owned()),
        shape: qk_core::sql_fingerprint("DELETE FROM customers WHERE id = 42"),
        exact: qk_core::exact_request_digest(
            SqlDialect::PostgreSql,
            "DELETE FROM customers WHERE id = 42",
        ),
        legacy_shape_only: false,
        scope: scope(),
        status: GrantStatus::Waiting,
        reuse: Scope::Once,
        expires_at_ms: FAR_FUTURE,
        reason_code: ReasonCode::RequireApproval,
        message: "m üñîcode 🎉 message".to_owned(),
        matched_policy: Some("production.main.approval_required[0]".to_owned()),
        decided_at_ms: None,
        decided_by: None,
    }
}

fn session(id: &str) -> SessionRecord {
    SessionRecord {
        id: id.to_owned(),
        connection_id: "qkc_test".to_owned(),
        agent: Some("agent-1".to_owned()),
        started_at_ms: NOW,
        ended_at_ms: None,
        source: "mcp".to_owned(),
    }
}

fn event(id: &str, session_id: &str, started_at_ms: u64) -> SessionEvent {
    SessionEvent {
        id: id.to_owned(),
        session_id: session_id.to_owned(),
        connection_id: "qkc_test".to_owned(),
        source: "mcp".to_owned(),
        fingerprint: "0d2e6c16b5960f15".to_owned(),
        sql: Some("SELECT id FROM t WHERE id = 1 -- héllo".to_owned()),
        query_class: "read".to_owned(),
        risk: "low".to_owned(),
        decision: "allow".to_owned(),
        started_at_ms,
        duration_ms: Some(3),
        rows_returned: Some(10),
        rows_affected: None,
        bytes_returned: Some(256),
        estimated_tokens_returned: Some(64),
        estimated_tokens_avoided: Some(128),
        error_code: None,
    }
}

/// Legacy TypeScript database as the reference leaves it: modern TS
/// schema (with historically added columns), version stamp untouched (0),
/// and no v2 columns. Built with raw SQL, exactly like `bun:sqlite` would.
fn legacy_ts_db(path: &PathBuf, partial: bool) {
    let conn = rusqlite::Connection::open(path).expect("legacy open");
    let schema_ddl = if partial { "" } else { ",\n  schema_ddl TEXT" };
    conn.execute_batch(&format!(
        "CREATE TABLE connections (id TEXT PRIMARY KEY, name TEXT NOT NULL, engine TEXT NOT NULL,
           environment TEXT NOT NULL DEFAULT 'unknown', source TEXT NOT NULL, database TEXT, host_label TEXT);
         CREATE TABLE sessions (id TEXT PRIMARY KEY, connection_id TEXT NOT NULL, agent TEXT,
           started_at INTEGER NOT NULL, ended_at INTEGER, source TEXT NOT NULL);
         CREATE TABLE query_events (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, connection_id TEXT NOT NULL,
           source TEXT NOT NULL, sql_fingerprint TEXT NOT NULL, sql TEXT, query_class TEXT NOT NULL,
           risk TEXT NOT NULL, decision TEXT NOT NULL, started_at INTEGER NOT NULL, duration_ms INTEGER,
           rows_returned INTEGER, rows_affected INTEGER, bytes_returned INTEGER,
           estimated_tokens_returned INTEGER, estimated_tokens_avoided INTEGER, error_code TEXT);
         CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
         CREATE TABLE approvals (id TEXT PRIMARY KEY, session_id TEXT, connection_id TEXT,
           fingerprint TEXT NOT NULL, status TEXT NOT NULL, reason TEXT NOT NULL, risk TEXT NOT NULL,
           operation_summary TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
           decided_at INTEGER, decision_source TEXT, scope TEXT{schema_ddl}, schema_diff TEXT);
         CREATE TABLE session_allows (session_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
           PRIMARY KEY (session_id, fingerprint));"
    ))
    .expect("legacy ddl");
    // Waiting legacy approval (no v2 columns).
    conn.execute(
        "INSERT INTO approvals (id, session_id, fingerprint, status, reason, risk,
           operation_summary, created_at, expires_at)
         VALUES ('qka_legacy1', 'session-1', '0d2e6c16b5960f15', 'waiting',
           'write/high', 'high', 'delete customers', 1000, 9999999999999)",
        [],
    )
    .expect("legacy waiting");
    // Approved session approval (frozen session-shape semantics).
    conn.execute(
        "INSERT INTO approvals (id, session_id, fingerprint, status, reason, risk,
           operation_summary, created_at, expires_at, decided_at, decision_source, scope)
         VALUES ('qka_legacy2', 'session-1', '0d2e6c16b5960f15', 'approved',
           'write/high', 'high', 'delete customers', 1000, 9999999999999, 2000, 'cli', 'session')",
        [],
    )
    .expect("legacy approved");
    // Expired waiting row.
    conn.execute(
        "INSERT INTO approvals (id, fingerprint, status, reason, risk,
           operation_summary, created_at, expires_at)
         VALUES ('qka_legacy3', '0d2e6c16b5960f15', 'waiting',
           'write/high', 'high', 'delete customers', 1000, 1000)",
        [],
    )
    .expect("legacy expired");
    // Orphan session grant (no matching approvals row).
    conn.execute(
        "INSERT INTO session_allows (session_id, fingerprint) VALUES ('s-orphan', 'aaaaaaaaaaaaaaaa')",
        [],
    )
    .expect("orphan");
    // Covered session grant (matching approvals row exists).
    conn.execute(
        "INSERT INTO session_allows (session_id, fingerprint) VALUES ('session-1', '0d2e6c16b5960f15')",
        [],
    )
    .expect("covered");
    // History rows.
    conn.execute(
        "INSERT INTO sessions (id, connection_id, agent, started_at, source)
         VALUES ('qks_legacy', 'qkc_test', 'agent-1', 1000, 'mcp')",
        [],
    )
    .expect("legacy session");
    conn.execute(
        "INSERT INTO query_events (id, session_id, connection_id, source, sql_fingerprint,
           query_class, risk, decision, started_at)
         VALUES ('qke_legacy', 'qks_legacy', 'qkc_test', 'mcp', '0d2e6c16b5960f15',
           'read', 'low', 'allow', 1000)",
        [],
    )
    .expect("legacy event");
}

// ---------------------------------------------------------------------------
// Schema / migration.
// ---------------------------------------------------------------------------

#[test]
fn fresh_db_creation() {
    let path = temp_path("fresh");
    let store = Store::open(&path).expect("open");
    assert_eq!(
        store.schema_version().expect("version"),
        qk_store::SCHEMA_VERSION
    );
    assert!(path.exists());
    // WAL journal mode on file databases (reference parity).
    let mode: String = {
        let conn = rusqlite::Connection::open(&path).expect("reopen");
        conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("pragma")
    };
    assert_eq!(mode.to_lowercase(), "wal");
}

#[test]
fn reopen_existing_is_stable() {
    let path = temp_path("reopen");
    {
        let store = Store::open(&path).expect("open");
        store.insert_grant(&grant("qka-1"), NOW).expect("insert");
    }
    let store = Store::open(&path).expect("reopen");
    assert_eq!(
        store.schema_version().expect("version"),
        qk_store::SCHEMA_VERSION
    );
    assert!(store.get_grant("qka-1").expect("get").is_some());
    // Re-migration is a no-op.
    let store = Store::open(&path).expect("reopen again");
    assert!(store.get_grant("qka-1").expect("get").is_some());
}

#[test]
fn migrate_legacy_ts_schema() {
    let path = temp_path("legacy");
    legacy_ts_db(&path, false);
    let store = Store::open(&path).expect("open legacy");
    assert_eq!(
        store.schema_version().expect("version"),
        qk_store::SCHEMA_VERSION
    );
    // Legacy waiting row reads with the legacy flag (no exact, no dims).
    let waiting = store.get_grant("qka_legacy1").expect("get").expect("row");
    assert_eq!(waiting.status, GrantStatus::Waiting);
    assert!(waiting.legacy_shape_only);
    assert_eq!(waiting.matched_policy, None);
    // Legacy session row keeps frozen shape semantics.
    let session = store.get_grant("qka_legacy2").expect("get").expect("row");
    assert_eq!(session.status, GrantStatus::Approved);
    assert_eq!(session.reuse, Scope::Session);
    // Expired legacy row reads (liveness gates it out of matching).
    let expired = store.get_grant("qka_legacy3").expect("get").expect("row");
    assert_eq!(expired.status, GrantStatus::Waiting);
    // Legacy history rows read back.
    let loaded = store
        .get_session("qks_legacy")
        .expect("get")
        .expect("session");
    assert_eq!(loaded.started_at_ms, 1000);
    let events = store
        .list_session_events("qks_legacy", 100)
        .expect("events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, "qke_legacy");
    // Orphan session grant was adopted as a synthetic approved session row
    // carrying the legacy fingerprint verbatim.
    let grants = store.list_grants(NOW).expect("list");
    let adopted = grants.iter().find(|g| g.id.as_str().starts_with("qkam-"));
    assert!(adopted.is_some(), "orphan must be adopted");
    assert_eq!(adopted.expect("grant").shape.as_str(), "aaaaaaaaaaaaaaaa");
}

fn legacy_scope() -> qk_approval::ApprovalScope {
    qk_approval::ApprovalScope {
        session_id: Some("s-orphan".to_owned()),
        integration: String::new(),
        environment: String::new(),
        database: String::new(),
        agent_id: String::new(),
        tool: String::new(),
    }
}

#[test]
fn orphan_session_grant_adopted() {
    let path = temp_path("orphan");
    legacy_ts_db(&path, false);
    let store = Store::open(&path).expect("open");
    // The orphan (session s-orphan, stored shape aaaa...) resolves by
    // shape even with empty scope dimensions: legacy rows skip dim
    // comparison.
    let shape = qk_core::QueryShapeFingerprint::new("aaaaaaaaaaaaaaaa".to_owned());
    let found = store
        .find_session_grant("s-orphan", &shape, &legacy_scope(), NOW)
        .expect("lookup");
    assert!(found.is_some(), "orphan must be adopted as session grant");
    let found = found.expect("grant");
    assert_eq!(found.status, GrantStatus::Approved);
    assert!(found.legacy_shape_only);
    // Idempotent: reopening does not duplicate the synthetic row.
    drop(store);
    let store = Store::open(&path).expect("reopen");
    let grants = store.list_grants(NOW).expect("list");
    assert_eq!(
        grants
            .iter()
            .filter(|g| g.id.as_str().starts_with("qkam-"))
            .count(),
        1
    );
}

#[test]
fn partial_ts_schema_repaired() {
    let path = temp_path("partial");
    legacy_ts_db(&path, true);
    let store = Store::open(&path).expect("open partial");
    assert_eq!(
        store.schema_version().expect("version"),
        qk_store::SCHEMA_VERSION
    );
    // v1 columns backfilled, v2 columns present, data intact.
    assert!(store.get_grant("qka_legacy1").expect("get").is_some());
}

#[test]
fn corrupt_and_incompatible_rejected() {
    let garbage = temp_path("garbage");
    std::fs::write(&garbage, b"definitely not sqlite").expect("write");
    let error = Store::open(&garbage).expect_err("must fail");
    assert!(matches!(
        error,
        StoreError::Open(_) | StoreError::Migration(_)
    ));
    let versioned = temp_path("future");
    {
        let conn = rusqlite::Connection::open(&versioned).expect("open");
        conn.execute_batch("PRAGMA user_version = 99")
            .expect("stamp");
    }
    let error = Store::open(&versioned).expect_err("must refuse");
    assert!(matches!(error, StoreError::SchemaMismatch(_)), "{error:?}");
    // Zero-byte file is a valid empty database.
    let empty = temp_path("empty");
    std::fs::write(&empty, b"").expect("write");
    let store = Store::open(&empty).expect("open empty");
    assert_eq!(
        store.schema_version().expect("version"),
        qk_store::SCHEMA_VERSION
    );
}

#[test]
fn nested_state_dir_created() {
    let dir = std::env::temp_dir().join(format!(
        "qk-store-nested-{}-{}",
        std::process::id(),
        "nested"
    ));
    let path = dir.join("deep").join("state.db");
    let _ = std::fs::remove_dir_all(&dir);
    let store = Store::open(&path).expect("open nested");
    assert_eq!(
        store.schema_version().expect("version"),
        qk_store::SCHEMA_VERSION
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Approval round-trips and state machine.
// ---------------------------------------------------------------------------

#[test]
fn grant_round_trip_all_fields() {
    let store = Store::open_in_memory().expect("memory");
    let mut full = grant("qka-full");
    full.status = GrantStatus::Approved;
    full.reuse = Scope::Session;
    full.decided_at_ms = Some(NOW);
    full.decided_by = Some(qk_approval::DecisionSource::Mcp);
    store.insert_grant(&full, NOW).expect("insert");
    let back = store.get_grant("qka-full").expect("get").expect("row");
    assert_eq!(back, full);
    assert!(!back.legacy_shape_only);
}

#[test]
fn duplicate_id_is_conflict() {
    let store = Store::open_in_memory().expect("memory");
    store.insert_grant(&grant("qka-dup"), NOW).expect("insert");
    let error = store
        .insert_grant(&grant("qka-dup"), NOW)
        .expect_err("duplicate");
    assert!(matches!(error, StoreError::Conflict(_)), "{error:?}");
}

#[test]
fn decide_transitions() {
    let store = Store::open_in_memory().expect("memory");
    store.insert_grant(&grant("qka-d"), NOW).expect("insert");
    // Unknown id.
    assert_eq!(
        store.decide_grant(
            "qka-nope",
            GrantStatus::Approved,
            Scope::Once,
            qk_approval::DecisionSource::Cli,
            NOW
        ),
        Err(StoreError::NotFound("approval qka-nope".to_owned()))
    );
    // Invalid target state.
    assert!(matches!(
        store.decide_grant(
            "qka-d",
            GrantStatus::Waiting,
            Scope::Once,
            qk_approval::DecisionSource::Cli,
            NOW
        ),
        Err(StoreError::Database(_))
    ));
    // Approved once.
    store
        .decide_grant(
            "qka-d",
            GrantStatus::Approved,
            Scope::Session,
            qk_approval::DecisionSource::Ui,
            NOW,
        )
        .expect("decide");
    let back = store.get_grant("qka-d").expect("get").expect("row");
    assert_eq!(back.status, GrantStatus::Approved);
    assert_eq!(back.reuse, Scope::Session);
    assert_eq!(back.decided_at_ms, Some(NOW));
    // Decided rows reject further decisions.
    assert_eq!(
        store.decide_grant(
            "qka-d",
            GrantStatus::Denied,
            Scope::Once,
            qk_approval::DecisionSource::Cli,
            NOW
        ),
        Err(StoreError::NotWaiting("approval qka-d".to_owned()))
    );
    // Denied path on a fresh row.
    store.insert_grant(&grant("qka-e"), NOW).expect("insert");
    store
        .decide_grant(
            "qka-e",
            GrantStatus::Denied,
            Scope::Once,
            qk_approval::DecisionSource::Mcp,
            NOW,
        )
        .expect("deny");
    assert_eq!(
        store.get_grant("qka-e").expect("get").expect("row").status,
        GrantStatus::Denied
    );
}

#[test]
fn expiry_boundaries() {
    let store = Store::open_in_memory().expect("memory");
    let mut expiring = grant("qka-x");
    expiring.expires_at_ms = 1000;
    store.insert_grant(&expiring, NOW).expect("insert");
    // now == expires_at is expired (reference boundary).
    assert_eq!(
        store.decide_grant(
            "qka-x",
            GrantStatus::Approved,
            Scope::Once,
            qk_approval::DecisionSource::Cli,
            1000
        ),
        Err(StoreError::Expired("approval qka-x".to_owned()))
    );
    assert_eq!(store.expire_due(999).expect("expire"), 0);
    assert_eq!(store.expire_due(1000).expect("expire"), 1);
    let back = store.get_grant("qka-x").expect("get").expect("row");
    assert_eq!(back.status, GrantStatus::Waiting, "flip is persisted");
    // Session lookup excludes the expired row.
    assert!(store
        .find_session_grant("session-1", &back.shape, &scope(), 1000)
        .expect("lookup")
        .is_none());
}

#[test]
fn concurrent_decide_single_winner() {
    use std::sync::Barrier;
    let store = std::sync::Arc::new(Store::open_in_memory().expect("memory"));
    store.insert_grant(&grant("qka-race"), NOW).expect("insert");
    let barrier = Arc::new(Barrier::new(2));
    // Spawn everything first: joining inline would serialize the spawns
    // and deadlock the barrier (lazy iterators).
    let handles: Vec<_> = [GrantStatus::Approved, GrantStatus::Denied]
        .into_iter()
        .map(|status| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store.decide_grant(
                    "qka-race",
                    status,
                    Scope::Once,
                    qk_approval::DecisionSource::Cli,
                    NOW,
                )
            })
        })
        .collect();
    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread"))
        .collect();
    let wins = outcomes.iter().filter(|r| r.is_ok()).count();
    assert_eq!(wins, 1, "exactly one decider wins: {outcomes:?}");
    let final_status = store
        .get_grant("qka-race")
        .expect("get")
        .expect("row")
        .status;
    assert!(
        final_status == GrantStatus::Approved || final_status == GrantStatus::Denied,
        "{final_status:?}"
    );
}

#[test]
fn busy_lock_is_typed() {
    let path = temp_path("busy");
    let store = Store::open(&path).expect("open");
    store.insert_grant(&grant("qka-b"), NOW).expect("insert");
    // A second connection holds a write lock.
    let holder = rusqlite::Connection::open(&path).expect("second connection");
    holder.execute_batch("BEGIN IMMEDIATE").expect("lock");
    store
        .set_busy_timeout(std::time::Duration::from_millis(50))
        .expect("timeout");
    let error = store
        .insert_grant(&grant("qka-c"), NOW)
        .expect_err("must be busy");
    assert!(matches!(error, StoreError::Busy(_)), "{error:?}");
    holder.execute_batch("COMMIT").expect("release");
    store
        .set_busy_timeout(std::time::Duration::from_millis(5000))
        .expect("timeout");
    store
        .insert_grant(&grant("qka-c"), NOW)
        .expect("insert after release");
}

// ---------------------------------------------------------------------------
// Invalid rows fail closed.
// ---------------------------------------------------------------------------

fn corrupt_approvals(path: &std::path::Path, id: &str, set: &str) {
    let conn = rusqlite::Connection::open(path).expect("raw open");
    conn.execute(&format!("UPDATE approvals SET {set} WHERE id = '{id}'"), [])
        .expect("corrupt");
}

#[test]
fn invalid_rows_never_authorize() {
    let path = temp_path("invalid");
    let store = Store::open(&path).expect("open");
    store.insert_grant(&grant("qka-ok"), NOW).expect("insert");
    // Unknown status / scope / source / reason.
    corrupt_approvals(&path, "qka-ok", "status = 'weird'");
    assert!(matches!(
        store.get_grant("qka-ok"),
        Err(StoreError::InvalidRow(_))
    ));
    corrupt_approvals(&path, "qka-ok", "status = 'approved', scope = 'forever'");
    assert!(matches!(
        store.get_grant("qka-ok"),
        Err(StoreError::InvalidRow(_))
    ));
    corrupt_approvals(
        &path,
        "qka-ok",
        "status = 'approved', scope = 'session', decided_by = 'pigeon'",
    );
    assert!(matches!(
        store.get_grant("qka-ok"),
        Err(StoreError::InvalidRow(_))
    ));
    corrupt_approvals(
        &path,
        "qka-ok",
        "status = 'approved', scope = 'session', decided_by = NULL, reason_code = 'BOGUS'",
    );
    assert!(matches!(
        store.get_grant("qka-ok"),
        Err(StoreError::InvalidRow(_))
    ));
    // Bad digests: short blob, non-hex fingerprint, negative expiry.
    corrupt_approvals(&path, "qka-ok", "status = 'approved', scope = 'session', decided_by = NULL, reason_code = NULL, exact_digest = X'00'");
    assert!(matches!(
        store.get_grant("qka-ok"),
        Err(StoreError::InvalidRow(_))
    ));
    corrupt_approvals(
        &path,
        "qka-ok",
        "exact_digest = NULL, fingerprint = 'short'",
    );
    assert!(matches!(
        store.get_grant("qka-ok"),
        Err(StoreError::InvalidRow(_))
    ));
    corrupt_approvals(
        &path,
        "qka-ok",
        "fingerprint = '0d2e6c16b5960f15', expires_at = -5",
    );
    assert!(matches!(
        store.get_grant("qka-ok"),
        Err(StoreError::InvalidRow(_))
    ));
    // Listings skip (never surface) invalid rows instead of failing.
    let listed = store.list_grants(NOW).expect("list");
    assert!(listed.iter().all(|g| g.id.as_str() != "qka-ok"));
}

// ---------------------------------------------------------------------------
// Sessions, events, connections.
// ---------------------------------------------------------------------------

#[test]
fn session_event_round_trip_and_ordering() {
    let mut store = Store::open_in_memory().expect("memory");
    store.set_event_cap(3);
    store
        .upsert_connection(&ConnectionRecord {
            id: "qkc_test".to_owned(),
            name: "test".to_owned(),
            engine: "postgres".to_owned(),
            environment: "production".to_owned(),
            source: "manual".to_owned(),
            database: Some("main Ünïcode 🎉".to_owned()),
            host_label: None,
        })
        .expect("upsert");
    // Upsert is idempotent and keeps the first row.
    store
        .upsert_connection(&ConnectionRecord {
            id: "qkc_test".to_owned(),
            name: "changed".to_owned(),
            engine: "postgres".to_owned(),
            environment: "production".to_owned(),
            source: "manual".to_owned(),
            database: None,
            host_label: None,
        })
        .expect("upsert again");
    let conn = store.get_connection("qkc_test").expect("get").expect("row");
    assert_eq!(conn.name, "test");
    assert_eq!(conn.database.as_deref(), Some("main Ünïcode 🎉"));
    assert!(store.get_connection("missing").expect("get").is_none());

    store.insert_session(&session("qks-1")).expect("session");
    assert!(store.get_session("qks-1").expect("get").is_some());
    assert!(store.get_session("missing").expect("get").is_none());
    for (i, id) in ["qke-1", "qke-2", "qke-3", "qke-4", "qke-5"]
        .iter()
        .enumerate()
    {
        store
            .record_event(&event(id, "qks-1", NOW + i as u64))
            .expect("record");
    }
    // Cap trims oldest first (reference behavior).
    let events = store.list_events(100).expect("list");
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].id, "qke-5");
    // Per-session listing returns chronological order.
    let session_events = store
        .list_session_events("qks-1", 100)
        .expect("session events");
    assert_eq!(session_events.len(), 3);
    assert_eq!(session_events[0].id, "qke-3");
    assert_eq!(session_events[2].id, "qke-5");
    assert_eq!(
        session_events[0].sql.as_deref(),
        Some("SELECT id FROM t WHERE id = 1 -- héllo")
    );
    // Limit respected.
    assert_eq!(store.list_events(1).expect("list").len(), 1);
    // End session; missing end is a silent no-op (reference parity).
    store.end_session("qks-1", NOW + 100).expect("end");
    assert_eq!(
        store
            .get_session("qks-1")
            .expect("get")
            .expect("row")
            .ended_at_ms,
        Some(NOW + 100)
    );
    store.end_session("missing", NOW).expect("silent");
    // Duplicate session/event ids conflict.
    assert!(matches!(
        store.insert_session(&session("qks-1")),
        Err(StoreError::Conflict(_))
    ));
    assert!(matches!(
        store.record_event(&event("qke-5", "qks-1", NOW)),
        Err(StoreError::Conflict(_))
    ));
}

#[test]
fn unicode_event_round_trip() {
    let store = Store::open_in_memory().expect("memory");
    store.insert_session(&session("qks-u")).expect("session");
    let mut unicode = event("qke-u", "qks-u", NOW);
    unicode.sql = Some("SELECT 'üñîcodé 🎉' FROM tâble WHERE x = '日本語'".to_owned());
    unicode.error_code = Some("érrör-🎉".to_owned());
    store.record_event(&unicode).expect("record");
    let back = store.list_session_events("qks-u", 10).expect("list");
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].sql, unicode.sql);
    assert_eq!(back[0].error_code, unicode.error_code);
}
