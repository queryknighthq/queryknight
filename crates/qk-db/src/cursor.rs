//! In-memory pagination cursors. Server-side state (never persisted):
//! id `qk_cur_<12 base64url chars from 9 random bytes>`, TTL 10 min,
//! swept on access, bound to the issuing connection key. Cursor paging
//! re-resolves stored SQL which the service EVALUATES again before
//! executing. Malformed cursors fail typed (no panic, no unbounded
//! allocation); offsets are validated `u64`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::{DbError, DbErrorKind};

/// Cursor time-to-live (frozen 10 minutes).
pub const CURSOR_TTL: Duration = Duration::from_secs(10 * 60);

/// A stored pagination position.
#[derive(Debug, Clone)]
pub struct StoredCursor {
    /// SQL text to re-evaluate and continue.
    pub sql: String,
    /// Bound parameters, if any.
    pub params: Vec<serde_json::Value>,
    /// Row offset to continue from.
    pub offset: u64,
    /// Connection key the cursor is bound to.
    pub connection_key: String,
}

/// Thread-safe cursor registry. One instance per service (or per
/// test); entries expire by TTL and are swept on every access.
#[derive(Debug, Default)]
pub struct CursorStore {
    inner: Mutex<HashMap<String, (StoredCursor, Instant)>>,
}

impl CursorStore {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a cursor id for stored state. Format
    /// `qk_cur_<12 base64url chars>` (frozen).
    pub fn issue(
        &self,
        sql: String,
        params: Vec<serde_json::Value>,
        offset: u64,
        connection_key: String,
    ) -> String {
        let mut bytes = [0u8; 9];
        getrandom::fill(&mut bytes).expect("system randomness available");
        use base64::Engine as _;
        let id = format!(
            "qk_cur_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        );
        let mut map = self.inner.lock().expect("cursor lock");
        let now = Instant::now();
        map.retain(|_, (_, expires)| *expires > now);
        map.insert(
            id.clone(),
            (
                StoredCursor {
                    sql,
                    params,
                    offset,
                    connection_key,
                },
                now + CURSOR_TTL,
            ),
        );
        id
    }

    /// Resolve a cursor for a connection. Unknown/expired ids and
    /// cross-connection use are typed errors (never panics).
    pub fn read(&self, id: &str, connection_key: &str) -> Result<StoredCursor, DbError> {
        let mut map = self.inner.lock().expect("cursor lock");
        let now = Instant::now();
        map.retain(|_, (_, expires)| *expires > now);
        match map.get(id) {
            None => Err(DbError::new(
                DbErrorKind::Query,
                "unknown or expired cursor",
            )),
            Some((cursor, _)) if cursor.connection_key != connection_key => Err(DbError::new(
                DbErrorKind::Query,
                "cursor is bound to another connection",
            )),
            Some((cursor, _)) => Ok(cursor.clone()),
        }
    }

    /// Entry count (test hook for expiry behavior).
    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().expect("cursor lock").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_read_binding() {
        let store = CursorStore::new();
        let id = store.issue("SELECT 1".to_owned(), vec![], 50, "conn-a".to_owned());
        assert!(id.starts_with("qk_cur_"));
        assert_eq!(id.len(), "qk_cur_".len() + 12);
        let cursor = store.read(&id, "conn-a").expect("read");
        assert_eq!(cursor.sql, "SELECT 1");
        assert_eq!(cursor.offset, 50);
        assert_eq!(store.len(), 1);
        assert!(store.read(&id, "conn-b").is_err());
        assert!(store.read("qk_cur_nope", "conn-a").is_err());
        assert_ne!(
            store.issue("SELECT 2".to_owned(), vec![], 0, "c".to_owned()),
            id
        );
    }
}
