//! Frozen result budgets: `maxRows = 50`, `maxBytes = 65536`
//! (serialized JSON bytes of row arrays), `maxEstimatedTokens = 8000`
//! (`ceil(bytes / 4)` heuristic). Semantics mirror `clipRows` exactly:
//! row cap first, then byte/token caps, first row exempt, cuts flagged.

use crate::value::DbValue;

/// Frozen page/preview row cap.
pub const MAX_ROWS: usize = 50;
/// Frozen serialized-bytes cap.
pub const MAX_BYTES: usize = 64 * 1024;
/// Frozen token-estimate cap (heuristic units).
pub const MAX_TOKENS: usize = 8000;
/// Frozen parameter count cap (`MAX_QUERY_PARAMS`).
pub const MAX_PARAMS: usize = 1000;

/// Budget triple (rows, bytes, token estimates).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultBudget {
    /// Maximum rows kept.
    pub max_rows: usize,
    /// Maximum serialized JSON bytes kept.
    pub max_bytes: usize,
    /// Maximum estimated tokens.
    pub max_tokens: usize,
}

impl Default for ResultBudget {
    fn default() -> Self {
        Self {
            max_rows: MAX_ROWS,
            max_bytes: MAX_BYTES,
            max_tokens: MAX_TOKENS,
        }
    }
}

/// Rough heuristic (~4 bytes/token). Estimates only — never presented
/// as exact model accounting.
pub fn estimate_tokens(bytes: usize) -> usize {
    bytes.div_ceil(4)
}

/// Serialized JSON byte weight of one row array (frozen `rowBytes`).
pub fn row_bytes(row: &[DbValue]) -> usize {
    serde_json::to_string(row)
        .map(|text| text.len())
        .unwrap_or(0)
}

/// Clip rows to a budget. Returns kept rows, accumulated bytes, token
/// estimate, and whether any cut occurred. The first row is exempt from
/// byte/token caps (a query always shows something).
pub fn clip_rows(
    rows: Vec<Vec<DbValue>>,
    budget: ResultBudget,
) -> (Vec<Vec<DbValue>>, usize, usize, bool) {
    let mut kept = Vec::new();
    let mut bytes = 0usize;
    for row in rows {
        if kept.len() >= budget.max_rows {
            return (kept, bytes, estimate_tokens(bytes), true);
        }
        let next = row_bytes(&row);
        if !kept.is_empty()
            && (bytes + next > budget.max_bytes
                || estimate_tokens(bytes + next) > budget.max_tokens)
        {
            return (kept, bytes, estimate_tokens(bytes), true);
        }
        kept.push(row);
        bytes += next;
    }
    let tokens = estimate_tokens(bytes);
    (kept, bytes, tokens, false)
}

/// SELECT detection for paging (`/^\s*select\b/i`, frozen).
pub fn is_select(sql: &str) -> bool {
    let trimmed = sql.trim_start();
    trimmed.len() >= 6
        && trimmed[..6].eq_ignore_ascii_case("select")
        && trimmed[6..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric() && c != '_')
}

/// Append `LIMIT/OFFSET` paging to a limit-less SELECT. Frozen quirk:
/// any `/\blimit\b/i` match (even inside strings or comments) disables
/// the rewrite.
pub fn with_page(sql: &str, limit: usize, offset: u64) -> String {
    if !is_select(sql) || has_limit(sql) {
        return sql.to_owned();
    }
    format!("{sql} LIMIT {limit} OFFSET {offset}")
}

/// Word-boundary `limit` scan (frozen `/\blimit\b/i`).
fn has_limit(sql: &str) -> bool {
    let bytes = sql.to_ascii_lowercase();
    let bytes = bytes.as_bytes();
    let mut i = 0;
    while i + 5 <= bytes.len() {
        if &bytes[i..i + 5] == b"limit"
            && (i == 0 || !is_word_byte(bytes[i - 1]))
            && (i + 5 >= bytes.len() || !is_word_byte(bytes[i + 5]))
        {
            return true;
        }
        i += 1;
    }
    false
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Strip trailing semicolons and surrounding whitespace (frozen).
pub fn trim_trailing_semicolons(sql: &str) -> String {
    let mut out = sql.trim().to_owned();
    while out.ends_with(';') {
        out.pop();
        out = out.trim_end().to_owned();
    }
    out
}

/// True when more than one statement remains after trimming (frozen
/// `multi` check: any interior `;`).
pub fn is_multi_statement(sql: &str) -> bool {
    trim_trailing_semicolons(sql).contains(';')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_detection() {
        assert!(is_select("SELECT 1"));
        assert!(is_select("  select a from t"));
        assert!(is_select("SELECTION".strip_suffix("ION").unwrap_or("")));
        assert!(!is_select("SELECTED 1"));
        assert!(!is_select("WITH x AS (...) SELECT 1"));
        assert!(!is_select("UPDATE t SET a = 1"));
    }

    #[test]
    fn paging_rewrite() {
        assert_eq!(
            with_page("SELECT * FROM t", 51, 0),
            "SELECT * FROM t LIMIT 51 OFFSET 0"
        );
        // Existing LIMIT disables the rewrite (frozen).
        assert_eq!(
            with_page("SELECT * FROM t LIMIT 5", 51, 0),
            "SELECT * FROM t LIMIT 5"
        );
        assert_eq!(with_page("UPDATE t SET a = 1", 51, 0), "UPDATE t SET a = 1");
    }

    #[test]
    fn clipping_precedence() {
        // Row cap wins.
        let rows = vec![vec![DbValue::Int(1)]; MAX_ROWS + 5];
        let (kept, _, _, truncated) = clip_rows(rows, ResultBudget::default());
        assert_eq!(kept.len(), MAX_ROWS);
        assert!(truncated);
        // First row exempt from byte caps.
        let big = vec![DbValue::Text("x".repeat(MAX_BYTES + 1))];
        let (kept, _, _, truncated) = clip_rows(
            vec![big],
            ResultBudget {
                max_bytes: 10,
                ..ResultBudget::default()
            },
        );
        assert_eq!(kept.len(), 1);
        assert!(!truncated);
        // Second row trips the byte cap.
        let rows = vec![
            vec![DbValue::Text("a".repeat(100))],
            vec![DbValue::Text("b".repeat(100))],
        ];
        let (kept, _, _, truncated) = clip_rows(
            rows,
            ResultBudget {
                max_bytes: 150,
                ..ResultBudget::default()
            },
        );
        assert_eq!(kept.len(), 1);
        assert!(truncated);
    }

    #[test]
    fn token_heuristic() {
        assert_eq!(estimate_tokens(0), 0);
        assert_eq!(estimate_tokens(4), 1);
        assert_eq!(estimate_tokens(5), 2);
        assert_eq!(estimate_tokens(8000 * 4), 8000);
    }
}
