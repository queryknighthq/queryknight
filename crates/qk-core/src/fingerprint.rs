//! Query fingerprinting: stable identity for literal-stripped SQL.
//!
//! Exact port of the reference algorithm: string literals (with `''`
//! escapes; backslash is literal, matching the oracle) and double-quoted
//! spans collapse to `?`, bare numbers collapse to `?`, whitespace
//! collapses to single spaces, the result lowercases, and the fingerprint
//! is the first 16 hex characters of its SHA-256. Session grants and
//! approval retries bind on this value: same normalized shape replays,
//! `DELETE 42` never replays as `DELETE 43`.

use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

static SINGLE_QUOTED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"'([^']|'')*'").expect("static pattern"));
static DOUBLE_QUOTED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""([^"]|"")*""#).expect("static pattern"));
// ASCII digits with ASCII boundaries (the oracle's `\b\d+\b` is ASCII-only).
static BARE_NUMBER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u:\b[0-9]+\b)").expect("static pattern"));
static WHITESPACE_RUN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\s+").expect("static pattern"));

/// Strip literals and normalize case/spacing. Deterministic; secrets in
/// literals collapse to `?`, which is why fingerprints are log-safe.
#[must_use]
pub fn normalize_sql(sql: &str) -> String {
    let step = SINGLE_QUOTED.replace_all(sql, "?");
    let step = DOUBLE_QUOTED.replace_all(&step, "?");
    let step = BARE_NUMBER.replace_all(&step, "?");
    WHITESPACE_RUN.replace_all(&step, " ").trim().to_lowercase()
}

/// Stable 16-hex-digit identity of normalized SQL.
#[must_use]
pub fn sql_fingerprint(sql: &str) -> String {
    let digest = Sha256::digest(normalize_sql(sql).as_bytes());
    format!("{digest:x}")[..16].to_owned()
}

#[cfg(test)]
mod tests {
    use super::{normalize_sql, sql_fingerprint};

    /// Vectors captured from the TypeScript oracle (2026-09-28).
    #[test]
    fn oracle_vectors() {
        assert_eq!(sql_fingerprint(""), "e3b0c44298fc1c14");
        assert_eq!(
            sql_fingerprint("SELECT id, name FROM customers WHERE id = 42"),
            "0d2e6c16b5960f15"
        );
        assert_eq!(
            sql_fingerprint("select ID, NAME from CUSTOMERS where ID=42"),
            "7224d28fa38c2f43"
        );
        assert_eq!(
            sql_fingerprint("UPDATE customers SET status = 'inactive' WHERE id = 7"),
            "c1f1acc27c59f39a"
        );
        assert_eq!(sql_fingerprint("DELETE FROM t"), "40ae96f50fcb7473");
        assert_eq!(sql_fingerprint("SELECT 'it''s'"), "e1c71d1661ae46e0");
    }

    #[test]
    fn literals_and_case_collapse() {
        assert_eq!(
            normalize_sql("SELECT id, name FROM customers WHERE id = 42"),
            "select id, name from customers where id = ?"
        );
        // Same shape, different literals: identical fingerprint.
        assert_eq!(
            sql_fingerprint("DELETE FROM customers WHERE id = 42"),
            sql_fingerprint("DELETE FROM customers WHERE id = 43")
        );
        // Different shape: different fingerprint.
        assert_ne!(
            sql_fingerprint("DELETE FROM customers WHERE id = 42"),
            sql_fingerprint("DELETE FROM orders WHERE id = 42")
        );
    }
}
