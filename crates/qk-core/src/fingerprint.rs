//! SQL identity in two strengths.
//!
//! `QueryShapeFingerprint` is the frozen compatibility identity: literals
//! abstract away, so one approval shape covers literal variants within a
//! session. `ExactRequestDigest` is the security binding: full-strength
//! SHA-256 over the exact request, so changing a literal changes identity.
//! The two types are incompatible by construction: `fingerprint == digest`
//! cannot compile.
//!
//! Legacy algorithm audit (probed against the oracle, kept byte-exact):
//! single-quoted spans collapse (only `''` escapes; backslash is literal),
//! double-quoted spans collapse (treated as strings, not identifiers),
//! ASCII bare numbers collapse (`$1` -> `$?`, `1.5` -> `?.?`, `-3` ->
//! `-?`, while `0x10` survives), whitespace runs collapse with trim and
//! lowercase. Comments, `?` placeholders, backticks, and `$n` parameter
//! prefixes are NOT special. No dialect is involved. The fingerprint is the
//! first 16 hex characters of SHA-256 over the normalized form.

use regex::Regex;
use sha2::{Digest, Sha256};
use std::fmt::{self, Display, Formatter};
use std::sync::LazyLock;

use qk_sql::SqlDialect;

static SINGLE_QUOTED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"'([^']|'')*'").expect("static pattern"));
static DOUBLE_QUOTED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""([^"]|"")*""#).expect("static pattern"));
// ASCII digits with ASCII boundaries (the oracle's `\b\d+\b` is ASCII-only).
static BARE_NUMBER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u:\b[0-9]+\b)").expect("static pattern"));
static WHITESPACE_RUN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\s+").expect("static pattern"));

/// Normalized query-shape identity: 16 hex characters, frozen external
/// representation. Used for compatibility, human-facing grouping, session
/// audit, and explicitly shape-scoped session grants. Never the sole
/// binding for an exact approval token (64-bit truncation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryShapeFingerprint(String);

impl QueryShapeFingerprint {
    /// The 16-hex compatibility rendering.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for QueryShapeFingerprint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Exact request identity: full SHA-256 over a domain-separated encoding
/// of dialect plus exact SQL bytes. Any literal change (including
/// whitespace) changes the digest. Internal and security-sensitive; never
/// truncated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExactRequestDigest([u8; 32]);

impl ExactRequestDigest {
    /// Full 64-hex rendering (persistence and test vectors; the bytes are
    /// a hash of provider-visible input, not a secret).
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

/// Domain separator: unambiguous framing so dialect and SQL bytes cannot
/// blur into each other across versions.
const DIGEST_DOMAIN: &[u8] = b"queryknight:approval-request:v1\x00";

/// Compute the exact request digest for SQL under a dialect.
#[must_use]
pub fn exact_request_digest(dialect: SqlDialect, sql: &str) -> ExactRequestDigest {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(dialect.to_string().as_bytes());
    hasher.update([0u8]);
    hasher.update(sql.as_bytes());
    let bytes: [u8; 32] = hasher.finalize().into();
    ExactRequestDigest(bytes)
}

/// Strip literals and normalize case/spacing. Deterministic; secrets in
/// literals collapse to `?`, which is why shape fingerprints are log-safe.
#[must_use]
pub fn normalize_sql(sql: &str) -> String {
    let step = SINGLE_QUOTED.replace_all(sql, "?");
    let step = DOUBLE_QUOTED.replace_all(&step, "?");
    let step = BARE_NUMBER.replace_all(&step, "?");
    WHITESPACE_RUN.replace_all(&step, " ").trim().to_lowercase()
}

/// Frozen 16-hex shape identity of normalized SQL.
#[must_use]
pub fn sql_fingerprint(sql: &str) -> QueryShapeFingerprint {
    let digest = Sha256::digest(normalize_sql(sql).as_bytes());
    QueryShapeFingerprint(format!("{digest:x}")[..16].to_owned())
}

#[cfg(test)]
mod tests {
    use super::{exact_request_digest, normalize_sql, sql_fingerprint};
    use qk_sql::SqlDialect;

    /// Vectors captured from the TypeScript oracle (2026-09-28).
    #[test]
    fn oracle_shape_vectors() {
        for (sql, normalized, fingerprint) in [
            ("", "", "e3b0c44298fc1c14"),
            (
                "SELECT id, name FROM customers WHERE id = 42",
                "select id, name from customers where id = ?",
                "0d2e6c16b5960f15",
            ),
            (
                "select ID, NAME from CUSTOMERS where ID=42",
                "select id, name from customers where id=?",
                "7224d28fa38c2f43",
            ),
            (
                "UPDATE customers SET status = 'inactive' WHERE id = 7",
                "update customers set status = ? where id = ?",
                "c1f1acc27c59f39a",
            ),
            ("DELETE FROM t", "delete from t", "40ae96f50fcb7473"),
            ("SELECT 'it''s'", "select ?", "e1c71d1661ae46e0"),
            // Oracle quirks, pinned: comments survive, `$n` collapses the
            // digits only, double quotes are strings, hex/floats split.
            (
                "SELECT 1 -- DROP TABLE x",
                "select ? -- drop table x",
                "53f14ff3b41fd9c8",
            ),
            (
                "SELECT $1, $2 FROM t WHERE id = $1",
                "select $?, $? from t where id = $?",
                "7abb3e86d746468b",
            ),
            (
                "SELECT \"col\" FROM t",
                "select ? from t",
                "ed97449ab5339f2e",
            ),
            (
                "SELECT 0x10, 1.5, -3 FROM t",
                "select 0x10, ?.?, -? from t",
                "2c62aaf4ce8e67a6",
            ),
        ] {
            assert_eq!(normalize_sql(sql), normalized, "{sql:?}");
            assert_eq!(sql_fingerprint(sql).as_str(), fingerprint, "{sql:?}");
        }
    }

    #[test]
    fn shape_collapses_literals() {
        // Same shape, different literals: identical shape identity.
        assert_eq!(
            sql_fingerprint("DELETE FROM customers WHERE id = 42"),
            sql_fingerprint("DELETE FROM customers WHERE id = 43")
        );
        assert_ne!(
            sql_fingerprint("DELETE FROM customers WHERE id = 42"),
            sql_fingerprint("DELETE FROM orders WHERE id = 42")
        );
    }

    #[test]
    fn exact_digest_vectors() {
        let pg = SqlDialect::PostgreSql;
        let my = SqlDialect::MySql;
        let lite = SqlDialect::Sqlite;
        let d42 = exact_request_digest(pg, "DELETE FROM customers WHERE id = 42");
        let d43 = exact_request_digest(pg, "DELETE FROM customers WHERE id = 43");
        let sel = exact_request_digest(pg, "SELECT 1");
        let uni = exact_request_digest(pg, "SELECT 'héllo 🎉' FROM tâble");
        // Full strength: 64 hex characters, deterministic.
        for digest in [d42, d43, sel, uni] {
            assert_eq!(digest.to_hex().len(), 64);
        }
        assert_eq!(
            d42,
            exact_request_digest(pg, "DELETE FROM customers WHERE id = 42")
        );
        // Literals change identity (the security property shape lacks).
        assert_ne!(d42, d43);
        assert_ne!(d42, sel);
        // Same bytes hash identically; dialect separates identical bytes.
        assert_eq!(
            d42.to_hex(),
            exact_request_digest(pg, "DELETE FROM customers WHERE id = 42").to_hex()
        );
        assert_ne!(
            d42,
            exact_request_digest(my, "DELETE FROM customers WHERE id = 42")
        );
        assert_ne!(
            d42,
            exact_request_digest(lite, "DELETE FROM customers WHERE id = 42")
        );
        assert_ne!(
            exact_request_digest(my, "SELECT 1"),
            exact_request_digest(lite, "SELECT 1")
        );
        // Pinned vectors (self-generated against the construction above;
        // determinism pins, review pins correctness).
        assert_eq!(
            d42.to_hex(),
            "8a1c0f480c7239adc79fd4e6c52c833362aae12005ff0f28058f84df34699b48"
        );
        assert_eq!(
            sel.to_hex(),
            "2d57fd23069370db8a3240bf60d22bcc57901de9ac0b6f87a353298dbad506e4"
        );
    }
}
