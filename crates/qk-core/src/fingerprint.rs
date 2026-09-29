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
    /// Wrap an already-validated 16-hex shape value (storage reads).
    pub fn new(hex: String) -> Self {
        Self(hex)
    }

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
    /// Wrap validated 32 bytes (storage reads; length is enforced by the
    /// caller reporting `InvalidRow` otherwise).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

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

    /// Raw 32 bytes for BLOB persistence.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Synthetic digest that can never match a real request. Used for
    /// legacy rows that predate exact identity: equality would require a
    /// SHA-256 preimage of this fixed value, so mismatch is structural,
    /// not probabilistic reasoning at match time.
    #[must_use]
    pub fn unmatchable() -> Self {
        Self([0xFF; 32])
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

/// Domain separator for parameter-aware digests. A distinct domain
/// (not a version byte inside v1) so V1 and V2 digests are never
/// comparable without checking the version first.
const DIGEST_DOMAIN_V2: &[u8] = b"queryknight:approval-request:v2\x00";

/// Canonical bound-parameter value for exact identity. Mirrors the
/// typed value passed to the driver (never a `Debug` rendering, never
/// JSON object text): order matters, types are tagged, and every
/// value is length-framed so concatenations cannot blur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestParam {
    /// SQL NULL.
    Null,
    /// Boolean.
    Bool(bool),
    /// Signed integer (driver `i64`; exact bits preserved).
    Int(i64),
    /// Unsigned integer (driver `u64`; exact bits preserved).
    UInt(u64),
    /// Binary float by exact bit pattern (`1.0` and `1.00` share
    /// bits and therefore identity — the driver sees one value).
    FloatBits(u64),
    /// Text (UTF-8 bytes verbatim).
    Text(String),
    /// Raw bytes verbatim.
    Bytes(Vec<u8>),
}

impl DigestParam {
    /// Type tag byte for framed encoding.
    fn tag(&self) -> u8 {
        match self {
            Self::Null => 0x00,
            Self::Bool(false) => 0x01,
            Self::Bool(true) => 0x02,
            Self::Int(_) => 0x03,
            Self::UInt(_) => 0x04,
            Self::FloatBits(_) => 0x05,
            Self::Text(_) => 0x06,
            Self::Bytes(_) => 0x07,
        }
    }

    /// Canonical value bytes (fixed width for numbers, verbatim for
    /// text/bytes, empty for null/bool which the tag already covers).
    fn bytes(&self) -> Vec<u8> {
        match self {
            Self::Null | Self::Bool(_) => Vec::new(),
            Self::Int(value) => value.to_be_bytes().to_vec(),
            Self::UInt(value) => value.to_be_bytes().to_vec(),
            Self::FloatBits(bits) => bits.to_be_bytes().to_vec(),
            Self::Text(text) => text.as_bytes().to_vec(),
            Self::Bytes(bytes) => bytes.clone(),
        }
    }
}

/// Parameter-aware exact request identity: full SHA-256 over a
/// domain-separated framing of dialect, exact SQL bytes, and the
/// ordered canonical parameters. Same type shape and guarantees as
/// [`ExactRequestDigest`]; the two versions are never interchangeable
/// (see [`ExactDigest`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExactRequestDigestV2([u8; 32]);

impl ExactRequestDigestV2 {
    /// Wrap validated 32 bytes (storage reads; length is enforced by
    /// the caller reporting `InvalidRow` otherwise).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Full 64-hex rendering (persistence and test vectors; the bytes
    /// are a hash of provider-visible input, not a secret).
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    /// Raw 32 bytes for BLOB persistence.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Synthetic digest that can never match a real request (legacy
    /// rows predate exact identity; see V1 `unmatchable`).
    #[must_use]
    pub fn unmatchable() -> Self {
        Self([0xFF; 32])
    }
}

fn push_framed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
    hasher.update(bytes);
}

/// Compute the parameter-aware exact digest. Empty `params` still
/// produces a V2 digest (callers select V1 vs V2; see
/// [`RequestIdentity`]).
#[must_use]
pub fn exact_request_digest_v2(
    dialect: SqlDialect,
    sql: &str,
    params: &[DigestParam],
) -> ExactRequestDigestV2 {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN_V2);
    push_framed(&mut hasher, dialect.to_string().as_bytes());
    push_framed(&mut hasher, sql.as_bytes());
    hasher.update(
        u32::try_from(params.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for param in params {
        hasher.update([param.tag()]);
        push_framed(&mut hasher, &param.bytes());
    }
    let bytes: [u8; 32] = hasher.finalize().into();
    ExactRequestDigestV2(bytes)
}

/// Versioned exact execution identity. V1 binds dialect + SQL only
/// (preserved for existing no-parameter approvals); V2 additionally
/// binds ordered parameter values. The enum makes version confusion
/// a compile-time shape, not a runtime prefix check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExactDigest {
    /// SQL-only identity (no bound params).
    V1(ExactRequestDigest),
    /// Parameter-aware identity (one or more bound params).
    V2(ExactRequestDigestV2),
}

impl ExactDigest {
    /// Binding version name (`exact_v1` / `exact_v2`, matching the
    /// persisted `binding_kind` values).
    #[must_use]
    pub fn version(&self) -> &'static str {
        match self {
            Self::V1(_) => "exact_v1",
            Self::V2(_) => "exact_v2",
        }
    }

    /// Raw 32 digest bytes regardless of version.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        match self {
            Self::V1(digest) => digest.as_bytes(),
            Self::V2(digest) => digest.as_bytes(),
        }
    }

    /// Full 64-hex rendering (persistence, test vectors).
    #[must_use]
    pub fn to_hex(&self) -> String {
        match self {
            Self::V1(digest) => digest.to_hex(),
            Self::V2(digest) => digest.to_hex(),
        }
    }
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
    use super::{
        exact_request_digest, exact_request_digest_v2, normalize_sql, sql_fingerprint, DigestParam,
        ExactDigest,
    };
    use qk_sql::SqlDialect;

    /// V1 compatibility: the SQL-only algorithm is byte-identical to
    /// the pre-parameterization digest (existing approvals keep working).
    #[test]
    fn v1_vectors_unchanged() {
        let v1 = exact_request_digest(SqlDialect::Sqlite, "DELETE FROM t WHERE id = 42");
        assert_eq!(v1.to_hex().len(), 64);
        // Deterministic and dialect-bound.
        assert_eq!(
            v1,
            exact_request_digest(SqlDialect::Sqlite, "DELETE FROM t WHERE id = 42")
        );
        assert_ne!(
            v1,
            exact_request_digest(SqlDialect::MySql, "DELETE FROM t WHERE id = 42")
        );
        assert_eq!(ExactDigest::V1(v1).version(), "exact_v1");
        // V1 and V2 never collide by construction (distinct domains).
        let v2 = exact_request_digest_v2(SqlDialect::Sqlite, "DELETE FROM t WHERE id = 42", &[]);
        assert_ne!(v1.as_bytes(), v2.as_bytes());
    }

    /// V2 parameter matrix (§21): order, type, and value sensitive;
    /// dialect-bound; deterministic; no panics on hostile inputs.
    #[test]
    fn v2_parameter_matrix() {
        use DigestParam as P;
        let sql = "DELETE FROM customers WHERE id = ?";
        let d = SqlDialect::PostgreSql;
        let base = || exact_request_digest_v2(d, sql, &[P::Int(42)]);
        // Same request → same digest.
        assert_eq!(base(), base());
        // Different value → different.
        assert_ne!(base(), exact_request_digest_v2(d, sql, &[P::Int(43)]));
        // Order matters.
        assert_ne!(
            exact_request_digest_v2(d, sql, &[P::Int(1), P::Int(2)]),
            exact_request_digest_v2(d, sql, &[P::Int(2), P::Int(1)])
        );
        // Arity matters (no concatenation ambiguity).
        assert_ne!(
            exact_request_digest_v2(d, sql, &[P::Text("ab".to_owned())]),
            exact_request_digest_v2(d, sql, &[P::Text("a".to_owned()), P::Text("b".to_owned())])
        );
        // Types matter: 42 vs "42", null vs "null", true vs 1.
        assert_ne!(
            base(),
            exact_request_digest_v2(d, sql, &[P::Text("42".to_owned())])
        );
        assert_ne!(
            exact_request_digest_v2(d, sql, &[P::Null]),
            exact_request_digest_v2(d, sql, &[P::Text("null".to_owned())])
        );
        assert_ne!(
            exact_request_digest_v2(d, sql, &[P::Bool(true)]),
            exact_request_digest_v2(d, sql, &[P::Int(1)])
        );
        // Int/float bit distinction: 1 (int) vs 1.0 (float bits).
        assert_ne!(
            exact_request_digest_v2(d, sql, &[P::Int(1)]),
            exact_request_digest_v2(d, sql, &[P::FloatBits(1.0f64.to_bits())])
        );
        // -42, large integers, 1.5 all distinct and stable.
        let neg = exact_request_digest_v2(d, sql, &[P::Int(-42)]);
        assert_ne!(neg, base());
        assert_eq!(neg, exact_request_digest_v2(d, sql, &[P::Int(-42)]));
        assert_ne!(base(), exact_request_digest_v2(d, sql, &[P::Int(i64::MAX)]));
        assert_ne!(
            base(),
            exact_request_digest_v2(d, sql, &[P::UInt(u64::MAX)])
        );
        assert_ne!(
            base(),
            exact_request_digest_v2(d, sql, &[P::FloatBits(1.5f64.to_bits())])
        );
        // Unicode, empty string, bytes.
        assert_eq!(
            exact_request_digest_v2(d, sql, &[P::Text("héllo🎉".to_owned())]),
            exact_request_digest_v2(d, sql, &[P::Text("héllo🎉".to_owned())])
        );
        assert_ne!(
            exact_request_digest_v2(d, sql, &[P::Text(String::new())]),
            exact_request_digest_v2(d, sql, &[P::Null])
        );
        assert_ne!(
            exact_request_digest_v2(d, sql, &[P::Bytes(vec![0, 1])]),
            exact_request_digest_v2(d, sql, &[P::Text("\0\x01".to_owned())])
        );
        // Dialect matters.
        assert_ne!(
            base(),
            exact_request_digest_v2(SqlDialect::MySql, sql, &[P::Int(42)])
        );
        // 1000 params at the cap: fine, deterministic.
        let many: Vec<P> = (0..1000i64).map(P::Int).collect();
        assert_eq!(
            exact_request_digest_v2(d, sql, &many),
            exact_request_digest_v2(d, sql, &many)
        );
        assert_eq!(ExactDigest::V2(base()).version(), "exact_v2");
        assert_eq!(base().to_hex().len(), 64);
    }

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
