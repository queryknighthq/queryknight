//! Defensive lexical safety scan: conservative evidence, never verdicts.
//!
//! The AST ([`QueryAnalysis`](crate::QueryAnalysis)) remains the sole source
//! of structural facts. This scanner answers a narrower question: *which
//! dangerous operations might this text contain, assuming the parser failed
//! or is untrusted here?* It reports possible operations and uncertainty
//! only. There is deliberately no `safe`, `read_only`, or `allowed` output:
//! fallback evidence can only add risk, never establish safety (INV-023).
//!
//! Mechanism: a single linear pass over the input with an explicit state
//! machine. Keywords inside strings, quoted identifiers, comments, and
//! dollar-quoted bodies are never matched. Word boundaries are real
//! (Unicode alphanumeric plus `_`); `$` is not a word character, matching
//! the conservative reference behavior. No regexes, no recursion, no
//! per-character heap allocation, no tables/columns/WHERE/LIMIT inference.

use std::collections::BTreeSet;

use crate::analyze::{analyze_with_options, AnalyzeOptions};
use crate::dialect::SqlDialect;
use crate::error::SqlAnalysisError;
use crate::model::QueryAnalysis;

/// A possibly-present operation. Names mirror
/// [`Operation`](crate::Operation) vocabulary; `UnknownWrite` and
/// `UnknownAdmin` mark detected-but-unclassifiable danger (`EXEC`/`EXECUTE`,
/// lexically incomplete tails).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PossibleOperation {
    /// Possible SELECT.
    Select,
    /// Possible INSERT.
    Insert,
    /// Possible UPDATE.
    Update,
    /// Possible DELETE.
    Delete,
    /// Possible MERGE.
    Merge,
    /// Possible CREATE.
    Create,
    /// Possible ALTER.
    Alter,
    /// Possible DROP.
    Drop,
    /// Possible TRUNCATE.
    Truncate,
    /// Possible GRANT.
    Grant,
    /// Possible REVOKE.
    Revoke,
    /// Possible COPY or LOAD DATA.
    Copy,
    /// Possible CALL.
    Call,
    /// Possible VACUUM.
    Vacuum,
    /// Possible transaction control (BEGIN/COMMIT/ROLLBACK/START/...).
    Transaction,
    /// Uncertain shape leaning dangerous (e.g. truncated input).
    UnknownWrite,
    /// Procedure execution with unknown effect (EXEC/EXECUTE).
    UnknownAdmin,
}

impl PossibleOperation {
    /// Stable lowercase name for messages and fixtures.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Merge => "merge",
            Self::Create => "create",
            Self::Alter => "alter",
            Self::Drop => "drop",
            Self::Truncate => "truncate",
            Self::Grant => "grant",
            Self::Revoke => "revoke",
            Self::Copy => "copy",
            Self::Call => "call",
            Self::Vacuum => "vacuum",
            Self::Transaction => "transaction",
            Self::UnknownWrite => "unknown_write",
            Self::UnknownAdmin => "unknown_admin",
        }
    }
}

/// Defensive scan signals. Uncertainty only; nothing here asserts safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DefensiveSignal {
    /// An unterminated string, comment, or dollar quote was found: the tail
    /// could hide anything.
    LexicallyIncomplete,
    /// `'` opened but never closed.
    UnterminatedString,
    /// `/*` opened but never closed.
    UnterminatedComment,
    /// `$tag$` opened but never closed (PostgreSQL).
    UnterminatedDollarQuote,
    /// A `;` outside protected regions is followed by further content.
    MultipleStatements,
}

/// Scan completeness. `LexicallyIncomplete` forces `UnknownWrite` and must
/// keep the future evaluator fail-closed regardless of possible operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanCompleteness {
    /// Whole input tokenized cleanly.
    Complete,
    /// Unterminated construct: the tail is unanalyzed.
    LexicallyIncomplete,
}

/// Owned defensive evidence for one SQL input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefensiveScan {
    /// Possibly-present operations. Sorted, deduplicated.
    pub possible_operations: BTreeSet<PossibleOperation>,
    /// Uncertainty signals. Sorted, deduplicated.
    pub signals: BTreeSet<DefensiveSignal>,
    /// Count of `;` outside strings/comments/quotes. Diagnostic only.
    pub statement_boundaries: usize,
    /// Whether the whole input was tokenized.
    pub completeness: ScanCompleteness,
}

/// Future-facing bundle: AST result plus defensive evidence, computed
/// together so the evaluator cannot forget the scan. The two models stay
/// separate types: nothing here converts fallback evidence into AST facts,
/// verdicts, or safety claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlInspection {
    /// Primary analysis (may be `Err`).
    pub analysis: Result<QueryAnalysis, SqlAnalysisError>,
    /// Defensive evidence for the same input.
    pub defensive: DefensiveScan,
}

impl SqlInspection {
    /// Run both layers over the same input. Neither layer mutates the
    /// other's output; see INV-023 for the combination contract.
    #[must_use]
    pub fn inspect(sql: &str, dialect: SqlDialect) -> Self {
        Self {
            analysis: analyze_with_options(sql, dialect, AnalyzeOptions::default()),
            defensive: defensive_scan(sql, dialect),
        }
    }

    /// True when the AST layer failed (parse error, complexity limit, ...).
    #[must_use]
    pub fn ast_failed(&self) -> bool {
        self.analysis.is_err()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Normal,
    LineComment,
    BlockComment,
    SingleString,
    DoubleId,
    BacktickId,
    BracketId,
    DollarQuote,
}

/// Scan SQL for possible operations without parsing. Linear time, iterative,
/// allocation-free per character (one small tag buffer only while inside a
/// PostgreSQL dollar quote).
pub fn defensive_scan(sql: &str, dialect: SqlDialect) -> DefensiveScan {
    let bytes = sql.as_bytes();
    let mut ops = BTreeSet::new();
    let mut signals = BTreeSet::new();
    let mut boundaries = 0usize;
    let mut content_before = false;
    let mut semi_after_content = false;
    let mut content_after_semi = false;
    let mut state = State::Normal;
    // Reused word buffer: comments are transparent to accumulation
    // (`DR/**/OP` yields `DROP`, matching SQL comment semantics and the
    // reference), while quotes, separators, and other bytes flush it.
    // One buffer for the whole scan; cleared on flush, never grown per
    // character beyond the current word.
    let mut word_buf: Vec<u8> = Vec::new();
    let mut dollar_tag = String::new();
    let mut i = 0usize;

    // MySQL treats backslash as an escape inside strings; PostgreSQL and
    // SQLite treat it as a literal (earlier string end, more code scanned:
    // the conservative direction).
    let backslash_escapes = dialect == SqlDialect::MySql;
    // Brackets quote identifiers only in SQLite; elsewhere `[`/`]` are
    // ordinary characters, so keywords inside them still match.
    let brackets_quote = dialect == SqlDialect::Sqlite;

    // Classify the accumulated word, if any, then clear the buffer.
    // Flushed at every non-comment boundary: `SELECT'foo'` still yields
    // possible Select.
    let flush_word = |word_buf: &mut Vec<u8>, ops: &mut BTreeSet<PossibleOperation>| {
        if !word_buf.is_empty() {
            if let Some(op) = classify_word(word_buf) {
                ops.insert(op);
            }
            word_buf.clear();
        }
    };

    while i < bytes.len() {
        let b = bytes[i];
        match state {
            State::LineComment => {
                if b == b'\n' {
                    state = State::Normal;
                }
                i += 1;
            }
            State::BlockComment => {
                if b == b'*' && bytes.get(i + 1) == Some(&b'/') {
                    state = State::Normal;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            State::SingleString => {
                if backslash_escapes && b == b'\\' {
                    i += 2;
                } else if b == b'\'' {
                    if bytes.get(i + 1) == Some(&b'\'') {
                        i += 2;
                    } else {
                        state = State::Normal;
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            State::DoubleId => {
                if b == b'"' {
                    if bytes.get(i + 1) == Some(&b'"') {
                        i += 2;
                    } else {
                        state = State::Normal;
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            State::BacktickId => {
                // No escape handling (reference-compatible, conservative:
                // `` `` `` inside identifiers re-opens scanning).
                if b == b'`' {
                    state = State::Normal;
                }
                i += 1;
            }
            State::BracketId => {
                if b == b']' {
                    state = State::Normal;
                }
                i += 1;
            }
            State::DollarQuote => {
                if b == b'$' && is_dollar_close(bytes, i, &dollar_tag) {
                    state = State::Normal;
                    i += dollar_tag.len() + 2;
                } else {
                    // Byte-wise advance; dollar bodies never yield words.
                    i += 1;
                }
            }
            State::Normal => {
                if b == b';' {
                    boundaries += 1;
                    flush_word(&mut word_buf, &mut ops);
                    // A `;` with content on both sides separates statements.
                    // (`SELECT 1;;` and `; SELECT 1` do not. A trailing `;`
                    // must not clear an already-separated pair.)
                    semi_after_content |= content_before;
                    content_before = false;
                    i += 1;
                } else if b == b'-' && bytes.get(i + 1) == Some(&b'-') {
                    // Comments are whitespace-equivalent in SQL grammar
                    // (`SEL/**/ECT` parses as SELECT): they neither break
                    // words nor hide content, so the pending word survives.
                    state = State::LineComment;
                    i += 2;
                } else if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
                    // MySQL `/*!...*/` executable comments run server-side:
                    // scan through them instead of hiding their content.
                    let executable =
                        dialect == SqlDialect::MySql && bytes.get(i + 2) == Some(&b'!');
                    if executable {
                        flush_word(&mut word_buf, &mut ops);
                        i += 2;
                    } else {
                        state = State::BlockComment;
                        i += 2;
                    }
                } else if b == b'\'' {
                    flush_word(&mut word_buf, &mut ops);
                    content_before = true;
                    if boundaries >= 1 {
                        content_after_semi = true;
                    }
                    state = State::SingleString;
                    i += 1;
                } else if b == b'"' {
                    flush_word(&mut word_buf, &mut ops);
                    content_before = true;
                    if boundaries >= 1 {
                        content_after_semi = true;
                    }
                    state = State::DoubleId;
                    i += 1;
                } else if b == b'`' {
                    flush_word(&mut word_buf, &mut ops);
                    content_before = true;
                    if boundaries >= 1 {
                        content_after_semi = true;
                    }
                    state = State::BacktickId;
                    i += 1;
                } else if b == b'[' && brackets_quote {
                    flush_word(&mut word_buf, &mut ops);
                    content_before = true;
                    if boundaries >= 1 {
                        content_after_semi = true;
                    }
                    state = State::BracketId;
                    i += 1;
                } else if b == b'$' && dialect == SqlDialect::PostgreSql {
                    if let Some(tag) = parse_dollar_open(&bytes[i..]) {
                        flush_word(&mut word_buf, &mut ops);
                        dollar_tag.clear();
                        dollar_tag.push_str(&tag);
                        state = State::DollarQuote;
                        i += tag.len() + 2;
                    } else {
                        // `$1`, `$ `, ...: ordinary character, no word.
                        flush_word(&mut word_buf, &mut ops);
                        i += 1;
                    }
                } else if is_word_byte(b) || is_word_start_extra(sql, i) {
                    let len = next_char_len(sql, i);
                    word_buf.extend_from_slice(&bytes[i..i + len]);
                    content_before = true;
                    if boundaries >= 1 {
                        content_after_semi = true;
                    }
                    i += next_char_len(sql, i);
                } else {
                    flush_word(&mut word_buf, &mut ops);
                    // `(` after a boundary is content too.
                    if b == b'(' {
                        content_before = true;
                        if boundaries >= 1 {
                            content_after_semi = true;
                        }
                    }
                    i += next_char_len(sql, i);
                }
            }
        }
    }
    if state == State::Normal {
        flush_word(&mut word_buf, &mut ops);
    }

    let unterminated = match state {
        State::Normal | State::LineComment => None,
        State::SingleString => Some(DefensiveSignal::UnterminatedString),
        State::BlockComment => Some(DefensiveSignal::UnterminatedComment),
        State::DollarQuote => Some(DefensiveSignal::UnterminatedDollarQuote),
        // Unterminated quoted identifiers: incomplete, but with no dedicated
        // sub-signal; LexicallyIncomplete + UnknownWrite still apply below.
        State::DoubleId | State::BacktickId | State::BracketId => None,
    };
    // Any unclosed quoted region leaves an unanalyzed tail, including
    // identifiers: the closing quote might itself be the hidden content.
    let incomplete_tail = !matches!(state, State::Normal | State::LineComment);
    let completeness = if incomplete_tail {
        if let Some(signal) = unterminated {
            signals.insert(signal);
        }
        signals.insert(DefensiveSignal::LexicallyIncomplete);
        // The unanalyzed tail could hide anything: lean dangerous.
        ops.insert(PossibleOperation::UnknownWrite);
        ScanCompleteness::LexicallyIncomplete
    } else {
        ScanCompleteness::Complete
    };
    if semi_after_content && content_after_semi {
        signals.insert(DefensiveSignal::MultipleStatements);
    }

    DefensiveScan {
        possible_operations: ops,
        signals,
        statement_boundaries: boundaries,
        completeness,
    }
}

/// ASCII word bytes; anything else is judged by the Unicode path.
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Non-ASCII alphanumeric or `_` at byte index `i`. `$` is deliberately not
/// a word character (conservative, reference-compatible).
fn is_word_start_extra(sql: &str, i: usize) -> bool {
    sql[i..]
        .chars()
        .next()
        .is_some_and(|c| !c.is_ascii() && c.is_alphanumeric())
}

/// Byte length of the character at index `i` (index always valid here).
fn next_char_len(sql: &str, i: usize) -> usize {
    sql[i..].chars().next().map_or(1, |c| c.len_utf8())
}

/// Byte-wise ASCII case-insensitive equality against a keyword literal.
fn word_eq(word: &[u8], lit: &[u8]) -> bool {
    word.len() == lit.len()
        && word
            .iter()
            .zip(lit)
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
}

/// Full-word ASCII case-insensitive keyword match. Non-ASCII words never
/// match: keywords are ASCII, and any non-ASCII byte fails `word_eq`.
fn classify_word(word: &[u8]) -> Option<PossibleOperation> {
    if word_eq(word, b"select") {
        Some(PossibleOperation::Select)
    } else if word_eq(word, b"insert") {
        Some(PossibleOperation::Insert)
    } else if word_eq(word, b"update") {
        Some(PossibleOperation::Update)
    } else if word_eq(word, b"delete") {
        Some(PossibleOperation::Delete)
    } else if word_eq(word, b"merge") {
        Some(PossibleOperation::Merge)
    } else if word_eq(word, b"create") {
        Some(PossibleOperation::Create)
    } else if word_eq(word, b"alter") {
        Some(PossibleOperation::Alter)
    } else if word_eq(word, b"drop") {
        Some(PossibleOperation::Drop)
    } else if word_eq(word, b"truncate") {
        Some(PossibleOperation::Truncate)
    } else if word_eq(word, b"grant") {
        Some(PossibleOperation::Grant)
    } else if word_eq(word, b"revoke") {
        Some(PossibleOperation::Revoke)
    } else if word_eq(word, b"copy") || word_eq(word, b"load") {
        Some(PossibleOperation::Copy)
    } else if word_eq(word, b"call") {
        Some(PossibleOperation::Call)
    } else if word_eq(word, b"vacuum") {
        Some(PossibleOperation::Vacuum)
    } else if word_eq(word, b"begin")
        || word_eq(word, b"commit")
        || word_eq(word, b"rollback")
        || word_eq(word, b"start")
        || word_eq(word, b"transaction")
    {
        Some(PossibleOperation::Transaction)
    } else if word_eq(word, b"exec") || word_eq(word, b"execute") {
        Some(PossibleOperation::UnknownAdmin)
    } else {
        None
    }
}

/// Parse a PostgreSQL dollar-quote opener at the start of `rest` (which
/// begins with `$`). Returns the tag (possibly empty) on success.
fn parse_dollar_open(rest: &[u8]) -> Option<String> {
    // `$` + tag + `$`; tag = letter/underscore/non-ASCII start, then
    // alphanumerics/underscores. `$1` and `$ ` are not openers.
    let mut j = 1usize;
    let first = *rest.get(j)?;
    if first == b'$' {
        return Some(String::new());
    }
    if !(first.is_ascii_alphabetic() || first == b'_' || first >= 0x80) {
        return None;
    }
    j += 1;
    while let Some(&c) = rest.get(j) {
        if c == b'$' {
            // Tag bytes are ASCII-or-high here by construction; lossy
            // conversion only affects exotic tags, never safety: a missed
            // opener scans the body as code (more flags, not fewer).
            return String::from_utf8(rest[1..j].to_vec()).ok();
        }
        if !(c.is_ascii_alphanumeric() || c == b'_' || c >= 0x80) {
            return None;
        }
        j += 1;
    }
    None
}

/// True when `bytes[i..]` opens the closer (`$` + tag + `$`) for a
/// dollar quote. Allocation-free.
fn is_dollar_close(bytes: &[u8], i: usize, tag: &str) -> bool {
    let t = tag.as_bytes();
    bytes.get(i + 1..i + 1 + t.len()) == Some(t) && bytes.get(i + 1 + t.len()) == Some(&b'$')
}
