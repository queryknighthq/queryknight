//! Frozen SQL logging levels: how much statement text an audit event
//! may carry. Default is safe (`Fingerprint`); raw SQL requires the
//! explicit `FullSql` opt-in.

/// SQL log level (frozen names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SqlLogLevel {
    /// No SQL text at all (ids + fingerprint only).
    None,
    /// Stable sha256 of literal-stripped SQL (safe).
    #[default]
    Fingerprint,
    /// Plus literal-stripped normalized SQL, tables, columns.
    Metadata,
    /// Plus raw SQL text (may contain secrets; opt-in only).
    FullSql,
}

impl SqlLogLevel {
    /// Frozen wire value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Fingerprint => "fingerprint",
            Self::Metadata => "metadata",
            Self::FullSql => "full_sql",
        }
    }

    /// Whether normalized SQL and columns are included.
    pub fn includes_metadata(self) -> bool {
        matches!(self, Self::Metadata | Self::FullSql)
    }

    /// Whether raw SQL text is included.
    pub fn includes_raw_sql(self) -> bool {
        matches!(self, Self::FullSql)
    }
}

/// Maximum SQL/normalized characters kept in an event (frozen 20000).
pub const MAX_SQL_LOG_CHARS: usize = 20_000;

/// Truncate to a char boundary (never splits UTF-8).
pub fn truncate_chars(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_is_utf8_safe() {
        assert_eq!(truncate_chars("abcdef", 4), "abcd");
        // Multi-byte chars: cut lands on a boundary, never mid-char.
        let text = "aébc🎉de";
        assert!(truncate_chars(text, 4).len() <= 4);
        assert!(truncate_chars(text, 4).is_char_boundary(0));
        for limit in 0..text.len() + 2 {
            let cut = truncate_chars(text, limit);
            assert!(text.starts_with(cut), "{limit}");
        }
    }
}
