//! Glob matching with reference-compatible semantics.
//!
//! Port of the TypeScript oracle: `*` matches any character sequence
//! (including dots), matching is case-insensitive, every other character is
//! literal. `*.api_key` therefore matches `users.api_key` and
//! `public.users.api_key`; `users.password_hash` matches exactly.
//!
//! Security rule: a pattern that cannot be compiled never matches. Match
//! failure is always deny-side (narrower), never a broader match.

use regex::{Regex, RegexBuilder};

/// Characters treated as literals that must be escaped for the regex engine.
/// Mirrors the oracle character class `[.+?^${}()|[\]\\]`; `*` is the only
/// wildcard and is handled by splitting before escaping.
const REGEX_SPECIAL: [char; 13] = [
    '.', '+', '?', '^', '$', '{', '}', '(', ')', '|', '[', ']', '\\',
];

fn escape_into(part: &str, out: &mut String) {
    for ch in part.chars() {
        if REGEX_SPECIAL.contains(&ch) {
            out.push('\\');
        }
        out.push(ch);
    }
}

fn build_source(pattern: &str) -> String {
    let mut body = String::with_capacity(pattern.len() * 2 + 4);
    let mut first = true;
    for part in pattern.split('*') {
        if !first {
            body.push_str(".*");
        }
        first = false;
        escape_into(part, &mut body);
    }
    let mut src = String::with_capacity(body.len() + 2);
    src.push('^');
    src.push_str(&body);
    src.push('$');
    src
}

fn compile(pattern: &str) -> Option<Regex> {
    RegexBuilder::new(&build_source(pattern))
        .case_insensitive(true)
        .build()
        .ok()
}

/// Returns true when `value` matches `pattern` under oracle semantics.
/// A pattern that fails to compile returns false (never a broader match).
#[must_use]
pub fn glob_match(pattern: &str, value: &str) -> bool {
    compile(pattern).is_some_and(|re| re.is_match(value))
}

/// Validation hook: true when `pattern` compiles and is usable in policy.
/// Load-time rejection uses [`crate::PolicyLoadError::InvalidGlob`].
#[must_use]
pub fn check_glob(pattern: &str) -> bool {
    compile(pattern).is_some()
}

#[cfg(test)]
mod tests {
    use super::{check_glob, glob_match};

    #[test]
    fn oracle_examples() {
        assert!(glob_match("*.api_key", "users.api_key"));
        assert!(glob_match("*.api_key", "public.users.api_key"));
        assert!(glob_match("users.password_hash", "users.password_hash"));
        assert!(!glob_match("users.password_hash", "users.password_hash_v2"));
    }

    #[test]
    fn case_insensitive() {
        assert!(glob_match("USERS.PASSWORD_HASH", "users.password_hash"));
        assert!(glob_match("users.password_hash", "USERS.PASSWORD_HASH"));
    }

    #[test]
    fn wildcard_boundaries() {
        assert!(glob_match("*", "anything.at.all"));
        assert!(glob_match("public.*", "public.customers"));
        assert!(!glob_match("public.*", "private.customers"));
        assert!(glob_match("del*", "delete"));
        assert!(!glob_match("del*", "insert"));
        assert!(!glob_match("", "x"));
        assert!(glob_match("", ""));
    }

    #[test]
    fn regex_chars_are_literal() {
        assert!(glob_match("users.api_key+v2", "users.api_key+v2"));
        assert!(!glob_match("users.api_key+v2", "users.api_keyvv"));
        assert!(glob_match("a(b|c).d", "a(b|c).d"));
        assert!(!glob_match("a(b|c).d", "ab.d"));
        assert!(glob_match("price[0]$^", "price[0]$^"));
    }

    #[test]
    fn failure_is_narrow() {
        // Absurd input that cannot compile must not match anything.
        let huge_star = "*".repeat(100_000);
        assert!(!glob_match(&huge_star, "x"));
        assert!(!check_glob(&huge_star));
        assert!(check_glob("*.api_key"));
    }
}
