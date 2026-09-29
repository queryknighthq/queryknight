//! Frozen credential redaction: `//user:password@` becomes
//! `//user:***@`. Applied at display edges; structured fields carry
//! stripped keys or redacted placeholders instead.

/// Redact a userinfo password, mirroring the frozen `redact()`
/// helper. Non-URL strings without a password shape pass through.
pub fn redact_credentials(text: &str) -> String {
    let Some(scheme_end) = text.find("://") else {
        return text.to_owned();
    };
    let after_scheme = &text[scheme_end + 3..];
    let Some(at) = after_scheme.find('@') else {
        return text.to_owned();
    };
    let userinfo = &after_scheme[..at];
    let Some(colon) = userinfo.find(':') else {
        return text.to_owned();
    };
    format!(
        "{}://{}:***@{}",
        &text[..scheme_end],
        &userinfo[..colon],
        &after_scheme[at + 1..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_redaction() {
        assert_eq!(
            redact_credentials("postgres://user:ULTRA_SECRET@localhost/db"),
            "postgres://user:***@localhost/db"
        );
        assert_eq!(
            redact_credentials("mysql://qk@127.0.0.1:3307/qk"),
            "mysql://qk@127.0.0.1:3307/qk"
        );
        assert_eq!(redact_credentials("not a url"), "not a url");
        assert_eq!(redact_credentials("sqlite:/tmp/x.db"), "sqlite:/tmp/x.db");
    }
}
