//! Bearer-token file lifecycle.
//!
//! Frozen semantics (from `ensureSessionToken`): restart reuses any
//! non-empty token file; a token is generated only when absent (or
//! empty-after-trim, which the reference also treats as absent); no
//! rotation endpoint. Hardening: reads are bounded (4 KiB), writes are
//! atomic (temp + `0600` + fsync + rename), and oversized/unreadable
//! files are typed startup failures.

use std::io::Write as _;

use crate::auth::AuthToken;

use super::error::{RuntimeError, RuntimeErrorKind};
use super::paths::RuntimePaths;

/// Upper bound for a token-file read. A 32-char token plus newline is
/// ~33 bytes; anything past this is not a token file.
pub const TOKEN_FILE_BOUND: u64 = 4096;

/// Load the persisted token or generate and atomically store a fresh
/// one. Generation uses [`crate::auth::generate_token`] (CSPRNG, 24
/// bytes, base64url no-pad — the frozen 32-character format).
pub fn load_or_create(paths: &RuntimePaths) -> Result<AuthToken, RuntimeError> {
    match read_token_file(&paths.token) {
        Ok(Some(token)) => Ok(token),
        Ok(None) => {
            let token = crate::auth::generate_token();
            store_token(&paths.token, &token)?;
            Ok(token)
        }
        Err(error) => Err(error),
    }
}

/// Read and validate the token file without ever generating: `Ok(None)`
/// when absent or empty-after-trim (both mean "generate" upstream).
fn read_token_file(path: &std::path::Path) -> Result<Option<AuthToken>, RuntimeError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(RuntimeError::new(
                RuntimeErrorKind::Token,
                format!("cannot read token file: {error}"),
            ));
        }
    };
    if bytes.len() as u64 > TOKEN_FILE_BOUND {
        return Err(RuntimeError::new(
            RuntimeErrorKind::Token,
            "token file exceeds size bound; refusing to start",
        ));
    }
    let text = String::from_utf8(bytes).map_err(|_| {
        RuntimeError::new(
            RuntimeErrorKind::Token,
            "token file is not valid UTF-8; refusing to start",
        )
    })?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    // Frozen reuse: any non-empty content is the token (no alphabet
    // check — the reference also reuses verbatim).
    Ok(Some(AuthToken::new(trimmed.to_owned())))
}

/// Read a persisted token without creating or rotating it. This is the
/// client-side counterpart to [`load_or_create`]: absent/empty files return
/// `None`, while malformed/oversized files remain typed startup failures.
pub fn read_existing(paths: &RuntimePaths) -> Result<Option<AuthToken>, RuntimeError> {
    read_token_file(&paths.token)
}

/// Raw token-file bytes for tests and diagnostics that must not parse.
pub fn read_token_raw(path: &std::path::Path) -> Result<Vec<u8>, RuntimeError> {
    std::fs::read(path).map_err(|error| {
        RuntimeError::new(
            RuntimeErrorKind::Token,
            format!("cannot read token file: {error}"),
        )
    })
}

/// Atomically persist a token: temp file in the same directory (so the
/// rename never crosses filesystems), restrictive permissions before any
/// bytes land on Unix, flush + sync, then atomic rename. Clients never
/// observe a partially written credential.
fn store_token(path: &std::path::Path, token: &AuthToken) -> Result<(), RuntimeError> {
    let dir = path
        .parent()
        .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::Token, "token path has no parent"))?;
    let tmp = dir.join(format!(".session.token.tmp.{}", std::process::id()));
    // A stale temp file from a crashed start is ours by name; remove so
    // `create_new` below cannot fail on it.
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp).map_err(|error| {
        RuntimeError::new(
            RuntimeErrorKind::Token,
            format!("cannot create token temp file: {error}"),
        )
    })?;
    // The token value is written here and only here; error paths never
    // include it (AuthToken is redacted by construction).
    writeln!(file, "{}", token.as_secret()).map_err(|error| {
        RuntimeError::new(
            RuntimeErrorKind::Token,
            format!("cannot write token temp file: {error}"),
        )
    })?;
    file.flush().map_err(|error| {
        RuntimeError::new(
            RuntimeErrorKind::Token,
            format!("cannot flush token temp file: {error}"),
        )
    })?;
    file.sync_all().map_err(|error| {
        RuntimeError::new(
            RuntimeErrorKind::Token,
            format!("cannot sync token temp file: {error}"),
        )
    })?;
    drop(file);
    std::fs::rename(&tmp, path).map_err(|error| {
        RuntimeError::new(
            RuntimeErrorKind::Token,
            format!("cannot publish token file: {error}"),
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_paths(name: &str) -> RuntimePaths {
        let dir =
            std::env::temp_dir().join(format!("qk-runtime-token-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        RuntimePaths::new(dir)
    }

    #[test]
    fn first_start_creates_restricted_token() {
        let paths = test_paths("create");
        let token = load_or_create(&paths).expect("create");
        assert_eq!(token.as_secret().len(), 32);
        let raw = read_token_raw(&paths.token).expect("read");
        assert_eq!(raw, format!("{}\n", token.as_secret()).into_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&paths.token)
                    .expect("meta")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        // No temp file lingers.
        assert!(std::fs::read_dir(&paths.home)
            .expect("ls")
            .all(|entry| !entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".session.token.tmp.")),);
        let _ = std::fs::remove_dir_all(&paths.home);
    }

    #[test]
    fn restart_reuses_token() {
        let paths = test_paths("reuse");
        let first = load_or_create(&paths).expect("first");
        let second = load_or_create(&paths).expect("second");
        assert_eq!(first, second);
        let _ = std::fs::remove_dir_all(&paths.home);
    }

    #[test]
    fn empty_file_regenerates_like_reference() {
        let paths = test_paths("empty");
        std::fs::write(&paths.token, "  \n").expect("plant");
        let token = load_or_create(&paths).expect("regenerate");
        assert_eq!(token.as_secret().len(), 32);
        let _ = std::fs::remove_dir_all(&paths.home);
    }

    #[test]
    fn oversized_file_fails_closed() {
        let paths = test_paths("oversized");
        std::fs::write(&paths.token, vec![b'x'; 5000]).expect("plant");
        let error = load_or_create(&paths).expect_err("must fail");
        assert_eq!(
            error.kind(),
            &RuntimeErrorKind::Token,
            "unexpected: {error}"
        );
        assert!(!format!("{error}").contains("xxx"));
        let _ = std::fs::remove_dir_all(&paths.home);
    }
}
