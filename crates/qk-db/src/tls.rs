//! Verified PostgreSQL backend TLS.
//!
//! QueryKnight exposes exactly two PostgreSQL transport modes: explicit
//! plaintext, or TLS that must verify. There is no `prefer`/`allow`
//! downgrade path, and no option disables certificate or hostname
//! verification.
//!
//! Trust anchors are either a QueryKnight-configured PEM bundle (which
//! *replaces* the default roots) or the platform native store. A custom
//! bundle never supplements the native store, so an operator cannot
//! silently broaden trust.
//!
//! TLS is built with `rustls` (ring provider, matching the workspace) and wired through
//! `tokio-postgres-rustls`; hostname verification and SNI use the trusted
//! PostgreSQL connection host, never agent-supplied input.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::error::{DbError, DbErrorKind};

/// Upper bound on a custom CA bundle read from disk. Bounds memory on
/// operator-supplied input; a real CA bundle is a few KiB.
pub const MAX_CA_FILE_BYTES: u64 = 1024 * 1024;

/// How a PostgreSQL backend connection is secured.
///
/// The variant is chosen from trusted connection configuration only
/// (the `sslmode` of the trusted URL plus a QueryKnight CA path); agents
/// never select it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostgresTransport {
    /// `sslmode=disable`: explicit plaintext. No TLS is attempted.
    Plaintext,
    /// `sslmode=require`: TLS is mandatory and must verify. When
    /// `ca_path` is set, that PEM bundle is the only trust anchor;
    /// otherwise the platform native store is used.
    TlsVerified {
        /// PEM CA bundle used as the sole trust anchor, or `None` for the
        /// platform native store.
        ca_path: Option<PathBuf>,
    },
}

impl PostgresTransport {
    /// Whether TLS is required for this connection.
    #[must_use]
    pub fn is_tls(&self) -> bool {
        matches!(self, Self::TlsVerified { .. })
    }

    /// Build the tokio-postgres TLS connector, or `None` for plaintext.
    ///
    /// A custom CA that cannot be read, exceeds [`MAX_CA_FILE_BYTES`],
    /// or yields zero valid certificates is a typed transport error, not
    /// a fallback to plaintext or to the native store.
    pub fn build_connector(&self) -> Result<Option<MakeRustlsConnect>, DbError> {
        match self {
            Self::Plaintext => Ok(None),
            Self::TlsVerified { ca_path } => Ok(Some(MakeRustlsConnect::new(
                rustls_client_config(self.trust_roots(ca_path.as_deref())?),
            ))),
        }
    }

    /// Build the shared `rustls` client configuration, or `None` for
    /// plaintext. The proxy reuses this so both PostgreSQL paths define
    /// "verified TLS" identically.
    pub fn build_rustls_config(&self) -> Result<Option<Arc<ClientConfig>>, DbError> {
        match self {
            Self::Plaintext => Ok(None),
            Self::TlsVerified { ca_path } => Ok(Some(Arc::new(rustls_client_config(
                self.trust_roots(ca_path.as_deref())?,
            )))),
        }
    }

    /// Trust anchors for verified TLS: a configured CA bundle (which
    /// replaces the default roots) or the platform native store.
    fn trust_roots(&self, ca_path: Option<&Path>) -> Result<RootCertStore, DbError> {
        match ca_path {
            Some(path) => load_custom_ca(path),
            None => load_native_roots(),
        }
    }
}

/// Build a client config with no client auth (server-authenticated TLS only).
///
/// `rustls` verifies the full chain against `roots` and the hostname
/// against the connection host; no verification bypass exists here.
fn rustls_client_config(roots: RootCertStore) -> ClientConfig {
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Load a custom CA bundle from a PEM file. The bundle *replaces* the
/// default roots (documented, predictable policy).
fn load_custom_ca(path: &Path) -> Result<RootCertStore, DbError> {
    let metadata = std::fs::metadata(path).map_err(|_| {
        DbError::new(
            DbErrorKind::Transport,
            "configured PostgreSQL TLS CA bundle cannot be read",
        )
    })?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(DbError::new(
            DbErrorKind::Transport,
            "configured PostgreSQL TLS CA bundle is not a non-empty file",
        ));
    }
    if metadata.len() > MAX_CA_FILE_BYTES {
        return Err(DbError::new(
            DbErrorKind::Transport,
            "configured PostgreSQL TLS CA bundle exceeds the size limit",
        ));
    }
    let pem = std::fs::read(path).map_err(|_| {
        DbError::new(
            DbErrorKind::Transport,
            "configured PostgreSQL TLS CA bundle cannot be read",
        )
    })?;
    let certs = rustls_pemfile::certs(&mut pem.as_slice())
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| {
            DbError::new(
                DbErrorKind::Transport,
                "configured PostgreSQL TLS CA bundle is not valid PEM",
            )
        })?;
    if certs.is_empty() {
        return Err(DbError::new(
            DbErrorKind::Transport,
            "configured PostgreSQL TLS CA bundle contains no certificates",
        ));
    }
    let mut roots = RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(DbError::new(
            DbErrorKind::Transport,
            "configured PostgreSQL TLS CA bundle contains no usable certificates",
        ));
    }
    if ignored > 0 {
        return Err(DbError::new(
            DbErrorKind::Transport,
            "configured PostgreSQL TLS CA bundle contains unparsable certificates",
        ));
    }
    Ok(roots)
}

/// Load the platform native trust store.
fn load_native_roots() -> Result<RootCertStore, DbError> {
    let result = rustls_native_certs::load_native_certs();
    if result.certs.is_empty() {
        return Err(DbError::new(
            DbErrorKind::Transport,
            "no platform trust roots are available for PostgreSQL TLS",
        ));
    }
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(result.certs);
    if added == 0 {
        return Err(DbError::new(
            DbErrorKind::Transport,
            "no usable platform trust roots are available for PostgreSQL TLS",
        ));
    }
    Ok(roots)
}

/// Classify a TLS/connection error raised during connect.
///
/// `tokio-postgres` reports TLS failures as `Connection` errors whose text
/// carries the rustls reason. We keep the distinction typed and never
/// surface certificate material.
pub(crate) fn classify_tls_error(message: &str) -> DbErrorKind {
    let lower = message.to_ascii_lowercase();
    if lower.contains("invalid certificate")
        || lower.contains("unknown issuer")
        || lower.contains("unknown ca")
        || lower.contains("certificate")
        || lower.contains("not valid for name")
        || lower.contains("hostname")
        || lower.contains("handshake")
        || lower.contains("tls")
        || lower.contains("ssl")
    {
        DbErrorKind::Transport
    } else {
        DbErrorKind::Connection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_builds_no_connector() {
        assert!(!PostgresTransport::Plaintext.is_tls());
        assert!(PostgresTransport::Plaintext
            .build_connector()
            .expect("plaintext connector")
            .is_none());
    }

    #[test]
    fn verified_tls_is_marked_and_builds_a_connector() {
        let transport = PostgresTransport::TlsVerified { ca_path: None };
        assert!(transport.is_tls());
        // Native roots may be unavailable in a minimal container; either a
        // connector or a typed transport error is acceptable here.
        match transport.build_connector() {
            Ok(Some(_)) => {}
            Ok(None) => panic!("verified TLS must produce a connector"),
            Err(error) => assert_eq!(error.kind(), &DbErrorKind::Transport),
        }
    }

    #[test]
    fn missing_custom_ca_is_a_typed_transport_error() {
        let transport = PostgresTransport::TlsVerified {
            ca_path: Some(PathBuf::from("/nonexistent/qk-ca-bundle.pem")),
        };
        match transport.build_connector() {
            Err(error) => assert_eq!(error.kind(), &DbErrorKind::Transport),
            Ok(_) => panic!("missing CA must fail"),
        }
    }

    #[test]
    fn malformed_custom_ca_is_rejected() {
        let dir = std::env::temp_dir().join(format!(
            "qk-tls-ca-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("ca.pem");
        std::fs::write(&path, b"not a certificate").expect("write");
        let transport = PostgresTransport::TlsVerified {
            ca_path: Some(path),
        };
        match transport.build_connector() {
            Err(error) => assert_eq!(error.kind(), &DbErrorKind::Transport),
            Ok(_) => panic!("malformed CA must fail"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_custom_ca_is_rejected() {
        let dir = std::env::temp_dir().join(format!(
            "qk-tls-empty-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("ca.pem");
        std::fs::write(&path, b"").expect("write");
        let transport = PostgresTransport::TlsVerified {
            ca_path: Some(path),
        };
        match transport.build_connector() {
            Err(error) => assert_eq!(error.kind(), &DbErrorKind::Transport),
            Ok(_) => panic!("empty CA must fail"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
