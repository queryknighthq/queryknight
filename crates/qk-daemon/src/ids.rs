//! Identifier derivation: approval/event/session ids and connection
//! identity. Formats frozen from the reference (`qka_`/`qke_`/`qks_`/
//! `qkc_` prefixes); randomness comes from the OS, never from SQL.

use sha2::{Digest, Sha256};

/// Mint `qka_<8 hex>` (4 random bytes), matching the daemon id format.
pub fn generate_approval_id() -> String {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).expect("system randomness available");
    format!("qka_{}", hex::encode(bytes))
}

/// Mint `qke_<12 hex>` (6 random bytes) for history events.
pub fn generate_event_id() -> String {
    let mut bytes = [0u8; 6];
    getrandom::fill(&mut bytes).expect("system randomness available");
    format!("qke_{}", hex::encode(bytes))
}

/// Mint `qks_<8 hex>` (4 random bytes) for sessions.
pub fn generate_session_id() -> String {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).expect("system randomness available");
    format!("qks_{}", hex::encode(bytes))
}

/// Connection id: `qkc_` plus 12 hex of SHA-256 over the connection key
/// (pure function of the key, stable across restarts).
pub fn connection_id_from_key(connection_key: &str) -> String {
    let digest = Sha256::digest(connection_key.as_bytes());
    format!("qkc_{}", hex::encode(&digest[..6]))
}

/// Derive a storable connection profile from a connection key, mirroring
/// the reference upsert (URL parse for engine/database/host label;
/// unparseable keys keep the raw key as host label).
pub fn connection_profile_from_key(connection_key: &str) -> qk_store::ConnectionRecord {
    let id = connection_id_from_key(connection_key);
    let (engine, database, host_label) = match connection_key.split_once("://") {
        Some((scheme, rest)) => {
            let engine = scheme.to_lowercase();
            let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
            let database = (!path.is_empty()).then(|| path.to_owned());
            (engine, database, Some(authority.to_owned()))
        }
        None => ("mysql".to_owned(), None, Some(connection_key.to_owned())),
    };
    qk_store::ConnectionRecord {
        id: id.clone(),
        name: host_label.clone().unwrap_or(id),
        engine,
        environment: "unknown".to_owned(),
        source: "env".to_owned(),
        database,
        host_label,
    }
}

/// Lowercase hex encoding without a dedicated dependency.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let mut out = String::with_capacity(bytes.as_ref().len() * 2);
        for byte in bytes.as_ref() {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{connection_id_from_key, connection_profile_from_key, generate_approval_id};

    #[test]
    fn id_formats() {
        let id = generate_approval_id();
        assert!(id.starts_with("qka_") && id.len() == 12);
        assert_ne!(generate_approval_id(), generate_approval_id());
        // Stable derivation, distinct keys diverge.
        assert_eq!(
            connection_id_from_key("mysql://u@h/db"),
            connection_id_from_key("mysql://u@h/db")
        );
        assert_ne!(
            connection_id_from_key("mysql://u@h/db"),
            connection_id_from_key("mysql://u@h/other")
        );
        assert!(connection_id_from_key("x").starts_with("qkc_"));
    }

    #[test]
    fn connection_profile_parsing() {
        let profile = connection_profile_from_key("mysql://qk@127.0.0.1:3307/queryknight");
        assert_eq!(profile.engine, "mysql");
        assert_eq!(profile.database.as_deref(), Some("queryknight"));
        assert_eq!(profile.host_label.as_deref(), Some("qk@127.0.0.1:3307"));
        assert_eq!(profile.environment, "unknown");
        let fallback = connection_profile_from_key("not a url");
        assert_eq!(fallback.engine, "mysql");
        assert_eq!(fallback.host_label.as_deref(), Some("not a url"));
    }
}
