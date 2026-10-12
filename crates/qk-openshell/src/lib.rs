//! NVIDIA OpenShell supervisor-middleware authorization adapter.
//!
//! This crate evaluates SQL carried in HTTP/WebSocket payloads through
//! `qk_db::authorize_guarded`. It does not execute SQL or bind an OpenShell
//! verdict to a later external execution; the gateway/executor boundary is a
//! documented trust limitation. Network listeners require authenticated HTTPS;
//! Unix sockets and loopback-only plaintext are explicit local modes.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod auth;
mod extract;
mod server;
mod service;
/// Generated OpenShell messages. Both packages share the schema parent
/// expected by the vendored cross-package references.
// Prost-generated oneof layouts are wire-contract types; keep codegen output unchanged.
#[allow(missing_docs, clippy::large_enum_variant)]
pub mod openshell {
    /// OpenShell extension peer metadata package.
    pub mod extension {
        /// `openshell.extension.v1` messages.
        pub mod v1 {
            tonic::include_proto!("openshell.extension.v1");
        }
    }

    /// OpenShell supervisor middleware package.
    pub mod middleware {
        /// `openshell.middleware.v1` messages and service clients.
        pub mod v1 {
            tonic::include_proto!("openshell.middleware.v1");
        }
    }
}

pub use auth::{OpenShellAuthConfigError, OpenShellJwtConfig};
/// Generated NVIDIA OpenShell peer metadata messages.
pub use openshell::extension::v1 as extension_proto;
/// Generated NVIDIA OpenShell supervisor middleware messages and clients.
pub use openshell::middleware::v1 as proto;
pub use server::{
    OpenShellServer, OpenShellServerConfig, OpenShellServerDiagnostics, OpenShellServerError,
    OpenShellServerHandle,
};
pub use service::{OpenShellService, OpenShellServiceConfig};

/// Advertised and enforced OpenShell payload limit (1 MiB).
pub const MAX_PAYLOAD_BYTES: usize = 1_048_576;
/// File descriptor set generated from the vendored NVIDIA OpenShell schemas.
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/openshell_descriptor.bin"));
