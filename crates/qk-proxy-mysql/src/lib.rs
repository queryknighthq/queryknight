//! MySQL classic-protocol COM_QUERY proxy.
//!
//! Every frontend owns one backend session. Executable COM_QUERY packets are
//! forwarded only after `qk-db::authorize_guarded` returns a consumed permit.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod config;
mod prepared;
mod protocol;
mod proxy;

pub use config::{ProxyConfig, ProxyConfigError};
pub use proxy::{ProxyError, ProxyServer};
