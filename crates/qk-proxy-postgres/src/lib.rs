//! PostgreSQL Simple Query wire proxy. Each frontend owns one backend session;
//! every executable Q frame is forwarded only after `authorize_guarded`
//! returns a consumed `ExecutionPermit`.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod config;
pub mod protocol;
mod proxy;

pub use config::{ProxyConfig, ProxyConfigError};
pub use proxy::{ProxyError, ProxyServer};
