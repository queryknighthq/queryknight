//! Engine adapters: postgres (tokio-postgres), mysql/mariadb
//! (mysql_async), sqlite (rusqlite, user databases only — never the
//! internal `qk-store` connection).

pub mod mysql;
pub mod postgres;
pub mod sqlite;
