//! `queryknight proxy [--listen PORT]`: local database wire proxy.

use std::future::Future;

/// Run the proxy selected by the trusted MySQL/PostgreSQL connection URL.
pub fn run(listen: Option<u16>) -> i32 {
    let Some(url) = qk_mcp::connection_url_from_env() else {
        eprintln!("set MYSQL_URL or DATABASE_URL");
        return 1;
    };
    let connection = match qk_mcp::McpConnection::from_url(&url) {
        Ok(connection) => connection,
        Err(_) => {
            eprintln!("invalid proxy backend configuration");
            return 1;
        }
    };
    let kind = match &connection.config {
        qk_db::DbConfig::Postgres(_) => "postgres",
        qk_db::DbConfig::Mysql(_) => "mysql",
        qk_db::DbConfig::Sqlite(_) => {
            eprintln!("queryknight proxy supports only PostgreSQL and MySQL");
            return 1;
        }
    };
    let policy = match qk_mcp::load_policy() {
        Ok(policy) => policy,
        Err(_) => {
            eprintln!("invalid QueryKnight policy configuration");
            return 1;
        }
    };
    let control_plane = qk_control_plane::ControlPlaneClient::discover(None).ok();
    let qk_mcp::McpConnection {
        config: db_config,
        connection_key,
        database_key,
        environment,
    } = connection;
    match kind {
        "postgres" => {
            let config = match qk_proxy_postgres::ProxyConfig::new(
                listen.unwrap_or(5434),
                db_config,
                connection_key,
                environment,
                database_key,
                policy,
                control_plane,
            ) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("cannot configure PostgreSQL proxy: {error}");
                    return 1;
                }
            };
            run_proxy(async move {
                let server = qk_proxy_postgres::ProxyServer::bind(config)
                    .await
                    .map_err(|_| "cannot bind PostgreSQL proxy listener".to_owned())?;
                let addr = server
                    .local_addr()
                    .map_err(|_| "cannot inspect PostgreSQL proxy listener".to_owned())?;
                eprintln!(
                    "proxy 127.0.0.1:{} -> configured PostgreSQL backend (local plaintext)",
                    addr.port()
                );
                server
                    .run_until(async {
                        let _ = tokio::signal::ctrl_c().await;
                    })
                    .await
                    .map_err(|_| "PostgreSQL proxy failed".to_owned())
            })
        }
        _ => {
            let config = match qk_proxy_mysql::ProxyConfig::new(
                listen.unwrap_or(3308),
                db_config,
                connection_key,
                environment,
                database_key,
                policy,
                control_plane,
            ) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("cannot configure MySQL proxy: {error}");
                    return 1;
                }
            };
            run_proxy(async move {
                let server = qk_proxy_mysql::ProxyServer::bind(config)
                    .await
                    .map_err(|_| "cannot bind MySQL proxy listener".to_owned())?;
                let addr = server
                    .local_addr()
                    .map_err(|_| "cannot inspect MySQL proxy listener".to_owned())?;
                eprintln!(
                    "proxy 127.0.0.1:{} -> configured MySQL backend (local plaintext)",
                    addr.port()
                );
                server
                    .run_until(async {
                        let _ = tokio::signal::ctrl_c().await;
                    })
                    .await
                    .map_err(|_| "MySQL proxy failed".to_owned())
            })
        }
    }
}

fn run_proxy(future: impl Future<Output = Result<(), String>>) -> i32 {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("cannot start proxy runtime");
            return 1;
        }
    };
    runtime.block_on(future).map_or_else(
        |error| {
            eprintln!("{error}");
            1
        },
        |_| 0,
    )
}
