//! `queryknight proxy [--listen PORT]`: local PostgreSQL Simple Query proxy.

/// Run the frozen PostgreSQL proxy CLI branch. Listener host and default port
/// match the TypeScript CLI; backend selection remains the trusted URL env.
pub fn run(listen: Option<u16>) -> i32 {
    let Some(url) = qk_mcp::connection_url_from_env() else {
        eprintln!("set MYSQL_URL or DATABASE_URL");
        return 1;
    };
    let connection = match qk_mcp::McpConnection::from_url(&url) {
        Ok(connection) => connection,
        Err(_) => {
            eprintln!("invalid PostgreSQL backend configuration");
            return 1;
        }
    };
    if !matches!(connection.config, qk_db::DbConfig::Postgres(_)) {
        eprintln!("queryknight proxy currently supports PostgreSQL only");
        return 1;
    }
    let policy = match qk_mcp::load_policy() {
        Ok(policy) => policy,
        Err(_) => {
            eprintln!("invalid QueryKnight policy configuration");
            return 1;
        }
    };
    let control_plane = qk_control_plane::ControlPlaneClient::discover(None).ok();
    let config = match qk_proxy_postgres::ProxyConfig::new(
        listen.unwrap_or(5434),
        connection.config,
        connection.connection_key,
        connection.environment,
        connection.database_key,
        policy,
        control_plane,
    ) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("cannot configure PostgreSQL proxy: {error}");
            return 1;
        }
    };
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime.block_on(async move {
            let server = match qk_proxy_postgres::ProxyServer::bind(config).await {
                Ok(server) => server,
                Err(error) => {
                    eprintln!("cannot start PostgreSQL proxy: {error}");
                    return 1;
                }
            };
            let addr = match server.local_addr() {
                Ok(addr) => addr,
                Err(error) => {
                    eprintln!("cannot inspect PostgreSQL proxy listener: {error}");
                    return 1;
                }
            };
            eprintln!(
                "proxy 127.0.0.1:{} -> configured PostgreSQL backend (local plaintext)",
                addr.port()
            );
            server
                .run_until(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await
                .map_or_else(
                    |error| {
                        eprintln!("PostgreSQL proxy failed: {error}");
                        1
                    },
                    |_| 0,
                )
        }),
        Err(_) => {
            eprintln!("cannot start PostgreSQL proxy runtime");
            1
        }
    }
}
