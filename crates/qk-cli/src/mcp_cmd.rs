//! `queryknight mcp`: stdio MCP server for the bound database
//! connection (frozen spelling and startup contract).

/// Run the MCP stdio server. URL sources (frozen): `MYSQL_URL`, then
/// `DATABASE_URL`; missing both prints `set MYSQL_URL` to stderr and
/// exits 1. Policy from `--policy`/`QUERYKNIGHT_POLICY_FILE`, else the
/// built-in demo policy. Stdout is protocol-only; diagnostics go to
/// stderr.
pub fn run(policy: Option<std::path::PathBuf>, home: Option<std::path::PathBuf>) -> i32 {
    if let Some(path) = policy {
        // Explicit `--policy` beats the environment for this process.
        std::env::set_var("QUERYKNIGHT_POLICY_FILE", path.as_os_str());
    }
    let Some(url) = qk_mcp::connection_url_from_env() else {
        eprintln!("set MYSQL_URL");
        return 1;
    };
    let policy = match qk_mcp::load_policy() {
        Ok(policy) => policy,
        Err(error) => {
            eprintln!("{error}");
            return 1;
        }
    };
    let state = match qk_mcp::McpState::new(&url, policy, home) {
        Ok(state) => state,
        Err(error) => {
            eprintln!("cannot start MCP server: {error:?}");
            return 1;
        }
    };
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime.block_on(async move {
            if let Err(error) = qk_mcp::serve_stdio(qk_mcp::QueryKnightServer::new(state)).await {
                eprintln!("MCP server failed: {error:?}");
                1
            } else {
                0
            }
        }),
        Err(error) => {
            eprintln!("cannot start async runtime: {error}");
            1
        }
    }
}
