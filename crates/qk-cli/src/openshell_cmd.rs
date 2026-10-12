use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Subcommand};
use qk_control_plane::ControlPlaneClient;
use qk_db::DbConfig;
use qk_openshell::{
    OpenShellJwtConfig, OpenShellServer, OpenShellServerConfig, OpenShellServerDiagnostics,
    OpenShellService, OpenShellServiceConfig,
};

const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 400;

#[derive(Subcommand, Debug)]
pub enum OpenShellAction {
    /// Start the authenticated HTTPS middleware service.
    Serve(ServeArgs),
    /// Validate local OpenShell middleware configuration without binding a port.
    Doctor(DoctorArgs),
}

#[derive(Args, Debug, Clone)]
struct CommonArgs {
    /// TCP address. Authenticated mode may bind non-loopback; development mode may not.
    #[arg(long, default_value = "127.0.0.1:50051")]
    listen: SocketAddr,
    /// PEM server certificate chain.
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    /// PEM server private key. The key is read from this file, never a flag value.
    #[arg(long)]
    tls_key: Option<PathBuf>,
    /// Operator-provisioned OpenShell gateway ID used for exact issuer validation.
    #[arg(long)]
    gateway_id: Option<String>,
    /// Exact middleware audience configured independently in OpenShell.
    #[arg(long)]
    audience: Option<String>,
    /// Operator-provisioned local OpenShell JWKS file containing public Ed25519 keys.
    #[arg(long)]
    jwks_file: Option<PathBuf>,
    /// Expected DNS name or IP address OpenShell will use for TLS verification.
    #[arg(long)]
    advertised_host: Option<String>,
    /// Binding RPC timeout in milliseconds (10–30000; default 400).
    #[arg(long, default_value_t = DEFAULT_REQUEST_TIMEOUT_MS)]
    request_timeout_ms: u64,
    /// QueryKnight state directory for approval-daemon discovery.
    #[arg(long)]
    home: Option<PathBuf>,
    /// Explicitly use plaintext unauthenticated loopback development mode.
    #[arg(long, conflicts_with_all = ["tls_cert", "tls_key", "gateway_id", "audience", "jwks_file", "advertised_host"])]
    insecure_local: bool,
}

#[derive(Args, Debug)]
pub struct ServeArgs {
    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Args, Debug)]
pub struct DoctorArgs {
    #[command(flatten)]
    common: CommonArgs,
    /// Local QueryKnight SQL policy YAML to validate and inspect for approvals.
    #[arg(long)]
    policy_file: Option<PathBuf>,
}

struct ConfiguredService {
    server: OpenShellServerConfig,
    service: OpenShellService,
    request_timeout: Duration,
}

fn configured_service(common: &CommonArgs) -> Result<ConfiguredService, String> {
    let request_timeout = Duration::from_millis(common.request_timeout_ms);
    if !(Duration::from_millis(10)..=Duration::from_secs(30)).contains(&request_timeout) {
        return Err("--request-timeout-ms must be between 10 and 30000".to_owned());
    }
    let (server, expected_audience) = if common.insecure_local {
        if !common.listen.ip().is_loopback() {
            return Err("OpenShellInsecureLocal requires a loopback --listen address".to_owned());
        }
        (OpenShellServerConfig::insecure_local(common.listen), None)
    } else {
        let tls_cert = common
            .tls_cert
            .as_ref()
            .ok_or("authenticated OpenShell mode requires --tls-cert")?;
        let tls_key = common
            .tls_key
            .as_ref()
            .ok_or("authenticated OpenShell mode requires --tls-key")?;
        let gateway_id = common
            .gateway_id
            .as_deref()
            .ok_or("authenticated OpenShell mode requires --gateway-id")?;
        let audience = common
            .audience
            .as_deref()
            .ok_or("authenticated OpenShell mode requires --audience")?;
        let jwks_file = common
            .jwks_file
            .as_ref()
            .ok_or("authenticated OpenShell mode requires --jwks-file")?;
        let jwt = OpenShellJwtConfig::new(gateway_id, audience, jwks_file)
            .map_err(|_| "OpenShell gateway ID or audience is invalid".to_owned())?;
        let expected_audience = Some(audience.to_owned());
        let mut server =
            OpenShellServerConfig::authenticated(common.listen, tls_cert, tls_key, jwt);
        if let Some(host) = &common.advertised_host {
            server = server.with_advertised_host(host.clone());
        }
        (server, expected_audience)
    };

    let database_url = qk_mcp::connection_url_from_env()
        .ok_or("set MYSQL_URL or DATABASE_URL to provide the trusted SQL dialect")?;
    let database = DbConfig::from_url(&database_url)
        .map_err(|_| "configured database URL is invalid".to_owned())?;
    let control_plane = match ControlPlaneClient::discover(common.home.clone()) {
        Ok(client) => Some(client),
        Err(_) if std::env::var(qk_daemon::runtime::paths::ENV_DAEMON_URL).is_ok() => {
            return Err("configured QueryKnight approval control plane is unavailable".to_owned());
        }
        Err(_) => None,
    };
    let mut service_config =
        OpenShellServiceConfig::new(database).with_request_timeout(request_timeout);
    if let Some(audience) = expected_audience {
        service_config = service_config.with_expected_audience(audience);
    }
    if let Some(client) = control_plane {
        service_config = service_config.with_control_plane(client);
    }
    Ok(ConfiguredService {
        server,
        service: OpenShellService::new(service_config),
        request_timeout,
    })
}

pub fn serve(args: ServeArgs) -> i32 {
    let ConfiguredService {
        server,
        service,
        request_timeout: _,
    } = match configured_service(&args.common) {
        Ok(configured) => configured,
        Err(error) => {
            eprintln!("cannot start OpenShell middleware: {error}");
            return 1;
        }
    };
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime.block_on(async move {
            let handle = match OpenShellServer::bind(server.clone(), service).await {
                Ok(handle) => handle,
                Err(error) => {
                    eprintln!("cannot start OpenShell middleware: {error}");
                    return 1;
                }
            };
            let address = handle.local_addr().unwrap_or(server.listen());
            eprintln!(
                "QueryKnight OpenShell middleware listening on {address}; mode={}",
                if server.is_authenticated() {
                    "OpenShellAuthenticated"
                } else {
                    "OpenShellInsecureLocal (DEVELOPMENT / TRUSTED TRANSPORT ONLY)"
                }
            );
            if let Err(error) = tokio::signal::ctrl_c().await {
                eprintln!("OpenShell shutdown signal failed: {error}");
                return 1;
            }
            match handle.stop().await {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("OpenShell middleware stopped with an error: {error}");
                    1
                }
            }
        }),
        Err(error) => {
            eprintln!("cannot start async runtime: {error}");
            1
        }
    }
}

pub fn doctor(args: DoctorArgs) -> i32 {
    let configured = match configured_service(&args.common) {
        Ok(configured) => configured,
        Err(error) => {
            eprintln!("OpenShell doctor: configuration error: {error}");
            return 1;
        }
    };
    let diagnostics =
        match OpenShellServer::validate_configuration(&configured.server, &configured.service) {
            Ok(diagnostics) => diagnostics,
            Err(error) => {
                eprintln!("OpenShell doctor: transport/auth configuration is invalid: {error}");
                return 1;
            }
        };
    print_diagnostics(&configured, &diagnostics);
    let (policy_valid, approvals_required) = match validate_policy(args.policy_file.as_deref()) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("OpenShell doctor: policy configuration error: {error}");
            return 1;
        }
    };
    if policy_valid {
        println!("QueryKnight policy          valid ✓");
    } else {
        println!(
            "QueryKnight policy          not checked (OpenShell ValidateConfig is authoritative)"
        );
    }
    if approvals_required {
        match ControlPlaneClient::discover(args.common.home.clone())
            .and_then(|client| client.list_approvals().map(|_| ()))
        {
            Ok(()) => println!("Approval control plane      reachable ✓"),
            Err(_) => {
                println!("Approval control plane      unavailable ✗");
                return 1;
            }
        }
    } else if policy_valid {
        println!("Approval control plane      not required by selected policy");
    } else {
        println!("Approval control plane      not checked (no local policy supplied)");
    }
    if diagnostics.authenticated_mode_configured {
        println!("OpenShell caller auth       configured; no request has been verified");
        println!("Ready for authenticated OpenShell registration.");
    } else {
        println!("WARNING DEVELOPMENT / TRUSTED TRANSPORT ONLY: no TLS or caller authentication");
        println!("Ready for local development only; not a network middleware deployment.");
    }
    0
}

fn print_diagnostics(configured: &ConfiguredService, diagnostics: &OpenShellServerDiagnostics) {
    println!("OpenShell protocol          1.0 ✓");
    println!("Target OpenShell release    v0.1.2 ✓");
    println!("Listener                    {}", configured.server.listen());
    println!(
        "Transport mode              {}",
        if diagnostics.authenticated_mode_configured {
            "OpenShellAuthenticated"
        } else {
            "OpenShellInsecureLocal"
        }
    );
    if diagnostics.authenticated_mode_configured {
        println!("TLS certificate/key         valid ✓");
        match diagnostics.advertised_host_san_matches {
            Some(true) => println!("Advertised hostname SAN      matches ✓"),
            Some(false) => println!("Advertised hostname SAN      mismatch ✗"),
            None => println!("Advertised hostname SAN      not checked (supply --advertised-host)"),
        }
        println!("Expected audience            configured ✓");
        println!(
            "Gateway issuer               openshell-gateway:{} ✓",
            diagnostics
                .expected_gateway_id
                .as_deref()
                .unwrap_or("<missing>")
        );
        println!(
            "Trusted JWKS                 {} Ed25519 key(s) loaded ✓",
            diagnostics.trusted_jwks_keys
        );
    } else {
        println!("TLS certificate/key         not configured");
        println!("Expected audience            not configured");
        println!("Gateway issuer               not configured");
        println!("Trusted JWKS                 not configured");
    }
    println!(
        "Per-operation timeout        {} ms",
        configured.request_timeout.as_millis()
    );
}

fn validate_policy(path: Option<&std::path::Path>) -> Result<(bool, bool), String> {
    let Some(path) = path else {
        return Ok((false, false));
    };
    let source =
        std::fs::read_to_string(path).map_err(|_| "policy file could not be read".to_owned())?;
    let policy = qk_core::parse_policy(&source).map_err(|_| "policy file is invalid".to_owned())?;
    let mut approvals = policy.defaults.decision == qk_core::PolicyDecision::RequireApproval
        || policy.defaults.on_parse_error == qk_core::ParseFallback::RequireApproval
        || policy.defaults.on_unknown == qk_core::ParseFallback::RequireApproval;
    for environment in policy.environments.values() {
        for database in environment.databases.values() {
            approvals |= !database.approval_required.is_empty();
            approvals |= database.sensitive.as_ref().is_some_and(|sensitive| {
                sensitive.action == qk_core::SensitiveAction::RequireApproval
            });
        }
    }
    Ok((true, approvals))
}
