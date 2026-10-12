//! QueryKnight standalone binary: local policy commands over the real
//! Rust core (`qk-sql` + `qk-core`), plus the standalone daemon
//! lifecycle (`start` / `stop` / `status`) over `qk-daemon`.
//!
//! Exit codes (frozen contract):
//!
//! - `0`: success. Valid policy, all policy tests pass, `inspect` allowed.
//! - `1`: policy test failures, unknown subcommand, or bare `policy`.
//! - `2`: usage errors (bad flags, missing file/SQL), invalid policy or
//!   cases files, unknown dialect.
//! - `3`: `inspect` evaluated successfully but the decision is not allow
//!   (deny or require-approval). The evaluation itself succeeded.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod daemon_cmd;
mod inspect;
mod mcp_cmd;
mod openshell_cmd;
mod policy;
mod proxy_cmd;

use clap::{ArgAction, CommandFactory, Parser, Subcommand};

/// Single source for the reported product version (matches the frozen
/// `0.1.0-beta.0` surface).
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug)]
#[command(
    name = "queryknight",
    about = "QueryKnight - database query safety net",
    disable_version_flag = true,
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<TopCommand>,
    /// Print version and exit.
    #[arg(short = 'v', long = "version", global = true, action = ArgAction::SetTrue)]
    version: bool,
}

#[derive(Subcommand, Debug)]
enum TopCommand {
    /// Print version and exit.
    Version,
    /// Print help and exit.
    Help,
    /// Evaluate SQL against a policy file (default: built-in demo policy).
    Inspect {
        /// SQL dialect: postgres, mysql, sqlite (plus documented aliases).
        #[arg(long, default_value = "mysql")]
        dialect: String,
        /// Policy file (default: built-in demo policy).
        #[arg(long)]
        policy: Option<std::path::PathBuf>,
        /// Machine-readable JSON output.
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
        /// Environment scope (default: production).
        #[arg(long)]
        env: Option<String>,
        /// Database scope (default: main).
        #[arg(long)]
        db: Option<String>,
        /// Agent identity for agent-scoped rules.
        #[arg(long)]
        agent: Option<String>,
        /// Integration name (default: cli).
        #[arg(long)]
        integration: Option<String>,
        /// Tool name for tool-scoped rules.
        #[arg(long)]
        tool: Option<String>,
        /// SQL to evaluate (joined with spaces); stdin when piped and empty.
        /// Unknown flags are rejected (exit 2); use `--` before SQL that
        /// begins with `-`.
        #[arg(trailing_var_arg = true)]
        sql: Vec<String>,
    },
    /// Policy file commands.
    Policy {
        #[command(subcommand)]
        action: Option<PolicyAction>,
    },
    /// Start the daemon (frozen reference shape; background by default).
    Start {
        /// Listen port (`QUERYKNIGHT_PORT`, default 47821; 0 is ephemeral).
        #[arg(long)]
        port: Option<u16>,
        /// State directory (`QUERYKNIGHT_HOME`, default ~/.queryknight).
        #[arg(long)]
        home: Option<std::path::PathBuf>,
        /// Run in the foreground (canonical implementation; the default
        /// `start` spawns this detached and polls for readiness).
        #[arg(long, action = ArgAction::SetTrue)]
        foreground: bool,
    },
    /// Stop the daemon (verified ownership, graceful SIGTERM).
    Stop {
        /// State directory (`QUERYKNIGHT_HOME`, default ~/.queryknight).
        #[arg(long)]
        home: Option<std::path::PathBuf>,
        /// Probe port (default: pid file's port, else `QUERYKNIGHT_PORT`).
        #[arg(long)]
        port: Option<u16>,
    },
    /// Show daemon status (pid evidence plus control-plane probe).
    Status {
        /// State directory (`QUERYKNIGHT_HOME`, default ~/.queryknight).
        #[arg(long)]
        home: Option<std::path::PathBuf>,
        /// Probe port (default: pid file's port, else `QUERYKNIGHT_PORT`).
        #[arg(long)]
        port: Option<u16>,
    },
    /// Start the MCP stdio server for the bound database connection.
    Mcp {
        /// Policy file (`QUERYKNIGHT_POLICY_FILE`, else built-in demo).
        #[arg(long)]
        policy: Option<std::path::PathBuf>,
        /// State directory (`QUERYKNIGHT_HOME`, default ~/.queryknight).
        #[arg(long)]
        home: Option<std::path::PathBuf>,
    },
    /// Start the local MySQL or PostgreSQL wire proxy (default port 3308 or 5434).
    Proxy {
        /// Loopback listener port (default 3308 for MySQL, 5434 for PostgreSQL).
        #[arg(long)]
        listen: Option<u16>,
    },
    /// OpenShell supervisor middleware commands.
    #[command(name = "openshell")]
    OpenShell {
        #[command(subcommand)]
        action: openshell_cmd::OpenShellAction,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyAction {
    /// Validate a policy file.
    Validate {
        /// Policy file to validate.
        file: Option<std::path::PathBuf>,
    },
    /// Run policy test cases (embedded `tests:` or a cases file).
    Test {
        /// Policy file under test.
        policy: Option<std::path::PathBuf>,
        /// Standalone cases file (bare list or `{tests: [...]}` mapping).
        cases: Option<std::path::PathBuf>,
        /// Default dialect for cases (default: postgres).
        #[arg(long)]
        dialect: Option<String>,
        /// Default environment for cases (default: production).
        #[arg(long)]
        env: Option<String>,
        /// Default database for cases (default: main).
        #[arg(long)]
        db: Option<String>,
    },
}

fn print_version() {
    println!("QueryKnight {VERSION}");
}

fn print_help() -> i32 {
    match Cli::command().print_help() {
        Ok(()) => {
            println!();
            0
        }
        Err(_) => 1,
    }
}

fn run(cli: Cli) -> i32 {
    if cli.version && cli.command.is_none() {
        print_version();
        return 0;
    }
    match cli.command {
        None => {
            // Bare `queryknight`: help to stdout, exit 1 (reference parity).
            print_help();
            1
        }
        Some(TopCommand::Version) => {
            print_version();
            0
        }
        Some(TopCommand::Help) => print_help(),
        Some(TopCommand::Inspect {
            dialect,
            policy,
            json,
            env,
            db,
            agent,
            integration,
            tool,
            sql,
        }) => inspect::run(inspect::InspectArgs {
            dialect,
            policy,
            json,
            env,
            db,
            agent,
            integration,
            tool,
            sql,
        }),
        Some(TopCommand::Policy { action }) => match action {
            None => {
                eprintln!("usage: queryknight policy <validate|test> ...");
                1
            }
            Some(PolicyAction::Validate { file }) => policy::validate(file),
            Some(PolicyAction::Test {
                policy,
                cases,
                dialect,
                env,
                db,
            }) => policy::test(policy, cases, dialect, env, db),
        },
        Some(TopCommand::Start {
            port,
            home,
            foreground,
        }) => daemon_cmd::start(home, port, foreground),
        Some(TopCommand::Stop { home, port }) => daemon_cmd::stop(home, port),
        Some(TopCommand::Status { home, port }) => daemon_cmd::status(home, port),
        Some(TopCommand::Mcp { policy, home }) => mcp_cmd::run(policy, home),
        Some(TopCommand::Proxy { listen }) => proxy_cmd::run(listen),
        Some(TopCommand::OpenShell { action }) => match action {
            openshell_cmd::OpenShellAction::Serve(args) => openshell_cmd::serve(args),
            openshell_cmd::OpenShellAction::Doctor(args) => openshell_cmd::doctor(args),
        },
    }
}

fn main() {
    let code = match Cli::try_parse() {
        Ok(cli) => run(cli),
        Err(error) => match error.kind() {
            // `--help`: clap prints to stdout, exit 0 (reference parity).
            clap::error::ErrorKind::DisplayHelp => {
                let _ = error.print();
                0
            }
            // Unknown subcommand: full help to stdout, exit 1 (reference
            // parity; clap would use exit 2).
            clap::error::ErrorKind::InvalidSubcommand => {
                print_help();
                1
            }
            // Bad flags, missing values, UTF-8 failures: clap diagnostics
            // to stderr, exit 2 (reference usage-error code).
            _ => {
                let _ = error.print();
                2
            }
        },
    };
    std::process::exit(code);
}
