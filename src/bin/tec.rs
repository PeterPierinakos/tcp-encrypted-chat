use clap::Parser;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::process::exit;
use tec::app::{self, ProxyMode};

#[derive(Parser, Debug)]
pub struct Args {
    #[arg(short, long)]
    /// Enables INFO and WARN logs for env_logger
    pub with_logs: bool,
    /// Enables DEBUG logs for env_logger
    #[arg(short, long)]
    pub debug_mode: bool,
    #[arg(default_value = "none")]
    pub proxy_mode: String,
    #[arg(long, required(true))]
    pub port: u16,
    #[arg(long, required(true))]
    /// Adds a peer socket address to the peers the client will connect to at runtime. There can be multiple peers. At least one peer address must be given.
    pub peer_addr: Vec<SocketAddr>,
    #[arg(long)]
    pub passphrase: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    println!("TEC - TCP Encrypted Chat\n");

    if args.with_logs && args.debug_mode {
        eprintln!(
            "You have to either provide --with-logs for normal logs or --debug-mode for all logs."
        );
        exit(1)
    } else if args.with_logs || args.debug_mode {
        if args.with_logs {
            std::env::set_var("RUST_LOG", "info");
        }

        if args.debug_mode {
            std::env::set_var("RUST_LOG", "debug");
        }

        std::env::set_var("RUST_LOG", std::env::var("RUST_LOG")?);
        env_logger::init();
    }

    if let Some(passphrase) = &args.passphrase {
        if passphrase.len() != 32 {
            eprintln!("Passphrase isn't 32 characters long.");
            exit(1)
        }
    }

    let proxy_mode = match args.proxy_mode.as_str() {
        "host" => ProxyMode::Hosting,
        "use" => ProxyMode::Using,
        "none" => ProxyMode::None,
        _ => {
            eprintln!("Invalid value provided to 'proxy_mode'.");
            exit(1)
        }
    };

    app::init(
        args.port,
        args.peer_addr
            .iter()
            .map(|addr| *addr)
            .collect::<HashSet<SocketAddr>>(),
        args.passphrase,
        proxy_mode,
    )
}
