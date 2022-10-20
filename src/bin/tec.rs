use std::collections::HashSet;
use std::net::SocketAddr;
use tec::app;
use clap::Parser;
use std::process::ExitCode;

#[derive(Parser, Debug)]
pub struct Args {
    #[arg(short, long)]
    /// Enables logs for env_logger; logs information for debugging
    pub with_logs: bool,
    // TODO: implement proxy functionality
    /// Used to specify whether you are establishing a connection with a specific peer (proxy) which will send all of the data received from the peers connected to it and will allow you to send messages as it
    #[arg(short, long)]
    pub using_proxy: bool,
    #[arg(long, required(true))]
    pub port: u16,
    #[arg(long, required(true))]
    /// Adds a peer socket address to the peers the client will connect to at runtime. There can be multiple peers.
    pub peer_addr: Vec<SocketAddr>,
    #[arg(long)]
    pub passphrase: Option<String>,
}

fn main() -> anyhow::Result<ExitCode> {
    let args = Args::parse();

    println!("TEC - TCP Encrypted Chat\n");

    if args.with_logs {
        std::env::set_var("RUST_LOG", "info");
        env_logger::init();
    }

    app::init(args.port, args.peer_addr.iter().map(|addr| *addr).collect::<HashSet<SocketAddr>>(), args.passphrase)?;

    Ok(ExitCode::from(0))
}
