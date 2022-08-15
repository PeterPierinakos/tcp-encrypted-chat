use tec::app;
use std::str::FromStr;
use std::net::SocketAddr;
use std::io::{self, BufRead, Write};

fn handle_input() -> anyhow::Result<()> {
    println!("Enter port the server should listen to for incoming TCP streams");
    print!("> ");

    io::stdout().flush()?;
    let mut stdin = io::stdin().lock();
    let mut buffer_port = String::new();
    stdin.read_line(&mut buffer_port)?;
    let port = match buffer_port.trim().parse::<u16>() {
        Ok(port) => port,
        Err(_) => return Err(anyhow::Error::new(io::Error::new(io::ErrorKind::InvalidData, "Invalid port given. The port can be 1 - 65535."))),
    };

    println!("Enter peer socket address");
    print!("> ");
    io::stdout().flush()?;
    let mut buffer_addr = String::new();
    stdin.read_line(&mut buffer_addr)?;
    let peer_addr = match SocketAddr::from_str(&buffer_addr.trim()) {
        Ok(addr) => addr,
        Err(_) => return Err(anyhow::Error::new(io::Error::new(io::ErrorKind::InvalidData, "Invalid socket address given. Example of a valid socket address: \"127.0.0.1:5542\"."))),
    };

    log::info!("Input is OK, starting server...");
    app::init(port, peer_addr);

    Ok(())
}

fn main() -> anyhow::Result<()> {
    println!("TEC - TCP Encrypted Chat");
    println!();

    let args = std::env::args().collect::<Vec<String>>();

    match args.len() {
        1 => {
            handle_input()?;
        },
        _ => {
            if app::handle_other_arguments(args) {
                handle_input()?;
            }
        },
    }

    Ok(())
}
