use tec::app;
use std::str::FromStr;
use std::net::SocketAddr;
use std::io::{self, BufRead, Write};

fn main() -> anyhow::Result<()> {
    println!("TEC - TCP Encrypted Chat");
    println!();

    let args = std::env::args().collect::<Vec<String>>();

    match args.len() {
        1 => {
            println!("Enter port the server should listen to for incoming TCP streams");
            print!("> ");
            io::stdout().flush()?;
            let mut stdin = io::stdin().lock();
            let mut buffer_port = String::new();
            stdin.read_line(&mut buffer_port)?;
            let port = match buffer_port.parse::<u16>() {
                Ok(port) => port,
                Err(_) => return Err(anyhow::Error::new(io::Error::new(io::ErrorKind::InvalidData, "Invalid port given. The port can be 1 - 65535."))),
            };
            println!("Enter peer socket address");
            print!("> ");
            io::stdout().flush()?;
            let mut stdin = io::stdin().lock();
            let mut buffer_addr = String::new();
            stdin.read_line(&mut buffer_addr)?;
            let peer_addr = match SocketAddr::from_str(&buffer_addr) {
                Ok(addr) => addr,
                Err(_) => return Err(anyhow::Error::new(io::Error::new(io::ErrorKind::InvalidData, "Invalid socket address given. Example of a valid socket address: \"127.0.0.1:5542\"."))),
            };
            app::init(port, peer_addr)
        },
        _ => app::handle_other_arguments(args),
    }

    Ok(())
}
