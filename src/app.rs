use std::env;
use std::io::{self, BufRead, Read, Write};
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

/// The main application's function. it is responsible for handling the TCP listener, the incoming
/// streams and the sending user's messages.
pub fn init(port: u16, peer_addr: SocketAddr) -> anyhow::Result<()> {
    let (message_tx, message_rx): (Sender<String>, Receiver<String>) = mpsc::channel();

    thread::spawn(move || start_shell(peer_addr).map_err(|e| {
        log::error!("{}", e);
        println!("{}", e);
        std::process::exit(1);
    }));
    thread::spawn(move || start_server(message_tx, peer_addr, port).map_err(|e| {
        log::error!("{}", e);
        println!("{}", e);
        std::process::exit(1);
    }));

    loop {
        println!("{peer_addr}: {}", message_rx.recv().unwrap());
    }
}

/// Starts the main thread for the server which listens to the given port.
pub fn start_server(message_tx: Sender<String>, peer_addr: SocketAddr, port: u16) -> io::Result<()> {
    let listener = match TcpListener::bind(format!("0.0.0.0:{port}")) {
        Ok(listener) => listener,
        Err(_) => return Err(io::Error::new(io::ErrorKind::Other, "Failed listening to given port. Maybe the program doesn't have the required privileges?")),
    };
    
    log::info!("Server successfully started.");

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(_) => {
                log::warn!(
                    "Something went wrong whilst getting stream, skipping. Possibly invalid data?"
                );
                continue;
            }
        };

        let stream_peer_addr = match stream.peer_addr() {
            Ok(peer_addr) => peer_addr,
            Err(_) => {
                log::warn!("Couldn't obtain stream's peer socket address, skipping.");
                continue;
            }
        };

        if stream.set_nonblocking(true).is_err() {
            log::warn!("Couldn't set stream to nonblocking, skipping.");
            continue;
        }

        // There is no point in checking if the ports match.
        if stream_peer_addr.ip() != peer_addr.ip() {
            log::warn!("Permission denied ({stream_peer_addr})");
            if stream.write(format!("Permission denied.\n\nYour socket address doesn't match the given peer's address.\nYour socket address: {stream_peer_addr}\nGiven peer's address: {peer_addr}").as_bytes()).is_err() {
                    log::warn!("Failed writing error to TCP stream, skipping.");
                };
            continue;
        }

        log::debug!("Connection successfully established with peer ({stream_peer_addr})");

        let mut msg = String::new();

        loop {
            match stream.read_to_string(&mut msg) {
                Ok(_) => break,
                Err(_) => {}
            };
        }

        if !msg.is_empty() {
            if message_tx.send(msg).is_err() {
                log::warn!("Failed transmitting stream's message.");
            } else {
                log::info!("Successfully transmitting client's message.");
            }
        } else {
            if stream.write(b"Message cannot be empty.").is_err() {
                log::warn!("Failed writing message rejection to TCP stream, skipping.");
            }
        }

        log::debug!("Connection ended with peer ({stream_peer_addr})");
    }

    Ok(())
}

pub fn start_shell(peer_addr: SocketAddr) -> anyhow::Result<()> {
    let mut stdin = io::stdin().lock();

    loop {
        let mut message_buf = String::new();
        stdin.read_line(&mut message_buf)?;
        let message = message_buf.trim();

        log::debug!("Connecting to peer...");

        let mut stream = match TcpStream::connect(peer_addr) {
            Ok(stream) => stream,
            Err(_) => return Err(anyhow::Error::new(std::io::Error::new(io::ErrorKind::ConnectionRefused, "Failed to connect to the peer's socket address."))),
        };

        if stream.write(message.as_bytes()).is_err() {
            log::warn!("Failed sending message to TCP stream; not sent.");
        }
    }
}

/// Handles all arguments besides none. Returns true if the app should continue after the arguments
/// are handled.
pub fn handle_other_arguments(args: Vec<String>) -> bool {
    let first_arg = args[1].clone();

    match first_arg.as_str() {
        "-v" | "--version" => println!("Version: {}", env::var("CARGO_PKG_VERSION").unwrap_or("could not detect Cargo version. Make sure you are running the program with the Rust's Cargo package manager.".to_string())),
        "-h" | "--help" => println!("There is no savior."),
        "--with-logs" => {
            env::set_var("RUST_LOG", "debug");
            env_logger::init();
            return true;
        }
        _ => println!("Invalid first argument provided."),
    }

    false
}
