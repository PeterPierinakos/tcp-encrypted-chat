use std::net::SocketAddr;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::thread;
use std::sync::mpsc::{self, Receiver, Sender};
use std::env;

/// The main application's function. it is responsible for handling the TCP listener, the incoming
/// streams and the sending user's messages.
pub fn init(port: u16, peer_addr: SocketAddr) {
    let (message_tx, message_rx): (Sender<String>, Receiver<String>) = mpsc::channel();
    start_server(message_tx, peer_addr, port);
    log::info!("Server started");

    // Indefinitely locks standard input so that the program doesn't end.
    let _ = io::stdin().lock();
}

pub fn start_server(message_tx: Sender<String>, peer_addr: SocketAddr, port: u16) {
    thread::spawn(move || {
        let listener = TcpListener::bind(format!("0.0.0.0:{port}")).expect("Failed listening to given port. Maybe the program doesn't have the required privileges?");

        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(stream) => stream,
                Err(_) => {
                    log::warn!("Something went wrong whilst getting stream, skipping. Possibly invalid data?");
                    continue;
                }
            };

            let stream_peer_addr = match stream.peer_addr() {
                Ok(peer_addr) => peer_addr,
                Err(_) => continue,
            };

            if stream_peer_addr != peer_addr {
                log::warn!("Permission denied ({stream_peer_addr})");
                if let Err(_) = stream.write(format!("Permission denied.\n\nYour socket address doesn't match the given peer's address.\nYour socket address: {stream_peer_addr}\nGiven peer's address: {peer_addr}").as_bytes()) {
                    log::warn!("Failed writing error to TCP stream, skipping.");
                };
                continue;
            }

            println!("Connection successfully established with peer ({stream_peer_addr})");
        }
    });
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
