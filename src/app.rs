use std::net::SocketAddr;
use std::env;

pub fn init(port: u16, peer_addr: SocketAddr) {

}

pub fn handle_other_arguments(args: Vec<String>) {
    let first_arg = args[1].clone();

    match first_arg.as_str() {
        "-v" | "--version" => println!("Version: {}", env::var("CARGO_PKG_VERSION").unwrap_or("could not detect Cargo version. Make sure you are running the program with the Rust's Cargo package manager.".to_string())),
        "-h" | "--help" => println!("There is no savior."),
        _ => println!("Invalid first argument provided."),
    }
}
