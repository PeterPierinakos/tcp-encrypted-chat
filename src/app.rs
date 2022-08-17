use std::env;
use std::time::Duration;
use std::io::{self, BufRead, Read, Write};
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use libaes::Cipher;

// If the message written to the stream is bigger than the maximum buffer size, it will create a
// new buffer as if it was a separate message.
pub const MAX_BUF_SIZE: usize = 1024;

/// Converts slice to a stringified form
///
/// Example: `[1,2,3,4] -> "[1,2,3,4]"`
pub fn parse_vec_to_string(vec: Vec<u8>) -> String {
    let mut string = "[".to_string();
    for num in vec {
        string.push_str(num.to_string().as_str());
        string.push(',');
    }
    string.pop();
    string.push(']');
    string
}

/// Converts slice in a string form to a real slice
///
/// Example: `"[1,2,3,4]" -> [1,2,3,4]`
pub fn parse_stringified_slice<'a>(msg: String) -> io::Result<Vec<u8>>
{
    let mut msg_no_weird_chars = String::new();

    for c in msg.chars() {
        if c != '[' && c != ']' && c != ' ' && c != '\0' {
            msg_no_weird_chars.push(c);
        }
    }

    let msg_splitted = msg_no_weird_chars.split(",").collect::<Vec<&str>>();

    let mut vec = vec![];

    for num in msg_splitted {
        let num = match num.parse::<u8>() {
            Ok(num) => num,
            Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, "Slice has an illegal character.")),
        };

        vec.push(num);
    }
    
    Ok(vec)
}

/// The main application's function. it is responsible for handling the TCP listener, the incoming
/// streams and the sending user's messages.
pub fn init(port: u16, peer_addr: SocketAddr, passphrase: &str) -> anyhow::Result<()> {
    let (message_tx, message_rx): (Sender<String>, Receiver<String>) = mpsc::channel();

    let mut passphrase_fixed: [u8; 32] = [0; 32];

    for (i, b) in passphrase.as_bytes().iter().enumerate() {
        passphrase_fixed[i] = *b;
    }

    log::debug!("Fixed passphrase: {:?} size: {}", passphrase_fixed, passphrase_fixed.len());

    // Cipher needs to be sent to both the server and the shell for encryption and decryption, so
    // create twice.
    // TODO: Find a way to send cipher between threads safely without having to create two ciphers
    let cipher = Cipher::new_256(&passphrase_fixed);
    let cipher_2 = Cipher::new_256(&passphrase_fixed);

    thread::spawn(move || start_shell(peer_addr, cipher).map_err(|e| {
        println!("{}", e);
        std::process::exit(1);
    }));
    thread::spawn(move || start_server(message_tx, peer_addr, port, cipher_2).map_err(|e| {
        println!("{}", e);
        std::process::exit(1);
    }));

    loop {
        println!("{peer_addr}: {}", message_rx.recv()?);
    }
}

/// Starts the main thread for the server which listens to the given port.
pub fn start_server(message_tx: Sender<String>, peer_addr: SocketAddr, port: u16, cipher: Cipher) -> io::Result<()> {
    let listener = match TcpListener::bind(format!("0.0.0.0:{port}")) {
        Ok(listener) => listener,
        Err(_) => return Err(io::Error::new(io::ErrorKind::Other, "Failed listening to given port. Maybe the program doesn't have the required privileges or another program is already listening to that port?")),
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

        log::debug!("Peer successfully established connection on their end ({stream_peer_addr})");

        loop {
            let mut msg_buf: [u8; MAX_BUF_SIZE] = [0; MAX_BUF_SIZE];

            loop {
                match stream.read(&mut msg_buf) {
                    Ok(_) => break,
                    Err(_) => {}
                };
            }

            let msg = match std::str::from_utf8(&msg_buf) {
                Ok(msg) => msg,
                Err(_) => {
                    log::error!("Peer's message doesn't contain valid UTF-8 data, not processing.");
                    continue;
                }
            };

            // Parsed byte slice
            let parsed_msg = match parse_stringified_slice(msg.clone().to_string()) {
                Ok(msg) => msg,
                Err(e) => {
                    log::error!("{}", e);
                    continue;
                },
            };

            let iv = b"This is the initialization vect.";

            let msg_dec = cipher.cbc_decrypt(iv, parsed_msg.as_slice());

            let msg_plaintext = match std::string::String::from_utf8(msg_dec) {
                Ok(plaintext) => plaintext,
                Err(_) => {
                    log::error!("Message isn't valid UTF-8 data, not sending message.");
                    continue;
                }
            };

            if !msg_plaintext.is_empty() {
                if message_tx.send(msg_plaintext).is_err() {
                    log::warn!("Failed transmitting stream's message.");
                } else {
                    log::info!("Successfully transmitting client's message.");
                }
            } else {
                if stream.write(b"Message cannot be empty.").is_err() {
                    log::warn!("Failed writing message rejection to TCP stream, skipping.");
                }
            }
        }
    }

    Ok(())
}

pub fn start_shell(peer_addr: SocketAddr, cipher: Cipher) -> anyhow::Result<()> {
    let mut stdin = io::stdin().lock();

    log::debug!("Connecting to peer...");

    let mut stream;

    loop {
        match TcpStream::connect(peer_addr) {
            Ok(new_stream) => {
                stream = new_stream;
                break;
            },
            Err(_) => {
                log::warn!("Connection to TCP failed, retrying in 3000 millis...");
                thread::sleep(Duration::from_millis(3000));
            }
        };
    }

    log::debug!("Connection successfully established with peer's end.");

    loop {
        let mut msg_buf = String::new();
        stdin.read_line(&mut msg_buf)?;
        let msg = msg_buf.trim();

        let iv = b"This is the initialization vect.";

        log::debug!("Encrypting message...");

        let encrypted_msg = cipher.cbc_encrypt(iv, msg.as_bytes());

        log::debug!("Encryption successful.");

        let encrypted_msg_str = parse_vec_to_string(encrypted_msg);

        if stream.write(encrypted_msg_str.as_bytes()).is_err() {
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
