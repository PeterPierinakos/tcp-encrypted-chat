use std::env;
use rand::prelude::*;
use std::net::IpAddr;
use std::collections::HashSet;
use std::time::Duration;
use std::io::{self, BufRead, Read, Write};
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use libaes::Cipher;

pub struct Message {
    pub peer: SocketAddr,
    pub message: String,
}

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

pub fn gen_iv() -> [u8; 32] {
    let mut rng = rand::thread_rng();
    let mut iv: [u8; 32] = [0; 32];

    for i in 0..iv.len() {
        iv[i] = rng.gen_range(0..128);
    }

    iv
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
            Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Slice has an illegal character ({num})."))),
        };

        vec.push(num);
    }
    
    Ok(vec)
}

/// The main application's function. it is responsible for handling the TCP listener, the incoming
/// streams and the sending user's messages.
pub fn init(port: u16, peer_addrs: HashSet<SocketAddr>, passphrase: &str) -> anyhow::Result<()> {
    let (message_tx, message_rx): (Sender<Message>, Receiver<Message>) = mpsc::channel();

    let mut passphrase_fixed: [u8; 32] = [0; 32];

    for (i, b) in passphrase.as_bytes().iter().enumerate() {
        passphrase_fixed[i] = *b;
    }

    log::debug!("Fixed size passphrase: {:?}", passphrase_fixed);

    let peer_addr_ip_only = peer_addrs.iter().map(|socket| socket.ip()).collect::<HashSet<IpAddr>>();

    thread::spawn(move || {
        start_shell(Vec::from_iter(peer_addrs), passphrase_fixed).map_err(|e| {
            println!("{}", e);
            std::process::exit(1);
        }
    )});
    thread::spawn(move || {
        start_server(message_tx, peer_addr_ip_only, port, passphrase_fixed).map_err(|e| {
            println!("{}", e);
            std::process::exit(1);
        })
    });

    loop {
        let msg = message_rx.recv()?;

        println!("{}: {}", msg.peer, msg.message);
    }
}

/// Starts the main thread for the server which listens to the given port.
pub fn start_server<'a>(message_tx: Sender<Message>, peer_addrs: HashSet<IpAddr>, port: u16, passphrase: [u8; 32]) -> io::Result<()> {
    let listener = match TcpListener::bind(format!("0.0.0.0:{port}")) {
        Ok(listener) => listener,
        Err(_) => return Err(io::Error::new(io::ErrorKind::Other, "Failed listening to given port. Maybe the program doesn't have the required privileges or another program is already listening to that port?")),
    };
    
    log::info!("Server successfully started.");

    for stream in listener.incoming() {
        let message_tx_clone = message_tx.clone();
        let peer_addrs_clone = peer_addrs.clone();
        let passphrase_clone = passphrase.clone();

        // Create new thread for each stream
        thread::spawn(move || {
            let stream = match stream {
                Ok(stream) => stream,
                Err(_) => {
                    log::warn!(
                        "Something went wrong whilst getting stream, skipping. Possibly invalid data?"
                    );
                    return;
                }
            };

            let passphrase = passphrase_clone;

            let cipher = Cipher::new_256(&passphrase);

            let mut stream = stream;

            let message_tx = message_tx_clone;
            let peer_addrs = peer_addrs_clone;

            let stream_peer_addr = match stream.peer_addr() {
                Ok(peer_addr) => peer_addr,
                Err(_) => {
                    log::warn!("Couldn't obtain stream's peer socket address, skipping.");
                    return;
                }
            };

            // There is no point in checking if the ports match.
            if !peer_addrs.contains(&stream_peer_addr.ip()) {
                log::warn!("Permission denied ({stream_peer_addr})");
                if stream.write(format!("Permission denied.\n\nYour socket address doesn't match the given peer's address.\nYour socket address: {stream_peer_addr}").as_bytes()).is_err() {
                        log::warn!("Failed writing error to TCP stream, skipping.");
                    };
                return;
            }

            log::debug!("Peer successfully established connection on their end ({stream_peer_addr})");

            let mut iv_buf: [u8; MAX_BUF_SIZE] = [0; MAX_BUF_SIZE];
            let mut iv_utf8: &str;
            let mut iv: [u8; 32] = [0; 32];

            loop {
                // First message must be the IV which is used for ciphertext decryption
                loop {
                    match stream.read(&mut iv_buf) {
                        Ok(_) => {
                            match std::str::from_utf8(&iv_buf) {
                                Ok(iv) => {
                                    iv_utf8 = iv;
                                    break;
                                },
                                Err(_) => {
                                    log::error!("Peer's IV isn't valid. ({stream_peer_addr})");
                                    continue;
                                }
                            };
                        },
                        Err(_) => {},
                    }
                };

                match parse_stringified_slice(iv_utf8.to_string()) {
                    Ok(new_iv) => {
                        if new_iv.len() != 32 {
                            log::error!("Peer's IV isn't equal to 32 length. ({stream_peer_addr})");
                            continue;
                        }
                        else {
                            for (i, b) in new_iv.iter().enumerate() {
                                iv[i] = *b;
                            }
                        }
                    },
                    Err(_) => {
                        log::error!("Peer's IV isn't valid. ({stream_peer_addr})");
                        continue;
                    },
                };

                break;
            }

            drop(iv_buf);
            drop(iv_utf8);

            log::debug!("Peer's IV: {:?} ({})", iv, stream_peer_addr);

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
                        log::error!("Peer's message doesn't contain valid UTF-8 data, not processing. ({stream_peer_addr})");
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

                let msg_dec = cipher.cbc_decrypt(&iv, parsed_msg.as_slice());

                let msg_plaintext = match std::string::String::from_utf8(msg_dec) {
                    Ok(plaintext) => plaintext,
                    Err(_) => {
                        log::error!("Received message isn't valid UTF-8 data, not showing message.");
                        continue;
                    }
                };

                if !msg_plaintext.is_empty() {
                    if message_tx.send(Message { peer: stream_peer_addr, message: msg_plaintext }).is_err() {
                        log::warn!("Failed transmitting stream's message. ({stream_peer_addr})");
                    } else {
                        log::debug!("Successfully transmitting client's message. ({stream_peer_addr})");
                    }
                } else {
                    log::error!("Received empty message, skipping.");
                    if stream.write(b"Message cannot be empty.").is_err() {
                        log::warn!("Failed writing message rejection to TCP stream, skipping. ({stream_peer_addr})");
                    }
                }
            }

        });
    }

    Ok(())
}

pub fn start_shell(mut peer_addrs: Vec<SocketAddr>, passphrase: [u8; 32]) -> anyhow::Result<()> {
    let mut stdin = io::stdin().lock();

    log::debug!("Connecting to peer...");

    let mut streams = vec![];

    while let Some(peer_addr) = peer_addrs.first() {
        match TcpStream::connect(peer_addr) {
            Ok(stream) => {
                log::debug!("Successfully established connection with peer ({peer_addr})");
                peer_addrs.remove(0);
                streams.push(stream);
            },
            Err(_) => {
                log::warn!("Connection via TCP failed ({peer_addr}), retrying in 3000 millis...");
                thread::sleep(Duration::from_millis(3000));
            }
        };
    }

    log::info!("Connection successfully established with all peers.");

    let cipher = Cipher::new_256(&passphrase);

    let iv = gen_iv();
    log::debug!("Your generated IV: {:?}", iv);

    let iv_str = parse_vec_to_string(iv.to_vec());

    for stream in streams.iter_mut() {
        if stream.write(iv_str.as_bytes()).is_err() {
            match stream.peer_addr() {
                Ok(peer_addr) => log::warn!("Failed writing IV to the TCP stream ({}).", peer_addr),
                Err(_) => log::warn!("Failed writing IV to the TCP stream (unknown IP)"),
            }
        }
    }

    loop {
        let mut msg_buf = String::new();
        stdin.read_line(&mut msg_buf)?;
        let msg = msg_buf.trim();

        if msg.is_empty() {
            log::error!("Message cannot be empty.");
            continue;
        }

        let encrypted_msg = cipher.cbc_encrypt(&iv, msg.as_bytes());

        log::debug!("Message encryption successful.");

        let encrypted_msg_str = parse_vec_to_string(encrypted_msg);

        for stream in streams.iter_mut() {
            if stream.write(encrypted_msg_str.as_bytes()).is_err() {
                match stream.peer_addr() {
                    Ok(peer_addr) => log::warn!("Failed sending message to TCP stream ({}); not sent.", peer_addr),
                    Err(_) => log::warn!("Failed sending message to TCP stream (unknown IP); not sent."),
                }
            }
        }
    }
}

/// Handles all arguments besides none. Returns true if the app should continue after the arguments
/// are handled.
pub fn handle_other_arguments(args: Vec<String>) -> bool {
    let first_arg = args[1].clone();

    match first_arg.as_str() {
        "-v" | "--version" => println!("Version: {}", env::var("CARGO_PKG_VERSION").unwrap_or("could not detect Cargo version. Make sure you are running the program with the Rust's Cargo package manager.".to_string())),
        "-h" | "--help" => println!(
            "
-v or --version | Show program's version
-h or --help | Show this message
--with-logs | Run the program with env_logger initialized (outputs all logs to stdout)
            "
        ),
        "--with-logs" => {
            env::set_var("RUST_LOG", "debug");
            env_logger::init();
            return true;
        }
        _ => println!("Invalid first argument provided."),
    }

    false
}
