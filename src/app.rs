use libaes::Cipher;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{self, BufRead, Read, Write};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub enum ProxyMode {
    Hosting,
    Using,
    None,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ValidMessage {
    Encrypted(Vec<u8>),
    Plaintext(String),
}

/// Read message transmittion in the docs for more information.
#[derive(Deserialize, Serialize, Debug)]
pub struct Message {
    pub iv: Option<[u8; 32]>,
    pub message_is_from_proxy: bool,
    pub message: ValidMessage,
}

pub struct FinalMessage {
    pub peer: SocketAddr,
    pub message: String,
}

// If the message written to the stream is bigger than the maximum buffer size, it will create a
// new buffer as if it was a separate message.
pub const MAX_BUF_SIZE: usize = 1024;

pub fn gen_iv() -> [u8; 32] {
    let mut rng = rand::thread_rng();
    let mut iv: [u8; 32] = [0; 32];

    for i in 0..iv.len() {
        iv[i] = rng.gen_range(0..128);
    }

    iv
}

/// The main application's function. it is responsible for handling the TCP listener, the incoming
/// streams and the sending user's messages.
pub fn init(
    port: u16,
    peer_addrs: HashSet<SocketAddr>,
    passphrase: Option<String>,
    proxy_mode: ProxyMode,
) -> anyhow::Result<()> {
    let (message_tx, message_rx): (Sender<FinalMessage>, Receiver<FinalMessage>) = mpsc::channel();

    let mut passphrase_fixed: Option<[u8; 32]> = None;

    if let Some(passphrase) = passphrase {
        passphrase_fixed = Some([0; 32]);
        passphrase
            .as_bytes()
            .iter()
            .enumerate()
            .for_each(|(i, b)| passphrase_fixed.unwrap()[i] = *b);
    }

    log::debug!("Fixed size passphrase: {:?}", passphrase_fixed);

    let peer_addr_ip_only = peer_addrs
        .iter()
        .map(|socket| socket.ip())
        .collect::<HashSet<IpAddr>>();

    thread::spawn(move || {
        start_shell(Vec::from_iter(peer_addrs), passphrase_fixed, proxy_mode).map_err(|e| {
            eprintln!("{}", e);
            std::process::exit(1);
        })
    });
    thread::spawn(move || {
        start_server(message_tx, peer_addr_ip_only, port, passphrase_fixed).map_err(|e| {
            eprintln!("{}", e);
            std::process::exit(1);
        })
    });

    loop {
        let msg = message_rx.recv()?;

        println!("{}: {}", msg.peer, msg.message);
    }
}

/// Starts the main thread for the server which listens to the given port.
pub fn start_server(
    message_tx: Sender<FinalMessage>,
    peer_addrs: HashSet<IpAddr>,
    port: u16,
    passphrase: Option<[u8; 32]>,
) -> io::Result<()> {
    let listener = match TcpListener::bind(format!("0.0.0.0:{port}")) {
        Ok(listener) => listener,
        _ => return Err(io::Error::new(io::ErrorKind::Other, "Failed listening to given port. Maybe the program doesn't have the required privileges or another program is already listening to that port?")),
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
                _ => {
                    log::warn!(
                        "Something went wrong whilst getting stream, skipping. Possibly invalid data?"
                    );
                    return;
                }
            };

            let passphrase = passphrase_clone;

            let cipher = if let Some(passphrase) = passphrase {
                Some(Cipher::new_256(&passphrase))
            } else {
                None
            };

            let mut stream = stream;

            let message_tx = message_tx_clone;
            let peer_addrs = peer_addrs_clone;

            let stream_peer_addr = match stream.peer_addr() {
                Ok(peer_addr) => peer_addr,
                _ => {
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

            log::debug!(
                "Peer successfully established connection on their end ({stream_peer_addr})"
            );

            loop {
                let mut data_buf: [u8; MAX_BUF_SIZE] = [0; MAX_BUF_SIZE];

                loop {
                    match stream.read(&mut data_buf) {
                        Ok(_) => break,
                        _ => {}
                    };
                }

                let data = match std::str::from_utf8(&data_buf) {
                    Ok(data) => data.trim(),
                    _ => {
                        log::error!("Peer's message doesn't contain valid UTF-8 data, not processing. ({stream_peer_addr})");
                        continue;
                    }
                };

                let mut closing_curly_bracket_index = None;

                for (i, c) in data.chars().enumerate() {
                    if c == '}' {
                        closing_curly_bracket_index = Some(i);
                    }
                }

                let closing_curly_bracket_index = match closing_curly_bracket_index {
                    Some(index) => index,
                    None => {
                        log::error!("Invalid JSON data found, skipping message.");
                        continue;
                    }
                };

                let data = data[..closing_curly_bracket_index+1].to_string();

                let data = data.as_str();

                let recv_full_msg: Message = match serde_json::from_str(data) {
                    Ok(data) => data,
                    _ => {
                        log::error!("Invalid JSON data, skipping message.");
                        continue;
                    }
                };

                log::debug!("Full received message: {recv_full_msg:?}");

                let mut final_msg = FinalMessage {
                    peer: stream_peer_addr,
                    message: String::new(),
                };

                if let Some(cipher) = &cipher {
                    let msg = match recv_full_msg.message {
                        ValidMessage::Encrypted(msg) => msg,
                        _ => {
                            log::error!("Received a plaintext message even though the server is configured to use ciphertext.");
                            continue;
                        }
                    };

                    let iv = match recv_full_msg.iv {
                        Some(iv) => iv,
                        _ => {
                            log::error!("Message doesn't contain IV even though the server is configured to use ciphertext.");
                            continue;
                        }
                    };

                    log::debug!("Peer's IV: {:?} ({stream_peer_addr})", iv);

                    let msg_dec = cipher.cbc_decrypt(&iv, msg.as_slice());

                    let msg_plaintext = match std::string::String::from_utf8(msg_dec) {
                        Ok(plaintext) => plaintext,
                        _ => {
                            log::error!(
                                "Received message isn't valid UTF-8 data, not showing message."
                            );
                            continue;
                        }
                    };

                    if !msg_plaintext.is_empty() {
                        final_msg.message = msg_plaintext;
                    } else {
                        log::warn!("Received empty message, skipping.");
                        if stream.write(b"Message cannot be empty.").is_err() {
                            log::warn!("Failed writing message rejection to TCP stream, skipping. ({stream_peer_addr})");
                        }
                        continue;
                    }
                } else {
                    final_msg.message = match recv_full_msg.message {
                        ValidMessage::Plaintext(msg) => {
                            if msg.len() > 0 {
                                msg
                            } else {
                                log::warn!("Received empty message, skipping.");
                                continue;
                            }
                        }
                        _ => {
                            log::error!("Received an encrypted message even though the server is configured to use plaintext.");
                            continue;
                        }
                    };
                }

                if message_tx.send(final_msg).is_err() {
                    log::warn!("Failed transmitting stream's message. ({stream_peer_addr})");
                } else {
                    log::debug!("Successfully transmitting client's message. ({stream_peer_addr})");
                }
            }
        });
    }

    Ok(())
}

pub fn start_shell(
    mut peer_addrs: Vec<SocketAddr>,
    passphrase: Option<[u8; 32]>,
    proxy_mode: ProxyMode,
) -> anyhow::Result<()> {
    let mut stdin = io::stdin().lock();

    log::debug!("Connecting to peer...");

    let mut streams = vec![];

    while let Some(peer_addr) = peer_addrs.first() {
        match TcpStream::connect(peer_addr) {
            Ok(stream) => {
                log::debug!("Successfully established connection with peer ({peer_addr})");
                peer_addrs.remove(0);
                streams.push(stream);
            }
            _ => {
                log::warn!("Connection via TCP failed ({peer_addr}), retrying in 3000 millis...");
                thread::sleep(Duration::from_millis(3000));
            }
        };
    }

    log::info!("Connection successfully established with all peers.");

    let cipher = if let Some(passphrase) = passphrase {
        Some(Cipher::new_256(&passphrase))
    } else {
        log::warn!("Connection is unencrypted, messages sent are plaintext.");
        None
    };

    loop {
        let mut msg_buf = String::new();
        stdin.read_line(&mut msg_buf)?;
        let msg = msg_buf.trim();

        if msg.is_empty() {
            log::error!("Message cannot be empty.");
            continue;
        }

        let message_is_from_proxy = if proxy_mode == ProxyMode::Using {
            true
        } else {
            false
        };

        let final_msg = if let Some(cipher) = &cipher {
            let iv = gen_iv();
            log::debug!("Your generated IV: {:?}", iv);

            let encrypted_msg = cipher.cbc_encrypt(&iv, msg.as_bytes());

            log::debug!("Message encryption successful.");

            let msg_con = Message {
                iv: Some(iv),
                message: ValidMessage::Encrypted(encrypted_msg),
                message_is_from_proxy,
            };

            match serde_json::to_string(&msg_con) {
                Ok(msg_con) => msg_con,
                _ => {
                    log::error!("Failed parsing message to JSON, not sending message.");
                    continue;
                }
            }
        } else {
            let msg_con = Message {
                message: ValidMessage::Plaintext(msg.to_string()),
                iv: None,
                message_is_from_proxy,
            };

            match serde_json::to_string(&msg_con) {
                Ok(msg_con) => msg_con,
                _ => {
                    log::error!("Failed parsing message to JSON, not sending message.");
                    continue;
                }
            }
        };

        log::debug!("Final message to be sent: {final_msg:?}");

        for stream in streams.iter_mut() {
            if stream.write(final_msg.as_bytes()).is_err() {
                match stream.peer_addr() {
                    Ok(peer_addr) => log::warn!(
                        "Failed sending message to TCP stream ({}); not sent.",
                        peer_addr
                    ),
                    _ => log::warn!("Failed sending message to TCP stream (unknown IP); not sent."),
                }
            }
        }
    }
}
