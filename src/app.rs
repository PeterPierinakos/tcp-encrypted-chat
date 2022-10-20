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
pub fn parse_stringified_slice(msg: String) -> io::Result<Vec<u8>>
{
    let mut msg_no_weird_chars = String::new();

    let illegal_chars = HashSet::from(['[', ']', ' ', '\0']);

    for c in msg.chars() {
        if !illegal_chars.contains(&c) {
            msg_no_weird_chars.push(c);
        }
    }

    let msg_splitted = msg_no_weird_chars.split(",").collect::<Vec<&str>>();

    let mut vec = vec![];

    for num in msg_splitted {
        let num = match num.parse::<u8>() {
            Ok(num) => num,
            Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Slice has an illegal character (\"{num}\")."))),
        };

        vec.push(num);
    }
    
    Ok(vec)
}

/// The main application's function. it is responsible for handling the TCP listener, the incoming
/// streams and the sending user's messages.
pub fn init(port: u16, peer_addrs: HashSet<SocketAddr>, passphrase: Option<String>) -> anyhow::Result<()> {
    let (message_tx, message_rx): (Sender<Message>, Receiver<Message>) = mpsc::channel();

    let mut passphrase_fixed: Option<[u8; 32]> = None;

    if let Some(passphrase) = passphrase {
        passphrase_fixed = Some([0; 32]);
        passphrase.as_bytes().iter().enumerate().for_each(|(i, b)| passphrase_fixed.unwrap()[i] = *b);
    }

    log::debug!("Fixed size passphrase: {:?}", passphrase_fixed);

    let peer_addr_ip_only = peer_addrs.iter().map(|socket| socket.ip()).collect::<HashSet<IpAddr>>();

    thread::spawn(move || {
        start_shell(Vec::from_iter(peer_addrs), passphrase_fixed).map_err(|e| {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    )});
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
pub fn start_server(message_tx: Sender<Message>, peer_addrs: HashSet<IpAddr>, port: u16, passphrase: Option<[u8; 32]>) -> io::Result<()> {
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

            loop {
                let mut data_buf: [u8; MAX_BUF_SIZE] = [0; MAX_BUF_SIZE];

                loop {
                    match stream.read(&mut data_buf) {
                        Ok(_) => break,
                        Err(_) => {}
                    };
                }

                let data = match std::str::from_utf8(&data_buf) {
                    Ok(data) => data,
                    Err(_) => {
                        log::error!("Peer's message doesn't contain valid UTF-8 data, not processing. ({stream_peer_addr})");
                        continue;
                    }
                };

                let mut final_msg = Message { peer: stream_peer_addr, message: String::new() };

                if let Some(cipher) = &cipher {
                    // The first line is the IV and the rest is the message being sent
                    let data_split = data.to_string();
                    let data_split = data_split.split('\n').collect::<Vec<&str>>();

                    // Treat the text before the newline as the IV and the rest as the ciphertext (as
                    // seen with the comments below)
                    let iv_buf = data_split[0];

                    let iv_utf8 = match std::str::from_utf8(iv_buf.trim().as_bytes()) {
                        Ok(iv_utf8) => iv_utf8,
                        Err(_) => {
                            log::error!("Peer's IV doesn't contain valid UTF-8 data, not processing. ({stream_peer_addr})");
                            continue;
                        },
                    };

                    let iv = match parse_stringified_slice(iv_utf8.to_string()) {
                        Ok(iv) => iv,
                        Err(_) => {
                            log::error!("Peer's IV contains invalid data. ({stream_peer_addr})");
                            continue;
                        },
                    };

                    log::debug!("Peer's IV: {iv:?} ({stream_peer_addr})");

                    // If more than one newline was found (the first one is reserved for IV), then the
                    // rest which is the ciphertext to be sent will be joined together into a single
                    // string. This string may look something like this in some cases if extra newlines
                    // exist:
                    // [23,64,92,77][11,44,99]
                    let msg = data_split[1..].to_vec().iter().map(|item| *item).collect::<String>();

                    // Parsed byte slice from all the messages
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
                        final_msg.message = msg_plaintext;
                    } else {
                        log::warn!("Received empty message, skipping.");
                        if stream.write(b"Message cannot be empty.").is_err() {
                            log::warn!("Failed writing message rejection to TCP stream, skipping. ({stream_peer_addr})");
                        }
                        continue;
                    }
                } else {
                    let data = data.trim();

                    if data.len() > 0 {
                        final_msg.message = data.trim().to_string();
                    } else {
                        log::warn!("Received empty message, skipping.");
                    }
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

pub fn start_shell(mut peer_addrs: Vec<SocketAddr>, passphrase: Option<[u8; 32]>) -> anyhow::Result<()> {
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

        let iv = gen_iv();
        log::debug!("Your generated IV: {:?}", iv);

        let iv_str = parse_vec_to_string(iv.to_vec());
        let iv_str = iv_str.as_str();

        let final_msg =  if let Some(cipher) = &cipher {
            let encrypted_msg = cipher.cbc_encrypt(&iv, msg.as_bytes());

            log::debug!("Message encryption successful.");

            let encrypted_msg_str = parse_vec_to_string(encrypted_msg);

            [iv_str, "\n", encrypted_msg_str.as_str()].concat()
        } else {
            msg.to_string()
        };

        for stream in streams.iter_mut() {
            if stream.write(final_msg.as_bytes()).is_err() {
                match stream.peer_addr() {
                    Ok(peer_addr) => log::warn!("Failed sending message to TCP stream ({}); not sent.", peer_addr),
                    Err(_) => log::warn!("Failed sending message to TCP stream (unknown IP); not sent."),
                }
            }
        }
    }
}
