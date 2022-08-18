# tcp-encrypted-chat

Simple peer-to-peer encrypted chat written in Rust.

## How it works

This program uses the Transmission Control Protocol (TCP) for the peers to communicate. It uses the [libaes](crates.io/crates/libaes) crate for AES-256-CBC encryption on both ends and it uses Rust's std::net built-in module for establishing and listening for incoming TCP streams. The program runs the server listening to the given port on a separate thread and there is another thread which works like a "shell" which has control over stdin.

## Why I made this

I made this project because I wanted to understand how TCP streams work.

## Usage

Upon starting the program, you have to enter the following things:

- The port the server should listen to
- The peer's socket address (e.g. <code>57.11.125.99:5542</code>). If there is more than one peer you want to send your messages to, add extra socket addresses separated by commas (e.g. <code>57.11.125.99:5542,92.69.22.21:3002</code>)
- The passphrase for message encryption and decryption (has to be exactly 32 characters long, all peers have to use the same one because AES is symmetric)

If the connection isn't successfully established with the peer(s), it will keep retrying to connect until it successfully establishes a connection. Have fun!
