use std::net::{SocketAddr, TcpListener};

/// Create a new TcpListener on localhost on random port
pub fn new_localhost_tcplistener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = listener.local_addr().unwrap();
    (listener, server_addr)
}
