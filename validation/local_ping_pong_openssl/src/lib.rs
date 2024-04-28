pub mod net_util;
mod openssl_util;
pub use openssl_util::Server as OpenSslServer;

mod rustls_util;
pub use rustls_util::Client as RustCryptoTlsClient;

#[cfg(test)]
mod test {
    use super::*;

    use std::path::Path;
    use std::thread;
    use std::time::Duration;

    const CA_CERT: &'static str = "ca.rsa4096.crt";
    const CERT: &'static str = "rustcryp.to.rsa4096.ca_signed.crt";
    const RSA_KEY: &'static str = "rustcryp.to.rsa4096.key";

    #[test]
    fn vs_openssl_as_client() {
        let path_certs = Path::new("certs");

        let (listener, server_addr) = net_util::new_localhost_tcplistener();

        // Client rustls-rustcrypto thread
        let client_thread = thread::spawn(move || {
            let mut rustls_client = RustCryptoTlsClient::new(path_certs.join(CA_CERT), server_addr);
            rustls_client.ping();
            assert_eq!(rustls_client.wait_pong(), "PONG\n");
            return;
        });

        // Canary Timeout thread
        let timeout_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            panic!("timeout");
        });

        // Server OpenSSL thread
        let server_thread = thread::spawn(move || {
            let mut openssl_server = OpenSslServer::from_listener(listener);
            let mut tls_stream = openssl_server.accept_next(
                path_certs.join(CA_CERT),
                path_certs.join(CERT),
                path_certs.join(RSA_KEY),
            );

            assert_eq!(tls_stream.wait_ping(), "PING\n");
            tls_stream.pong();
            tls_stream.shutdown();
        });

        loop {
            thread::sleep(Duration::from_millis(10));

            if client_thread.is_finished() && server_thread.is_finished() {
                break;
            }
            if timeout_thread.is_finished() {
                panic!("TIMEOUT");
            }
        }

        client_thread.join().expect("Client thread panic");
        server_thread.join().expect("Server thread panic");
    }
}
