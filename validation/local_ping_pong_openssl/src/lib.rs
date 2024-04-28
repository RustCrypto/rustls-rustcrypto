pub mod net_util;
pub mod openssl_util;

mod rustls_util;
pub use rustls_util::Client as RustCryptoTlsClient;

#[cfg(test)]
mod test {
    use super::*;

    use std::io::{Read, Write};
    use std::path::Path;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn vs_openssl_as_client() {
        let (listener, server_addr) = net_util::new_localhost_tcplistener();

        // Client rustls-rustcrypto thread
        let client_thread = thread::spawn(move || {
            let mut rustls_client = RustCryptoTlsClient::new("certs/ca.rsa4096.crt", server_addr);
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
            let path_ca_cert = Path::new("certs").join("ca.rsa4096.crt");
            let path_cert = Path::new("certs").join("rustcryp.to.rsa4096.ca_signed.crt");
            let path_key = Path::new("certs").join("rustcryp.to.rsa4096.key");

            let mut ssl_stream =
                openssl_util::accept_next(listener, path_ca_cert, path_cert, path_key);

            let mut buf_in = vec![0; 1024];
            let siz = ssl_stream.ssl_read(&mut buf_in);

            let incoming = match siz {
                Ok(i) => buf_in[0..i].to_vec(),
                Err(_e) => panic!("Error reading?"),
            };

            assert_eq!(core::str::from_utf8(&incoming), Ok("PING\n"));

            let out = "PONG\n";
            ssl_stream.write(&out.as_bytes()).unwrap();
            ssl_stream.shutdown().unwrap();
        });

        loop {
            thread::sleep(Duration::from_millis(10));
            if client_thread.is_finished() == true && server_thread.is_finished() == true {
                break;
            }
            if timeout_thread.is_finished() == true {
                panic!("TIMEOUT");
            }
        }

        client_thread.join().expect("Client thread panic");
        server_thread.join().expect("Server thread panic");
    }
}
