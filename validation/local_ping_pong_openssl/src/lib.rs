pub mod net_util;
pub mod openssl_util;
pub mod rustls_util;

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

        // rustls-rustcrypto Client thread
        let client_thread = thread::spawn(move || {
            let rustls_client = rustls_util::Client::new("certs/ca.rsa4096.crt", server_addr);

            let mut tls = rustls_client.tls;
            tls.write_all(b"PING\n").unwrap();
            let _ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
            let mut plaintext = Vec::new();
            tls.read_to_end(&mut plaintext).unwrap();

            assert_eq!(core::str::from_utf8(&plaintext), Ok("PONG\n"));

            return;
        });

        let timeout_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            panic!("timeout");
        });

        // OpenSSL Server Handler
        let server_thread = thread::spawn(move || {
            let path_ca_cert = Path::new("certs").join("ca.rsa4096.crt");
            let path_cert = Path::new("certs").join("rustcryp.to.rsa4096.ca_signed.crt");
            let path_key = Path::new("certs").join("rustcryp.to.rsa4096.key");

            let mut ssl_stream =
                openssl_util::accept_next(listener, path_ca_cert, path_cert, path_key);
            ssl_stream.accept().unwrap();

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
