use std::io::{Read, Write};

use std::fs::File;

use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslStream};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::pki_types::CertificateDer;
use rustls::pki_types::ServerName;

use rustls_rustcrypto::provider as rustcrypto_provider;

#[test]
fn local_ping_pong() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = listener.local_addr().unwrap();

    let mut ca_pkcs10_file = File::open("certs/ca.rsa4096.crt").unwrap();
    let mut ca_pkcs10_data: Vec<u8> = vec![];
    ca_pkcs10_file.read_to_end(&mut ca_pkcs10_data).unwrap();
    let (ca_type_label, ca_data) = pem_rfc7468::decode_vec(&ca_pkcs10_data).unwrap();
    assert_eq!(ca_type_label, "CERTIFICATE");
    let rustls_cert_der: CertificateDer = ca_data.try_into().unwrap();

    // rustls-rustcrypto Client thread
    let client_thread = thread::spawn(move || {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(rustls_cert_der).unwrap();

        let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustcrypto_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let mut conn = rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut sock = TcpStream::connect(server_addr).unwrap();
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);

        tls.write_all(b"PING\n").unwrap();

        let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();

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
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let mut ssl_context_build =
                        openssl::ssl::SslContext::builder(openssl::ssl::SslMethod::tls_server())
                            .unwrap();
                    ssl_context_build.set_verify(openssl::ssl::SslVerifyMode::NONE);
                    ssl_context_build
                        .set_ca_file("certs/ca.rsa4096.crt")
                        .unwrap();
                    ssl_context_build
                        .set_certificate_file(
                            "certs/rustcryp.to.rsa4096.ca_signed.crt",
                            openssl::ssl::SslFiletype::PEM,
                        )
                        .unwrap();
                    ssl_context_build
                        .set_private_key_file(
                            "certs/rustcryp.to.rsa4096.key",
                            openssl::ssl::SslFiletype::PEM,
                        )
                        .unwrap();
                    // https://docs.rs/openssl/latest/openssl/ssl/struct.SslContextBuilder.html#method.set_cipher_list
                    // https://docs.rs/openssl/latest/openssl/ssl/struct.SslContextBuilder.html#method.set_ciphersuites
                    ssl_context_build.check_private_key().unwrap();
                    let ctx = ssl_context_build.build();
                    let ssl = openssl::ssl::Ssl::new(&ctx).unwrap();

                    let mut ssl_stream = openssl::ssl::SslStream::new(ssl, stream).unwrap();
                    ssl_stream.accept().unwrap();
                    let mut buf_in = vec![0; 1024];
                    let siz = ssl_stream.ssl_read(&mut buf_in);

                    let incoming = match siz {
                        Ok(i) => buf_in[0..i].to_vec(),
                        Err(e) => panic!("Error reading?"),
                    };

                    assert_eq!(core::str::from_utf8(&incoming), Ok("PING\n"));

                    let out = "PONG\n";
                    ssl_stream.write(&out.as_bytes());

                    ssl_stream.shutdown().unwrap();
                }
                Err(e) => panic!("Connection failed"),
            }
            return;
        }
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
