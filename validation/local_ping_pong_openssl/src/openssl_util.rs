use openssl::ssl::{SslFiletype, SslMethod, SslStream};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;

pub fn accept_next(
    listener: TcpListener,
    path_ca_cert: PathBuf,
    path_cert: PathBuf,
    path_key: PathBuf,
) -> SslStream<TcpStream> {
    if let Some(stream) = listener.incoming().next() {
        match stream {
            Ok(stream) => {
                let mut ssl_context_build =
                    openssl::ssl::SslContext::builder(SslMethod::tls_server()).unwrap();
                ssl_context_build.set_verify(openssl::ssl::SslVerifyMode::NONE);

                ssl_context_build.set_ca_file(path_ca_cert).unwrap();
                ssl_context_build
                    .set_certificate_file(path_cert, SslFiletype::PEM)
                    .unwrap();

                ssl_context_build
                    .set_private_key_file(path_key, SslFiletype::PEM)
                    .unwrap();
                // https://docs.rs/openssl/latest/openssl/ssl/struct.SslContextBuilder.html#method.set_cipher_list
                // https://docs.rs/openssl/latest/openssl/ssl/struct.SslContextBuilder.html#method.set_ciphersuites
                ssl_context_build.check_private_key().unwrap();
                let ctx = ssl_context_build.build();
                let ssl = openssl::ssl::Ssl::new(&ctx).unwrap();
                let mut ssl_stream = SslStream::new(ssl, stream).unwrap();
                ssl_stream.accept().unwrap();
                return ssl_stream;
            }
            Err(_) => panic!("Failed OpenSSL accept_next()"),
        }
    } else {
        panic!("No stream.");
    }
}
