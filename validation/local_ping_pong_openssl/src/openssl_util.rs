use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;

use openssl::ssl::{SslFiletype, SslMethod, SslStream};

mod groups_list;
pub use groups_list::GroupsList;

#[derive(Debug)]
#[allow(non_snake_case)]
pub struct CipherSuites {
    pub TLS_AES_128_GCM_SHA256: bool,
    pub TLS_AES_256_GCM_SHA384: bool,
    pub TLS_CHACHA20_POLY1305_SHA256: bool,
    pub TLS_AES_128_CCM_SHA256: bool,
    pub TLS_AES_128_CCM_8_SHA256: bool,
}

impl core::fmt::Display for CipherSuites {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        let mut vec_suites: Vec<&str> = vec![];
        if self.TLS_AES_128_GCM_SHA256 {
            vec_suites.push("TLS_AES_128_GCM_SHA256");
        }
        if self.TLS_AES_256_GCM_SHA384 {
            vec_suites.push("TLS_AES_256_GCM_SHA384");
        }
        if self.TLS_CHACHA20_POLY1305_SHA256 {
            vec_suites.push("TLS_CHACHA20_POLY1305_SHA256");
        }
        if self.TLS_AES_128_CCM_SHA256 {
            vec_suites.push("TLS_AES_128_CCM_SHA256");
        }
        if self.TLS_AES_128_CCM_8_SHA256 {
            vec_suites.push("TLS_AES_128_CCM_8_SHA256");
        }
        write!(f, "{}", vec_suites.join(":"))
    }
}

impl Default for CipherSuites {
    fn default() -> Self {
        CipherSuites {
            TLS_AES_128_GCM_SHA256: true,
            TLS_AES_256_GCM_SHA384: true,
            TLS_CHACHA20_POLY1305_SHA256: true,
            TLS_AES_128_CCM_SHA256: false,
            TLS_AES_128_CCM_8_SHA256: false,
        }
    }
}

pub struct Server {
    listener: TcpListener,
}

pub struct TlsStream {
    pub stream: SslStream<TcpStream>,
}

impl Server {
    pub fn from_listener(listener: TcpListener) -> Self {
        Self { listener }
    }
    pub fn accept_next(
        &mut self,
        groups_list: GroupsList,
        cipher_suites: CipherSuites,
        path_ca_cert: PathBuf,
        path_cert: PathBuf,
        path_key: PathBuf,
    ) -> TlsStream {
        let stream = match self.listener.incoming().next() {
            Some(stream_try) => match stream_try {
                Ok(stream) => stream,
                Err(_) => panic!("Failed OpenSSL accept_next()"),
            },
            None => panic!("No stream?"),
        };

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

        ssl_context_build
            .set_groups_list(&groups_list.to_string())
            .unwrap();

        ssl_context_build
            .set_ciphersuites(&cipher_suites.to_string())
            .unwrap();
        // https://docs.rs/openssl/latest/openssl/ssl/struct.SslContextBuilder.html#method.set_cipher_list
        // https://docs.rs/openssl/latest/openssl/ssl/struct.SslContextBuilder.html#method.set_ciphersuites
        ssl_context_build.check_private_key().unwrap();
        let ctx = ssl_context_build.build();
        let ssl = openssl::ssl::Ssl::new(&ctx).unwrap();
        let mut ssl_stream = SslStream::new(ssl, stream).unwrap();
        ssl_stream.accept().unwrap();
        TlsStream { stream: ssl_stream }
    }
}

impl TlsStream {
    pub fn wait_ping(&mut self) -> String {
        let mut buf_in = vec![0; 1024];
        let siz = self.stream.ssl_read(&mut buf_in);

        let incoming = match siz {
            Ok(i) => buf_in[0..i].to_vec(),
            Err(_e) => panic!("Error reading?"),
        };

        String::from_utf8_lossy(&incoming).to_string()
    }
    pub fn pong(&mut self) {
        let out = "PONG\n";
        self.stream.write_all(out.as_bytes()).unwrap();
    }
    pub fn shutdown(&mut self) {
        self.stream.shutdown().unwrap();
    }
}
