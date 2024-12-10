pub mod net_util;
mod openssl_util;
pub use openssl_util::CipherSuites as OpenSslCipherSuites;
pub use openssl_util::GroupsList as OpenSslGroupsList;
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
    fn vs_openssl_as_client_autoneg() {
        vs_openssl_as_client(OpenSslGroupsList::default(), OpenSslCipherSuites::default());
    }

    #[test]
    #[should_panic] // No ciphers enabled for max supported SSL/TLS version
    fn vs_openssl_as_client_none() {
        let cipher_suites = OpenSslCipherSuites {
            TLS_AES_128_GCM_SHA256: false,
            TLS_AES_256_GCM_SHA384: false,
            TLS_CHACHA20_POLY1305_SHA256: false,
            TLS_AES_128_CCM_SHA256: false,
            TLS_AES_128_CCM_8_SHA256: false,
        };
        vs_openssl_as_client(OpenSslGroupsList::default(), cipher_suites);
    }

    #[test]
    fn vs_openssl_as_client_gcm_sha256() {
        let cipher_suites = OpenSslCipherSuites {
            TLS_AES_128_GCM_SHA256: true,
            TLS_AES_256_GCM_SHA384: false,
            TLS_CHACHA20_POLY1305_SHA256: false,
            TLS_AES_128_CCM_SHA256: false,
            TLS_AES_128_CCM_8_SHA256: false,
        };
        vs_openssl_as_client(OpenSslGroupsList::default(), cipher_suites);
    }

    #[test]
    fn vs_openssl_as_client_gcm_sha384() {
        let cipher_suites = OpenSslCipherSuites {
            TLS_AES_128_GCM_SHA256: false,
            TLS_AES_256_GCM_SHA384: true,
            TLS_CHACHA20_POLY1305_SHA256: false,
            TLS_AES_128_CCM_SHA256: false,
            TLS_AES_128_CCM_8_SHA256: false,
        };
        vs_openssl_as_client(OpenSslGroupsList::default(), cipher_suites);
    }

    #[test]
    fn vs_openssl_as_client_poly1305_sha256() {
        let cipher_suites = OpenSslCipherSuites {
            TLS_AES_128_GCM_SHA256: false,
            TLS_AES_256_GCM_SHA384: false,
            TLS_CHACHA20_POLY1305_SHA256: true,
            TLS_AES_128_CCM_SHA256: false,
            TLS_AES_128_CCM_8_SHA256: false,
        };
        vs_openssl_as_client(OpenSslGroupsList::default(), cipher_suites);
    }

    #[test]
    fn vs_openssl_as_client_ccm_sha256() {
        let cipher_suites = OpenSslCipherSuites {
            TLS_AES_128_GCM_SHA256: false,
            TLS_AES_256_GCM_SHA384: false,
            TLS_CHACHA20_POLY1305_SHA256: false,
            TLS_AES_128_CCM_SHA256: true,
            TLS_AES_128_CCM_8_SHA256: false,
        };
        vs_openssl_as_client(OpenSslGroupsList::default(), cipher_suites);
    }

    #[test]
    fn vs_openssl_as_client_ccm8_sha256() {
        let cipher_suites = OpenSslCipherSuites {
            TLS_AES_128_GCM_SHA256: false,
            TLS_AES_256_GCM_SHA384: false,
            TLS_CHACHA20_POLY1305_SHA256: false,
            TLS_AES_128_CCM_SHA256: false,
            TLS_AES_128_CCM_8_SHA256: true,
        };
        vs_openssl_as_client(OpenSslGroupsList::default(), cipher_suites);
    }

    #[test]
    #[should_panic]
    fn vs_openssl_as_client_group_none() {
        let group_list = OpenSslGroupsList::all_false();
        vs_openssl_as_client(group_list, OpenSslCipherSuites::default());
    }
    #[test]
    fn vs_openssl_as_client_group_p256() {
        let mut group_list = OpenSslGroupsList::all_false();
        group_list.P256 = true;
        vs_openssl_as_client(group_list, OpenSslCipherSuites::default());
    }
    #[test]
    fn vs_openssl_as_client_group_p384() {
        let mut group_list = OpenSslGroupsList::all_false();
        group_list.P384 = true;
        vs_openssl_as_client(group_list, OpenSslCipherSuites::default());
    }
    #[test]
    fn vs_openssl_as_client_group_p521() {
        let mut group_list = OpenSslGroupsList::all_false();
        group_list.P521 = true;
        vs_openssl_as_client(group_list, OpenSslCipherSuites::default());
    }
    #[test]
    fn vs_openssl_as_client_group_x25519() {
        let mut group_list = OpenSslGroupsList::all_false();
        group_list.X25519 = true;
        vs_openssl_as_client(group_list, OpenSslCipherSuites::default());
    }
    #[test]
    #[should_panic] // no support
    fn vs_openssl_as_client_group_x448() {
        let mut group_list = OpenSslGroupsList::all_false();
        group_list.X448 = true;
        vs_openssl_as_client(group_list, OpenSslCipherSuites::default());
    }

    fn vs_openssl_as_client(groups_list: OpenSslGroupsList, cipher_suites: OpenSslCipherSuites) {
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
            thread::sleep(Duration::from_millis(1_000));
            panic!("timeout");
        });

        // Server OpenSSL thread
        let server_thread = thread::spawn(move || {
            let mut openssl_server = OpenSslServer::from_listener(listener);
            let mut tls_stream = openssl_server.accept_next(
                groups_list,
                cipher_suites,
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
