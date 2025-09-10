use std::io::{Read, Write};
use std::sync::{Arc, OnceLock};

use fake_cert_server_resolver::FakeServerCertResolver;
use fake_time::FakeTime;
use itertools::iproduct;
use mem_socket::MemorySocket;
use rand_core::{OsRng, TryRngCore};
use rustls::crypto::CryptoProvider;
use rustls::{
    ClientConfig as RusTlsClientConfig, RootCertStore, ServerConfig as RusTlsServerConfig,
};
use rustls_rustcrypto::{Provider, provider as rustcrypto_provider, verify};

mod fake_cert_server_resolver;
mod fake_time;

static SERVER_RESOLVER: OnceLock<Arc<FakeServerCertResolver>> = OnceLock::new();

fn make_client_config(provider: CryptoProvider) -> RusTlsClientConfig {
    let resolver = SERVER_RESOLVER.get_or_init(|| Arc::new(FakeServerCertResolver::new()));
    let mut store = RootCertStore::empty();

    store.add(resolver.rsa_root_cert()).unwrap();
    store.add(resolver.ecdsa_root_cert()).unwrap();

    RusTlsClientConfig::builder_with_details(Arc::new(provider), Arc::new(FakeTime {}))
        .with_safe_default_protocol_versions()
        .expect("Default protocol versions error?")
        .with_root_certificates(store)
        // .dangerous()
        // .with_custom_certificate_verifier(Arc::new(FakeServerCertVerifier {}))
        .with_no_client_auth()
}

fn make_server_config(provider: CryptoProvider) -> RusTlsServerConfig {
    let resolver = SERVER_RESOLVER
        .get_or_init(|| Arc::new(FakeServerCertResolver::new()))
        .clone();
    RusTlsServerConfig::builder_with_details(Arc::new(provider), Arc::new(FakeTime {}))
        .with_safe_default_protocol_versions()
        .expect("Default protocol versions error?")
        .with_no_client_auth()
        .with_cert_resolver(resolver)
}

// Test integration between rustls and rustls in Client builder context
#[test]
fn integrate_client_builder_with_details_fake() {
    // Out of scope
    let rustls_client_config = make_client_config(rustcrypto_provider());

    // RustCrypto is not fips
    assert!(!rustls_client_config.fips());
}

// Test integration between rustls and rustls in Server builder context
#[test]
fn integrate_server_builder_with_details_fake() {
    let rustls_server_config = make_server_config(rustcrypto_provider());

    // RustCrypto is not fips
    assert!(!rustls_server_config.fips());
}

const CLIENT_MAGIC: &[u8; 18] = b"Hello from Client!";
const SERVER_MAGIC: &[u8; 18] = b"Hello from Server!";

// Test integration
#[test]
fn test_basic_round_trip() {
    std::thread::scope(move |s| {
        for provider in generate_providers() {
            let base_name = format!(
                "{:?}-{:?}",
                provider.cipher_suites[0], provider.kx_groups[0]
            );
            // Creates a pair of sockets that interconnect from client to server, and server to client
            let (socket_c2s, socket_s2c) = MemorySocket::new_pair();

            let mut random_data: [u8; 64 * 1024] = [0; 64 * 1024];
            OsRng.try_fill_bytes(&mut random_data).unwrap();

            std::thread::Builder::new()
                .name(format!("{base_name}-server"))
                .spawn_scoped(s, {
                    let provider: CryptoProvider = provider.clone();
                    move || {
                        let config = Arc::new(make_server_config(provider));
                        let mut stream = socket_s2c;
                        let mut conn = rustls::ServerConnection::new(config.clone())
                            .expect("failed to create server config");

                        let mut tls = rustls::Stream::new(&mut conn, &mut stream);

                        {
                            let mut buf = [0; CLIENT_MAGIC.len()];
                            tls.read_exact(&mut buf).unwrap();
                            assert_eq!(&buf, CLIENT_MAGIC);
                        }

                        tls.write_all(SERVER_MAGIC)
                            .expect("failed to write to client");
                        tls.write_all(&random_data)
                            .expect("failed to write random data to client");
                        tls.conn.send_close_notify();
                        tls.flush().expect("failed to flush connection");
                    }
                })
                .unwrap();

            std::thread::Builder::new()
                .name(format!("{base_name}-client"))
                .spawn_scoped(s, move || {
                    let mut sock = socket_c2s;
                    let server_name = "acme.com".try_into().expect("failed to get server name");
                    let mut conn = rustls::ClientConnection::new(
                        Arc::new(make_client_config(provider)),
                        server_name,
                    )
                    .expect("failed to create client config");
                    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
                    tls.write_all(CLIENT_MAGIC)
                        .expect("failed to write to server");

                    {
                        let mut buf = [0; SERVER_MAGIC.len()];
                        tls.read_exact(&mut buf)
                            .expect("failed to read from server");
                        assert_eq!(&buf, SERVER_MAGIC);
                    }

                    {
                        let mut plaintext = Vec::new();
                        tls.write_all(&random_data)
                            .expect("failed to write random data to server");
                        tls.read_to_end(&mut plaintext)
                            .expect("failed to read from server");
                        assert_eq!(plaintext, random_data);
                    }
                })
                .unwrap();
        }
    });
}

fn generate_providers() -> impl Iterator<Item = CryptoProvider> {
    let CryptoProvider {
        cipher_suites,
        kx_groups,
        ..
    } = rustcrypto_provider();

    iproduct!(cipher_suites, kx_groups).map(|(cipher_suite, kx_group)| CryptoProvider {
        cipher_suites: vec![cipher_suite],
        kx_groups: vec![kx_group],
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &Provider,
        key_provider: &Provider,
    })
}

mod mem_socket;
