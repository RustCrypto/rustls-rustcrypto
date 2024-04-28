use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::sync::Arc;

use rustls_rustcrypto::provider as rustcrypto_provider;

use rustls::RootCertStore;
use rustls::StreamOwned as RustlsStreamOwned;
use rustls::{ClientConfig, ClientConnection};

use rustls::pki_types::CertificateDer;
use rustls::pki_types::ServerName;

/// Read rustls compatible CertificateDer from ca_path
pub fn load_ca_der(ca_path: &str) -> CertificateDer {
    let mut ca_pkcs10_file = File::open(ca_path).unwrap();
    let mut ca_pkcs10_data: Vec<u8> = vec![];
    ca_pkcs10_file.read_to_end(&mut ca_pkcs10_data).unwrap();
    let (ca_type_label, ca_data) = pem_rfc7468::decode_vec(&ca_pkcs10_data).unwrap();
    assert_eq!(ca_type_label, "CERTIFICATE");
    ca_data.try_into().unwrap()
}

/// provide rustls roots with pinned CA cert
pub fn roots(ca_pinned: CertificateDer) -> RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_pinned).unwrap();
    roots
}

/// Create new ClientConfig
pub fn rustcrypto_client_config(root_store: RootCertStore) -> ClientConfig {
    rustls::ClientConfig::builder_with_provider(Arc::new(rustcrypto_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

#[derive(Debug)]
pub struct Client {
    pub tls: RustlsStreamOwned<ClientConnection, TcpStream>,
}

impl Client {
    pub fn new(ca_pinned: &str, server_addr: SocketAddr) -> Self {
        let ca = load_ca_der(ca_pinned);
        let roots = roots(ca);
        let config = rustcrypto_client_config(roots);

        let conn = rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();

        let sock = TcpStream::connect(server_addr).unwrap();
        let tls = rustls::StreamOwned::new(conn, sock);

        Self { tls }
    }
}
