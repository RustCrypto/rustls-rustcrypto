use pki_types::{CertificateDer, PrivateKeyDer};
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::{sign, ServerConfig};
use rustls_provider_rustcrypto::sign::ecdsa::EcdsaSigningKey;
use rustls_provider_rustcrypto::Provider;
use std::io::{self};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::io::{copy, sink, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

struct TestResolvesServerCert(Arc<sign::CertifiedKey>);

impl TestResolvesServerCert {
    pub fn new(cert_chain: Vec<CertificateDer<'static>>, key_der: PrivateKeyDer<'_>) -> Self {
        let key: EcdsaSigningKey<p256::ecdsa::SigningKey> = key_der.try_into().unwrap();

        Self(Arc::new(sign::CertifiedKey::new(cert_chain, Arc::new(key))))
    }
}

impl ResolvesServerCert for TestResolvesServerCert {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

struct TestPki {
    server_cert_der: Vec<u8>,
    server_key_der: Vec<u8>,
}

impl TestPki {
    fn new() -> Self {
        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let mut ca_params = rcgen::CertificateParams::new(Vec::new());
        ca_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Rustls Server Acceptor");
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Example CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        ca_params.alg = alg;
        let ca_cert = rcgen::Certificate::from_params(ca_params).unwrap();

        // Create a server end entity cert issued by the CA.
        let mut server_ee_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]);
        server_ee_params.is_ca = rcgen::IsCa::NoCa;
        server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        server_ee_params.alg = alg;
        let server_cert = rcgen::Certificate::from_params(server_ee_params).unwrap();
        let server_cert_der = server_cert.serialize_der_with_signer(&ca_cert).unwrap();
        let server_key_der = server_cert.serialize_private_key_der();
        Self {
            server_cert_der,
            server_key_der,
        }
    }

    fn server_config<C: CryptoProvider>(&self) -> Arc<ServerConfig> {
        let mut server_config: ServerConfig = ServerConfig::builder_with_provider(&Provider)
            .with_safe_defaults()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(TestResolvesServerCert::new(
                vec![self.server_cert_der.clone().into()],
                PrivateKeyDer::Pkcs8(self.server_key_der.clone().into()),
            )));

        server_config.key_log = Arc::new(rustls::KeyLogFile::new());

        Arc::new(server_config)
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    env_logger::init();

    let pki = TestPki::new();
    let server_config = pki.server_config::<Provider>();
    let addr = "0.0.0.0:4443"
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::AddrNotAvailable))?;
    let acceptor = TlsAcceptor::from(server_config);

    let listener = TcpListener::bind(&addr).await?;

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();

        let fut = async move {
            let mut stream = acceptor.accept(stream).await?;

            let mut output = sink();
            stream
                .write_all(
                    &b"HTTP/1.0 200 ok\r\n\
                Connection: close\r\n\
                Content-length: 12\r\n\
                \r\n\
                Hello world!"[..],
                )
                .await?;
            stream.shutdown().await?;
            copy(&mut stream, &mut output).await?;
            println!("Hello: {}", peer_addr);

            Ok(()) as io::Result<()>
        };

        tokio::spawn(async move {
            if let Err(err) = fut.await {
                eprintln!("{:?}", err);
            }
        });
    }
}
