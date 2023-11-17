use std::{
    io::{self},
    net::ToSocketAddrs,
};

use hyper::{
    server::conn::AddrIncoming,
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server, StatusCode,
};
use hyper_rustls::TlsAcceptor;
use pki_types::PrivateKeyDer;
use rustls_provider_rustcrypto::Provider;

struct TestPki {
    server_cert_der: Vec<u8>,
    server_key_der:  Vec<u8>,
}

impl TestPki {
    fn new() -> Self {
        let alg = &rcgen::PKCS_ED25519;
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let pki = TestPki::new();
    let addr = "0.0.0.0:4443"
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::AddrNotAvailable))?;
    let incoming = AddrIncoming::bind(&addr)?;
    let acceptor = TlsAcceptor::builder()
        .with_provider_and_single_cert(
            &Provider,
            vec![pki.server_cert_der.clone().into()],
            PrivateKeyDer::Pkcs8(pki.server_key_der.clone().into()),
        )?
        .with_all_versions_alpn()
        .with_incoming(incoming);
    let service = make_service_fn(|_| async { Ok::<_, io::Error>(service_fn(echo)) });
    let server = Server::builder(acceptor).serve(service);

    // Run the future, keep going until an error occurs.
    println!("Starting to serve on https://{}.", addr);
    server.await?;
    Ok(())
}

// Custom echo service, handling two different routes and a
// catch-all 404 responder.
async fn echo(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let mut response = Response::new(Body::empty());
    match (req.method(), req.uri().path()) {
        // Help route.
        (&Method::GET, "/") => {
            *response.body_mut() = Body::from("Try POST /echo\n");
        }
        // Echo service route.
        (&Method::POST, "/echo") => {
            *response.body_mut() = req.into_body();
        }
        // Catch-all 404.
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    };
    Ok(response)
}
