use std::{net::ToSocketAddrs, sync::Arc};

use futures_util::StreamExt;
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Bytes, Incoming},
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use pki_types::PrivateKeyDer;
use rustls::ServerConfig;
use rustls_rustcrypto::provider;
use tls_listener::{SpawningHandshakes, TlsListener};
use tokio::{net::TcpListener, signal::ctrl_c};
use tokio_rustls::TlsAcceptor;
struct TestPki {
    server_cert_der: Vec<u8>,
    server_key_der: Vec<u8>,
}

impl TestPki {
    fn new() -> Self {
        let alg = &rcgen::PKCS_ECDSA_P384_SHA384;
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

    let incoming = TcpListener::bind(&addr).await?;

    let mut server_config = ServerConfig::builder_with_provider(Arc::new(provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![pki.server_cert_der.clone().into()],
            PrivateKeyDer::Pkcs8(pki.server_key_der.clone().into()),
        )?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
    let service = service_fn(echo);

    println!("Starting to serve on https://{}.", addr);

    TlsListener::new(SpawningHandshakes(tls_acceptor), incoming)
        .take_until(ctrl_c())
        .for_each_concurrent(None, |s| {
            async {
                match s {
                    Ok((stream, remote_addr)) => {
                        println!("accepted client from {}", remote_addr);
                        if let Err(err) = Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(stream), service)
                            .await
                        {
                            eprintln!("failed to serve connection: {err:#}");
                        }
                    }
                    Err(e) => {
                        eprintln!("failed to perform tls handshake: {:?}", e);
                    }
                }
            }
        })
        .await;

    Ok(())
}

// Custom echo service, handling two different routes and a
// catch-all 404 responder.
async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let mut response = Response::new(Full::default());
    match (req.method(), req.uri().path()) {
        // Help route.
        (&Method::GET, "/") => {
            *response.body_mut() = Full::from("Try POST /echo\n");
        }
        // Echo service route.
        (&Method::POST, "/echo") => {
            *response.body_mut() = Full::from(req.into_body().collect().await?.to_bytes());
        }
        // Catch-all 404.
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    };
    Ok(response)
}
