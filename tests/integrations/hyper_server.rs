use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use super::pki::TestPki;
use bytes::Bytes;
use futures::StreamExt;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, service::service_fn, Method, Request, Response, StatusCode};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use indoc::indoc;
use pki_types::PrivateKeyDer;
use rustls::ServerConfig;
use tls_listener::TlsListener;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub const HTML_ROOT_CONTENT: &'static str = indoc! {r##"
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
    </head>
    <body>
        <h1>Hello World!</h1>
    </body>
</html>
"##};

pub const HTML_NOT_FOUND_CONTENT: &'static str = "404 NOT FOUND";

async fn serve(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    let res = match (req.method(), req.uri().path()) {
        // Index route.
        (&Method::GET, "/") => hyper::Response::builder()
            .header(hyper::header::CONTENT_TYPE, "text/html")
            .status(StatusCode::OK)
            .body(HTML_ROOT_CONTENT.into()),
        // Echo service route.
        (&Method::POST, "/echo") => hyper::Response::builder()
            .header(hyper::header::CONTENT_TYPE, "text/plain")
            .status(StatusCode::OK)
            .body(req.into_body().collect().await?.to_bytes().into()),
        // Catch-all 404.
        _ => hyper::Response::builder()
            .header(hyper::header::CONTENT_TYPE, "text/html")
            .status(StatusCode::NOT_FOUND)
            .body(HTML_NOT_FOUND_CONTENT.into()),
    }?;
    Ok(res)
}

pub async fn make_hyper_server() -> anyhow::Result<(
    tokio::task::JoinHandle<()>,
    SocketAddr,
    reqwest::Certificate,
)> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    let addr = listener.local_addr()?;

    let pki = TestPki::new(&rcgen::PKCS_ED25519);
    let (cert, key) = pki.sign(vec!["localhost".to_string(), "127.0.0.1".to_string()]);
    let mut server_config =
        ServerConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone().into()],
                PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    let server_config = Arc::new(server_config);
    let tls_acceptor = TlsAcceptor::from(server_config.clone());
    let service = service_fn(serve);

    Ok((
        tokio::spawn(
            TlsListener::new(tls_acceptor, listener).for_each_concurrent(
                None,
                move |s| async move {
                    match s {
                        Ok((stream, _)) => {
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
                },
            ),
        ),
        addr,
        reqwest::Certificate::from_der(pki.ca_cert().der())?,
    ))
}
