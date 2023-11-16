use std::{str::FromStr, sync::Arc};

use hyper::{body::to_bytes, client, client::HttpConnector, Body, Uri};
use hyper_rustls::HttpsConnector;
use rustls_provider_rustcrypto::Provider;

pub fn build_hyper_client() -> client::Client<HttpsConnector<HttpConnector>, hyper::Body> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder_with_provider(&Provider)
        .with_safe_defaults()
        .dangerous()
        .with_custom_certificate_verifier(Provider::certificate_verifier(Arc::new(root_store)))
        .with_no_client_auth();

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_or_http()
        .enable_all_versions()
        .build();

    client::Client::builder().build(https)
}

// I'm not sure how to exactly extract the hyper TLS error result to pinpoint
// what error it should match For now treating it as a grand result is alright
pub async fn run_request(uri: &str) -> anyhow::Result<()> {
    let client = build_hyper_client();
    let uri = Uri::from_str(uri)?;
    let res = client.get(uri).await?;
    let body: Body = res.into_body();

    // We could definite check whether this is a HTML, but for now we don't really
    // care about the body content
    to_bytes(body).await?;

    Ok(())
}
