use std::str::FromStr;

use anyhow::anyhow;
use hyper::{body::to_bytes, client, Body, Uri};
use rustls_provider_rustcrypto::Provider;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder_with_provider(&Provider)
        .with_safe_defaults()
        .with_custom_certificate_verifier(Provider::certificate_verifier(root_store))
        .with_no_client_auth();

    // Prepare the HTTPS connector
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_or_http()
        .enable_http1()
        .build();

    // Build the hyper client from the HTTPS connector.
    let client: client::Client<_, hyper::Body> = client::Client::builder().build(https);

    // Prepare a chain of futures which sends a GET request, inspects
    // the returned headers, collects the whole body and prints it to
    // stdout.
    let fut = async move {
        let res = client
            .get(Uri::from_str("https://youtube.com")?)
            .await
            .map_err(|e| anyhow!("Could not get: {:?}", e))?;
        println!("Status:\n{}", res.status());
        println!("Headers:\n{:#?}", res.headers());

        let body: Body = res.into_body();
        let body = to_bytes(body)
            .await
            .map_err(|e| anyhow!("Could not get body: {:?}", e))?;
        println!("Body:\n{}", String::from_utf8_lossy(&body));

        Ok(())
    };

    fut.await
}
