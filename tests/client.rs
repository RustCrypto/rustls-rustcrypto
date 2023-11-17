use std::str::FromStr;

use hyper::{body::to_bytes, client, client::HttpConnector, Body, Uri};
use hyper_rustls::HttpsConnector;
use rustls_rustcrypto::Provider;

pub fn build_hyper_client(
) -> anyhow::Result<client::Client<HttpsConnector<HttpConnector>, hyper::Body>> {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(&Provider)
        .https_or_http()
        .enable_all_versions()
        .build();

    Ok(client::Client::builder().build(https))
}

// I'm not sure how to exactly extract the hyper TLS error result to pinpoint
// what error it should match For now treating it as a grand result is alright
pub async fn run_request(uri: &str) -> anyhow::Result<()> {
    let client = build_hyper_client()?;
    let uri = Uri::from_str(uri)?;
    let res = client.get(uri).await?;
    let body: Body = res.into_body();

    // We could definite check whether this is a HTML, but for now we don't really
    // care about the body content
    let bytes = to_bytes(body).await?;

    println!("{:?}", bytes);

    Ok(())
}
