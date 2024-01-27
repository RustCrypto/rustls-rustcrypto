use std::str::FromStr;

use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Uri};
use hyper_rustls::HttpsConnector;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use rustls_rustcrypto::provider;

pub fn build_hyper_client() -> anyhow::Result<Client<HttpsConnector<HttpConnector>, Empty<Bytes>>> {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(provider())?
        .https_or_http()
        .enable_all_versions()
        .build();
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

    Ok(client)
}

// I'm not sure how to exactly extract the hyper TLS error result to pinpoint
// what error it should match For now treating it as a grand result is alright
pub async fn run_request(uri: &str) -> anyhow::Result<()> {
    let client = build_hyper_client()?;
    let uri = Uri::from_str(uri)?;
    let res = client.get(uri).await?;

    // We could definite check whether this is a HTML, but for now we don't really
    // care about the body content
    let bytes = res.into_body().collect().await?.to_bytes();

    println!("{:?}", bytes);

    Ok(())
}
