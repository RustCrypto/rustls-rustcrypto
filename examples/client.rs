use std::str::FromStr;

use anyhow::anyhow;
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Uri};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use rustls_rustcrypto::provider;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Prepare the HTTPS connector
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(provider())?
        .https_or_http()
        .enable_all_versions()
        .build();

    // Build the hyper client from the HTTPS connector.
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

    // Prepare a chain of futures which sends a GET request, inspects
    // the returned headers, collects the whole body and prints it to
    // stdout.
    let fut = async move {
        let res = client
            .get(Uri::from_str("https://ecc256.badssl.com/")?)
            .await
            .map_err(|e| anyhow!("Could not get: {:?}", e))?;
        println!("Status:\n{}", res.status());
        println!("Headers:\n{:#?}", res.headers());

        let body = res
            .into_body()
            .collect()
            .await
            .map_err(|e| anyhow!("Could not get body: {:?}", e))?
            .to_bytes();

        println!("Body:\n{}", String::from_utf8_lossy(&body));

        Ok(())
    };

    fut.await
}
