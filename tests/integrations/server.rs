use std::collections::HashMap;

use futures::TryFutureExt;
use hyper_server::{HTML_NOT_FOUND_CONTENT, HTML_ROOT_CONTENT};
use reqwest::Client;

#[tokio::test]
async fn test_hyper_server() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = rustls_rustcrypto::provider().install_default().unwrap();

    let (_server, addr, root_cert) = hyper_server::make_hyper_server().await?;
    let client = Client::builder().add_root_certificate(root_cert).build()?;
    {
        let body = client
            .get(format!("https://localhost:{}/", addr.port()))
            .send()
            .and_then(|x| x.text())
            .await?;
        assert_eq!(body, HTML_ROOT_CONTENT);
    }

    {
        let body = client
            .get(format!("https://127.0.0.1:{}/404", addr.port()))
            .send()
            .and_then(|x| x.text())
            .await?;
        assert_eq!(body, HTML_NOT_FOUND_CONTENT);
    }

    {
        let mut map: HashMap<String, String> = HashMap::new();
        map.insert("hello".to_string(), "world".to_string());
        map.insert("tls".to_string(), "rust".to_string());

        let body: HashMap<String, String> = client
            .post(format!("https://127.0.0.1:{}/echo", addr.port()))
            .json(&map)
            .send()
            .and_then(|x| x.json())
            .await?;
        assert_eq!(body, map);
    }

    Ok(())
}

mod hyper_server;
mod pki;
