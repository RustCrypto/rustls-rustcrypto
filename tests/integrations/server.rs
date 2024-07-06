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
    Ok(())
}

mod hyper_server;
mod pki;
