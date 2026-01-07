use env_logger::Env;
use gm_quic::handy::{client_parameters, server_parameters};
use gm_quic::{QuicClient, QuicListeners};
use log::{debug, error, info, trace};
use rustls::crypto::CryptoProvider;
use rustls_rustcrypto::provider as rustcrypto_provider;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{self, AsyncWriteExt};
use tokio::task::JoinSet;

const CLIENT_COUNT: usize = 16;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("trace")).init();

    info!("Rustls Real Socket TLS Test Starting...");
    // Initialize rustls with rustcrypto provider
    let provider = Arc::new(rustcrypto_provider());
    info!("Rustcrypto provider initialized");

    let mut set = JoinSet::new();

    set.spawn({
        let provider = provider.clone();
        async move {
            if let Err(e) = run_quic_server(provider.clone()).await {
                error!("QUIC server error: {}", e);
            }
        }
    });

    for i in 0..CLIENT_COUNT {
        set.spawn({
            let provider = provider.clone();
            async move {
                if let Err(e) = run_quic_client(provider, i).await {
                    error!("QUIC client error: {}", e);
                }
            }
        });
    }

    set.join_all().await;

    Ok(())
}

async fn run_quic_server(provider: Arc<CryptoProvider>) -> anyhow::Result<()> {
    let listeners = QuicListeners::builder_with_crypto_provieder(provider)?
        .without_client_cert_verifier()
        .with_parameters(server_parameters())
        .defer_idle_timeout(Duration::from_secs(0))
        .enable_0rtt()
        .listen(4096);
    listeners.add_server(
        "foo",
        include_bytes!("cert.der"),
        include_bytes!("key.der"),
        ["127.0.0.1:4443", "[::1]:4443"],
        None,
    )?;

    let mut total_conn = 0;

    loop {
        if total_conn >= CLIENT_COUNT {
            break Ok(());
        }
        let (connection, _server, pathway, ..) = listeners.accept().await?;
        info!("accepted new connection from {:?}", pathway.remote());
        total_conn += 1;
        tokio::spawn(async move {
            while let Ok((_sid, (mut reader, mut writer))) = connection.accept_bi_stream().await {
                tokio::spawn(async move {
                    let mut buf = vec![];
                    io::copy(&mut reader, &mut buf).await?;

                    let str = String::from_utf8(buf)?;
                    trace!("received echo from client: {str}");

                    io::copy(
                        &mut format!("server welcomes {total_conn} back {str}").as_bytes(),
                        &mut writer,
                    )
                    .await?;
                    writer.shutdown().await?;

                    Ok::<_, anyhow::Error>(())
                });
            }
        });
    }
}

async fn run_quic_client(provider: Arc<CryptoProvider>, ordinal: usize) -> anyhow::Result<()> {
    let client = QuicClient::builder_with_crypto_provieder(provider)
        .without_verifier()
        .without_cert()
        .with_parameters(client_parameters())
        .defer_idle_timeout(Duration::from_secs(60))
        .enable_0rtt()
        .build();

    let server_addr: SocketAddr = "127.0.0.1:4443".parse()?;

    debug!("client {ordinal}: connecting to server at {server_addr}");
    let connection = client.connect("foo", [server_addr])?;
    let (_sid, (mut reader, mut writer)) = connection
        .open_bi_stream()
        .await?
        .ok_or_else(|| anyhow::anyhow!("Failed to open bi-stream"))?;
    debug!("client {ordinal}: opened stream");

    writer.write_all("hello world!".as_bytes()).await?;
    writer.shutdown().await?;
    debug!("client {ordinal}: sent hello world");

    let mut buf = vec![];
    io::copy(&mut reader, &mut buf).await?;
    trace!(
        "client {ordinal}: received echo from server: {}",
        String::from_utf8(buf)?
    );

    Ok(())
}
