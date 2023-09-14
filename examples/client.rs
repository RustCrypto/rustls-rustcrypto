use std::{
    io::{stdout, Read, Write},
    net::TcpStream,
    sync::Arc,
};

use rustls_provider_rustcrypto::Provider;

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder_with_provider(&Provider)
        .with_safe_defaults()
        .with_custom_certificate_verifier(Provider::certificate_verifier(root_store))
        .with_no_client_auth();

    let server_name = "scotthelme.co.uk".try_into()?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)?;
    let mut sock = TcpStream::connect("scotthelme.co.uk:443")?;
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: scotthelme.co.uk\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )?;
    let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:#?} {:#?}",
        ciphersuite.suite(),
        ciphersuite.version()
    )?;
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext)?;
    // stdout().write_all(&plaintext)?;
    Ok(())
}
