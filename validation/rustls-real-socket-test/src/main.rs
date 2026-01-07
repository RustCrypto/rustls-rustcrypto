use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{mpsc, Arc};
use std::thread;

use env_logger::Env;
use log::{error, info};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::ServerConfig;
use rustls::{ClientConnection, ServerConnection, SignatureScheme, Stream};
use rustls_rustcrypto::provider as rustcrypto_provider;

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("trace")).init();

    info!("Rustls Real Socket TLS Test Starting...");

    // Initialize rustls with rustcrypto provider
    let provider = Arc::new(rustcrypto_provider());
    info!("Rustcrypto provider initialized");

    // Create TLS configurations
    let client_config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();
    info!("TLS client config created successfully");

    let server_config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![const { CertificateDer::from_slice(include_bytes!("cert.der")) }],
            PrivateKeyDer::Pkcs8(include_bytes!("key.der").as_slice().into()),
        )?;
    info!("TLS server config created successfully");

    let (tx, rx) = mpsc::channel();

    // Start TLS server in a separate thread
    let server_handle = thread::spawn(move || {
        run_tls_server(server_config, tx);
    });

    // Start TLS client in another thread
    let client_handle = thread::spawn(move || {
        if let Ok(port) = rx.recv() {
            run_tls_client(client_config, port);
        } else {
            error!("Failed to receive port from server thread");
        }
    });

    // Wait for both threads to complete
    if let Err(e) = server_handle.join() {
        error!("Server thread panicked: {:?}", e);
    }

    if let Err(e) = client_handle.join() {
        error!("Client thread panicked: {:?}", e);
    }

    info!("Rustls Real Socket TLS Test completed!");
    Ok(())
}

fn run_tls_server(server_config: ServerConfig, tx: mpsc::Sender<u16>) {
    info!("Starting TLS server...");

    // Bind to a random port and send it to the client thread
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => {
            let addr = listener.local_addr().unwrap();
            info!("TLS server listening on {}", addr);
            if tx.send(addr.port()).is_err() {
                error!("Failed to send port to client thread");
                return;
            }
            listener
        }
        Err(e) => {
            error!("Failed to bind server: {:?}", e);
            return;
        }
    };

    // Accept one connection for testing
    match listener.accept() {
        Ok((mut tcp_stream, addr)) => {
            info!("Accepted connection from {}", addr);

            let mut tls_conn = match ServerConnection::new(Arc::new(server_config)) {
                Ok(conn) => conn,
                Err(e) => {
                    error!("Failed to create TLS server connection: {:?}", e);
                    return;
                }
            };

            let mut tls_stream = Stream::new(&mut tls_conn, &mut tcp_stream);

            info!("TLS handshake completed successfully");

            // Read and echo data
            let mut buffer = [0; 1024];
            match tls_stream.read(&mut buffer) {
                Ok(n) if n > 0 => {
                    let received = String::from_utf8_lossy(&buffer[..n]);
                    info!("Server received: {}", received.trim());

                    // Echo back
                    if let Err(e) = tls_stream.write_all(format!("Echo: {}", received).as_bytes()) {
                        error!("Failed to write response: {:?}", e);
                    }
                }
                Ok(_) => info!("Connection closed by client"),
                Err(e) => error!("Read error: {:?}", e),
            }
        }
        Err(e) => {
            error!("Accept failed: {:?}", e);
        }
    }

    info!("TLS server shutting down");
}

fn run_tls_client(client_config: ClientConfig, port: u16) {
    info!("Starting TLS client...");

    // Connect to the server on the port received from the channel
    let server_addr = format!("127.0.0.1:{}", port);

    let mut tcp_stream = match TcpStream::connect(&server_addr) {
        Ok(stream) => {
            info!("Connected to server at {}", server_addr);
            stream
        }
        Err(e) => {
            error!("Failed to connect to server: {:?}", e);
            return;
        }
    };

    let server_name = match ServerName::try_from("localhost") {
        Ok(name) => name,
        Err(e) => {
            error!("Invalid server name: {:?}", e);
            return;
        }
    };

    let mut tls_conn = match ClientConnection::new(Arc::new(client_config), server_name) {
        Ok(conn) => conn,
        Err(e) => {
            error!("Failed to create TLS client connection: {:?}", e);
            return;
        }
    };

    let mut tls_stream = Stream::new(&mut tls_conn, &mut tcp_stream);

    info!("TLS handshake completed successfully");

    // Send test message
    let test_message = "Hello from Rustls client!";
    if let Err(e) = tls_stream.write_all(test_message.as_bytes()) {
        error!("Failed to send message: {:?}", e);
        return;
    }

    // Read response
    let mut buffer = [0; 1024];
    match tls_stream.read(&mut buffer) {
        Ok(n) if n > 0 => {
            let response = String::from_utf8_lossy(&buffer[..n]);
            info!("Client received: {}", response.trim());
        }
        Ok(_) => info!("Server closed connection"),
        Err(e) => error!("Read error: {:?}", e),
    }

    info!("TLS client shutting down");
}

// Dummy certificate verifier for testing (DO NOT USE IN PRODUCTION)
#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ]
    }
}

