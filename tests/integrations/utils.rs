use reqwest::{Certificate, Client, Error};

pub fn make_client() -> Result<Client, Error> {
    let mut builder = Client::builder();
    for cert in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        builder = builder.add_root_certificate(Certificate::from_der(cert).unwrap())
    }
    builder.build()
}
