#![no_std]
#![forbid(unsafe_code)]
#![warn(
    clippy::unwrap_used,
    //missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]
#![doc = include_str!("../README.md")]
#![allow(dead_code)] // HEAVY TODO

//! RusTLS RustCrypto ValidationProvider
//! This crate is used to internally minimally validate the provider in CI
//! Obviously - don't use in prod ;-)

// I hope in future there is an API without Arc for providers
extern crate alloc;
use alloc::sync::Arc;

use rustls::client::ClientConfig as RusTlsClientConfig;

use rustls_rustcrypto::provider as rustcrypto_provider;

// TODO: rustcrypto tls PKI verifier provider missing
// We are not testing webpki / rustls itself which typically handle certificates
// Perhaps a separate crate for PKI operations e.g. cert verifying and then test that ?
mod fakes;
use crate::fakes::fake_cert_verifier::FakeServerCertVerifier;
use crate::fakes::fake_time_provider::FakeTime;

pub struct ProviderValidatorClient {
    pub(crate) rustls_client_config: RusTlsClientConfig,
}

impl ProviderValidatorClient {
    pub fn builder() -> Self {
        let provider = rustcrypto_provider();
        let time_provider = FakeTime {};

        let fake_server_cert_verifier = FakeServerCertVerifier {};

        let builder_init =
            RusTlsClientConfig::builder_with_details(Arc::new(provider), Arc::new(time_provider));

        let builder_default_versions = builder_init
            .with_safe_default_protocol_versions()
            .expect("Default protocol versions error?");

        // TODO - test with different verifiers
        let dangerous_verifier = builder_default_versions
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(fake_server_cert_verifier));

        // Out of scope
        let rustls_client_config = dangerous_verifier.with_no_client_auth();

        Self {
            rustls_client_config,
        }
    }
}
