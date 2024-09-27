use crate::misc::const_concat_slices;
use ecdsa::TLS_ECDHE_ECDSA_SUITES;
use rsa::TLS_ECDHE_RSA_SUITES;
use rustls::SupportedCipherSuite;

pub const TLS12_SUITES: &[SupportedCipherSuite] = const_concat_slices!(
    SupportedCipherSuite,
    TLS_ECDHE_ECDSA_SUITES,
    TLS_ECDHE_RSA_SUITES
);

pub mod ecdsa;
pub mod rsa;
pub mod schemes;
