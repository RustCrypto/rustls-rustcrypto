use crate::feature_slice;
use crate::misc::const_concat_slices;
use rustls::SupportedCipherSuite;

pub const TLS12_SUITES: &[SupportedCipherSuite] = const_concat_slices!(
    SupportedCipherSuite,
    feature_slice!([feature = "ecdsa"], ecdsa::TLS_ECDHE_ECDSA_SUITES),
    feature_slice!(
        [any(feature = "rsa-pss", feature = "rsa-pkcs1")],
        rsa::TLS_ECDHE_RSA_SUITES
    )
);

#[cfg(feature = "ecdsa")]
pub mod ecdsa;
#[cfg(any(feature = "rsa-pss", feature = "rsa-pkcs1"))]
pub mod rsa;
pub mod schemes;
