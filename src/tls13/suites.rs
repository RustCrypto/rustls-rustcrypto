use crate::const_concat_slices;
use crate::feature_slice;
use rustls::SupportedCipherSuite;

pub const TLS13_SUITES: &[SupportedCipherSuite] = const_concat_slices!(
    SupportedCipherSuite,
    feature_slice!([feature = "aes"], aes::TLS13_AES_SUITES),
    feature_slice!(
        [feature = "chacha20poly1305"],
        &[
            #[cfg(feature = "hash-sha256")]
            SupportedCipherSuite::Tls13(&chacha20::TLS13_CHACHA20_POLY1305_SHA256),
        ]
    )
);

#[cfg(feature = "aes")]
pub mod aes;

#[cfg(feature = "chacha20poly1305")]
pub mod chacha20;
