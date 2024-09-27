use crate::const_concat_slices;
use aes::TLS13_AES_SUITES;
use chacha20::TLS13_CHACHA20_POLY1305_SHA256;
use rustls::SupportedCipherSuite;

pub const TLS13_SUITES: &[SupportedCipherSuite] = const_concat_slices!(
    SupportedCipherSuite,
    TLS13_AES_SUITES,
    &[TLS13_CHACHA20_POLY1305_SHA256]
);

pub mod aes;
pub mod chacha20;
