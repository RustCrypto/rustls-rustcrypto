#[cfg(feature = "hash-sha256")]
use crate::tls13::aead::CHACHA20_POLY1305;
use crate::{hash, hmac, tls13_cipher_suite};
use rustls::crypto::{CipherSuiteCommon, tls13::HkdfUsingHmac};
use rustls::{CipherSuite, Tls13CipherSuite};

#[cfg(feature = "hash-sha256")]
tls13_cipher_suite!(
    TLS13_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    hash::SHA256,
    HkdfUsingHmac(hmac::SHA256),
    CHACHA20_POLY1305
);
