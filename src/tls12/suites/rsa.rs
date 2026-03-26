use rustls::SupportedCipherSuite;

#[cfg(feature = "aead")]
use crate::tls12::suites::schemes::TLS12_RSA_SCHEMES;
#[cfg(feature = "aead")]
use crate::{hash, hmac, tls12_ecdhe_cipher_suite};
#[cfg(feature = "aead")]
use rustls::crypto::{CipherSuiteCommon, KeyExchangeAlgorithm, tls12::PrfUsingHmac};
#[cfg(feature = "aead")]
use rustls::{CipherSuite, Tls12CipherSuite};

#[cfg(feature = "gcm")]
use crate::tls12::aead::gcm::{AES_128_GCM, AES_256_GCM};

#[cfg(feature = "chacha20poly1305")]
use crate::tls12::aead::chacha20::ChaCha20Poly1305;

#[cfg(all(feature = "aes-gcm", feature = "hash-sha256"))]
tls12_ecdhe_cipher_suite!(
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    hash::SHA256,
    PrfUsingHmac(hmac::SHA256),
    TLS12_RSA_SCHEMES,
    AES_128_GCM
);

#[cfg(all(feature = "aes-gcm", feature = "hash-sha384"))]
tls12_ecdhe_cipher_suite!(
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    hash::SHA384,
    PrfUsingHmac(hmac::SHA384),
    TLS12_RSA_SCHEMES,
    AES_256_GCM
);

#[cfg(all(feature = "chacha20poly1305", feature = "hash-sha256"))]
tls12_ecdhe_cipher_suite!(
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    hash::SHA256,
    PrfUsingHmac(hmac::SHA256),
    TLS12_RSA_SCHEMES,
    &ChaCha20Poly1305
);

pub const TLS_ECDHE_RSA_SUITES: &[SupportedCipherSuite] = &[
    #[cfg(all(feature = "aes-gcm", feature = "hash-sha256"))]
    SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
    #[cfg(all(feature = "aes-gcm", feature = "hash-sha384"))]
    SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
    #[cfg(all(feature = "chacha20poly1305", feature = "hash-sha256"))]
    SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
];
