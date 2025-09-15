use rustls::SupportedCipherSuite;

#[cfg(feature = "aead")]
use crate::tls12::suites::schemes::TLS12_ECDSA_SCHEMES;
#[cfg(feature = "aead")]
use crate::{hash, hmac, tls12_ecdhe_cipher_suite};
#[cfg(feature = "aead")]
use rustls::crypto::{CipherSuiteCommon, KeyExchangeAlgorithm, tls12::PrfUsingHmac};
#[cfg(feature = "aead")]
use rustls::{CipherSuite, Tls12CipherSuite};

#[cfg(feature = "aes-gcm")]
use crate::tls12::aead::gcm::{AES_128_GCM, AES_256_GCM};

#[cfg(all(feature = "aes-ccm", feature = "hash-sha256"))]
use crate::tls12::aead::ccm::{AES_128_CCM, AES_128_CCM_8, AES_256_CCM, AES_256_CCM_8};

#[cfg(all(feature = "chacha20poly1305", feature = "hash-sha256"))]
use crate::tls12::aead::chacha20::ChaCha20Poly1305;

#[cfg(all(feature = "aes-gcm", feature = "hash-sha256"))]
tls12_ecdhe_cipher_suite!(
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    hash::SHA256,
    PrfUsingHmac(hmac::SHA256),
    TLS12_ECDSA_SCHEMES,
    AES_128_GCM
);

#[cfg(all(feature = "aes-gcm", feature = "hash-sha384"))]
tls12_ecdhe_cipher_suite!(
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    hash::SHA384,
    PrfUsingHmac(hmac::SHA384),
    TLS12_ECDSA_SCHEMES,
    AES_256_GCM
);

// https://ciphersuite.info/cs/TLS_ECDHE_ECDSA_WITH_AES_128_CCM/
#[cfg(all(feature = "aes-ccm", feature = "hash-sha256"))]
tls12_ecdhe_cipher_suite!(
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
    hash::SHA256,
    PrfUsingHmac(hmac::SHA256),
    TLS12_ECDSA_SCHEMES,
    AES_128_CCM
);

// https://ciphersuite.info/cs/TLS_ECDHE_ECDSA_WITH_AES_256_CCM/
#[cfg(all(feature = "aes-ccm", feature = "hash-sha256"))]
tls12_ecdhe_cipher_suite!(
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
    hash::SHA256,
    PrfUsingHmac(hmac::SHA256),
    TLS12_ECDSA_SCHEMES,
    AES_256_CCM
);

// https://ciphersuite.info/cs/TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8/
#[cfg(all(feature = "aes-ccm", feature = "hash-sha256"))]
tls12_ecdhe_cipher_suite!(
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
    hash::SHA256,
    PrfUsingHmac(hmac::SHA256),
    TLS12_ECDSA_SCHEMES,
    AES_128_CCM_8
);

// https://ciphersuite.info/cs/TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8/
#[cfg(all(feature = "aes-ccm", feature = "hash-sha256"))]
tls12_ecdhe_cipher_suite!(
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
    hash::SHA256,
    PrfUsingHmac(hmac::SHA256),
    TLS12_ECDSA_SCHEMES,
    AES_256_CCM_8
);

#[cfg(all(feature = "chacha20poly1305", feature = "hash-sha256"))]
tls12_ecdhe_cipher_suite!(
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    hash::SHA256,
    PrfUsingHmac(hmac::SHA256),
    TLS12_ECDSA_SCHEMES,
    &ChaCha20Poly1305
);

pub const TLS_ECDHE_ECDSA_SUITES: &[SupportedCipherSuite] = &[
    #[cfg(all(feature = "aes-gcm", feature = "hash-sha256"))]
    SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
    #[cfg(all(feature = "aes-gcm", feature = "hash-sha384"))]
    SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
    #[cfg(all(feature = "aes-ccm", feature = "hash-sha256"))]
    SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_128_CCM),
    #[cfg(all(feature = "aes-ccm", feature = "hash-sha256"))]
    SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_256_CCM),
    #[cfg(all(feature = "aes-ccm", feature = "hash-sha256"))]
    SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8),
    #[cfg(all(feature = "aes-ccm", feature = "hash-sha256"))]
    SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8),
    #[cfg(all(feature = "chacha20poly1305", feature = "hash-sha256"))]
    SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
];
