use rustls::SupportedCipherSuite;

#[cfg(feature = "aead")]
use crate::tls12::suites::schemes::TLS12_RSA_SCHEMES;
#[cfg(feature = "aead")]
use crate::{hash, hmac};
#[cfg(feature = "aead")]
use rustls::crypto::{CipherSuiteCommon, KeyExchangeAlgorithm, tls12::PrfUsingHmac};
#[cfg(feature = "aead")]
use rustls::{CipherSuite, Tls12CipherSuite};

#[cfg(feature = "gcm")]
use crate::tls12::aead::gcm::{AES_128_GCM, AES_256_GCM};

#[cfg(feature = "chacha20poly1305")]
use crate::tls12::aead::chacha20::ChaCha20Poly1305;

#[cfg(all(feature = "aes-gcm", feature = "hash-sha256"))]
pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: Tls12CipherSuite = Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        hash_provider: hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_RSA_SCHEMES,
    aead_alg: AES_128_GCM,
    prf_provider: &PrfUsingHmac(hmac::SHA256),
};

#[cfg(all(feature = "aes-gcm", feature = "hash-sha384"))]
pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: Tls12CipherSuite = Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        hash_provider: hash::SHA384,
        confidentiality_limit: u64::MAX,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_RSA_SCHEMES,
    aead_alg: AES_256_GCM,
    prf_provider: &PrfUsingHmac(hmac::SHA384),
};

#[cfg(all(feature = "chacha20poly1305", feature = "hash-sha256"))]
pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: Tls12CipherSuite = Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        hash_provider: hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_RSA_SCHEMES,
    prf_provider: &PrfUsingHmac(hmac::SHA256),
    aead_alg: &ChaCha20Poly1305,
};

pub const TLS_ECDHE_RSA_SUITES: &[SupportedCipherSuite] = &[
    #[cfg(all(feature = "aes-gcm", feature = "hash-sha256"))]
    SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
    #[cfg(all(feature = "aes-gcm", feature = "hash-sha384"))]
    SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
    #[cfg(all(feature = "chacha20poly1305", feature = "hash-sha256"))]
    SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
];
