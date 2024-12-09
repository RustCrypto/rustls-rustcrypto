use rustls::SupportedCipherSuite;

#[cfg(feature = "aead")]
use crate::tls12::suites::schemes::TLS12_RSA_SCHEMES;
#[cfg(feature = "aead")]
use crate::{hash, hmac};
#[cfg(feature = "aead")]
use rustls::crypto::{tls12::PrfUsingHmac, CipherSuiteCommon, KeyExchangeAlgorithm};
#[cfg(feature = "aead")]
use rustls::{CipherSuite, Tls12CipherSuite};

#[cfg(feature = "aes-gcm")]
use crate::aead::gcm::{Aes128Gcm, Aes256Gcm};

#[cfg(feature = "chacha20poly1305")]
use crate::aead::ChaCha20Poly1305;

#[cfg(all(feature = "aes-gcm", feature = "hash-sha256"))]
pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: Tls12CipherSuite = Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        hash_provider: hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_RSA_SCHEMES,
    aead_alg: &Aes128Gcm,
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
    aead_alg: &Aes256Gcm,
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
