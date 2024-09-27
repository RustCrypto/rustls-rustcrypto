use crate::aead::chacha20::ChaCha20Poly1305;
use crate::aead::gcm::{Aes128Gcm, Aes256Gcm};
use crate::{hash, hmac};
use rustls::crypto::{tls12::PrfUsingHmac, CipherSuiteCommon, KeyExchangeAlgorithm};
use rustls::{CipherSuite, SupportedCipherSuite, Tls12CipherSuite};

use super::schemes::TLS12_ECDSA_SCHEMES;

pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            hash_provider: hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: &TLS12_ECDSA_SCHEMES,
        aead_alg: &Aes128Gcm,
        prf_provider: &PrfUsingHmac(hmac::SHA256),
    });

pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            hash_provider: hash::SHA384,
            confidentiality_limit: u64::MAX,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: &TLS12_ECDSA_SCHEMES,
        prf_provider: &PrfUsingHmac(hmac::SHA384),
        aead_alg: &Aes256Gcm,
    });

pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        prf_provider: &PrfUsingHmac(hmac::SHA256),
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: &TLS12_ECDSA_SCHEMES,
        aead_alg: &ChaCha20Poly1305,
    });

pub const TLS_ECDHE_ECDSA_SUITES: &[SupportedCipherSuite] = &[
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
];
