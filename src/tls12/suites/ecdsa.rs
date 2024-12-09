use rustls::SupportedCipherSuite;

#[cfg(feature = "aead")]
use crate::tls12::suites::schemes::TLS12_ECDSA_SCHEMES;
#[cfg(feature = "aead")]
use crate::{hash, hmac};
#[cfg(feature = "aead")]
use rustls::crypto::{tls12::PrfUsingHmac, CipherSuiteCommon, KeyExchangeAlgorithm};
#[cfg(feature = "aead")]
use rustls::{CipherSuite, Tls12CipherSuite};

#[cfg(feature = "aes-gcm")]
use crate::aead::gcm::{Aes128Gcm, Aes256Gcm};

#[cfg(feature = "aes-ccm")]
use crate::aead::ccm::{Aes128Ccm, Aes128Ccm8, Aes256Ccm, Aes256Ccm8};

#[cfg(feature = "chacha20poly1305")]
use crate::aead::ChaCha20Poly1305;

#[cfg(feature = "aes-gcm")]
pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: Tls12CipherSuite = Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        hash_provider: hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_ECDSA_SCHEMES,
    aead_alg: &Aes128Gcm,
    prf_provider: &PrfUsingHmac(hmac::SHA256),
};

#[cfg(feature = "aes-gcm")]
pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: Tls12CipherSuite = Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        hash_provider: hash::SHA384,
        confidentiality_limit: u64::MAX,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_ECDSA_SCHEMES,
    prf_provider: &PrfUsingHmac(hmac::SHA384),
    aead_alg: &Aes256Gcm,
};

// https://ciphersuite.info/cs/TLS_ECDHE_ECDSA_WITH_AES_128_CCM/
#[cfg(feature = "aes-ccm")]
pub const TLS_ECDHE_ECDSA_WITH_AES_128_CCM: Tls12CipherSuite = Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
        hash_provider: hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_ECDSA_SCHEMES,
    aead_alg: &Aes128Ccm,
    prf_provider: &PrfUsingHmac(hmac::SHA256),
};

// https://ciphersuite.info/cs/TLS_ECDHE_ECDSA_WITH_AES_256_CCM/
#[cfg(feature = "aes-ccm")]
pub const TLS_ECDHE_ECDSA_WITH_AES_256_CCM: Tls12CipherSuite = Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
        hash_provider: hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_ECDSA_SCHEMES,
    aead_alg: &Aes256Ccm,
    prf_provider: &PrfUsingHmac(hmac::SHA256),
};

// https://ciphersuite.info/cs/TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8/
#[cfg(feature = "aes-ccm")]
pub const TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8: Tls12CipherSuite = Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
        hash_provider: hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_ECDSA_SCHEMES,
    aead_alg: &Aes128Ccm8,
    prf_provider: &PrfUsingHmac(hmac::SHA256),
};

// https://ciphersuite.info/cs/TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8/
#[cfg(feature = "aes-ccm")]
pub const TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8: Tls12CipherSuite = Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
        hash_provider: hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_ECDSA_SCHEMES,
    aead_alg: &Aes256Ccm8,
    prf_provider: &PrfUsingHmac(hmac::SHA256),
};

#[cfg(feature = "chacha20poly1305")]
pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: Tls12CipherSuite = Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        hash_provider: hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    prf_provider: &PrfUsingHmac(hmac::SHA256),
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_ECDSA_SCHEMES,
    aead_alg: &ChaCha20Poly1305,
};

pub const TLS_ECDHE_ECDSA_SUITES: &[SupportedCipherSuite] = &[
    #[cfg(feature = "aes-gcm")]
    SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
    #[cfg(feature = "aes-gcm")]
    SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
    #[cfg(feature = "aes-ccm")]
    SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_128_CCM),
    #[cfg(feature = "aes-ccm")]
    SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_256_CCM),
    #[cfg(feature = "aes-ccm")]
    SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8),
    #[cfg(feature = "aes-ccm")]
    SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8),
    #[cfg(feature = "chacha20poly1305")]
    SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
];
