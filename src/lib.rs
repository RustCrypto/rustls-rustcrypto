#![cfg_attr(not(feature = "std"), no_std)]
#![deny(clippy::all, clippy::pedantic)]

extern crate alloc;

use alloc::sync::Arc;

#[cfg(feature = "tls12")]
use rustls::SignatureScheme;
use rustls::{
    cipher_suite::CipherSuiteCommon,
    client::{danger::ServerCertVerifier, WebPkiServerVerifier},
    crypto::{CryptoProvider, GetRandomFailed, SupportedKxGroup},
    CipherSuite, RootCertStore, SupportedCipherSuite, Tls13CipherSuite,
};

#[derive(Debug)]
pub struct Provider;

impl Provider {
    #[must_use]
    pub fn certificate_verifier(roots: RootCertStore) -> Arc<dyn ServerCertVerifier> {
        Arc::new(WebPkiServerVerifier::new_with_algorithms(
            roots,
            verify::ALGORITHMS,
        ))
    }
}

impl CryptoProvider for Provider {
    fn fill_random(&self, bytes: &mut [u8]) -> Result<(), GetRandomFailed> {
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(bytes)
            .map_err(|_| GetRandomFailed)
    }

    fn default_cipher_suites(&self) -> &'static [SupportedCipherSuite] {
        ALL_CIPHER_SUITES
    }

    fn default_kx_groups(&self) -> &'static [&'static dyn SupportedKxGroup] {
        kx::ALL_KX_GROUPS
    }
}

#[cfg(feature = "tls12")]
const TLS12_ECDSA_SCHEMES: [SignatureScheme; 4] = [
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ED25519,
];

#[cfg(feature = "tls12")]
const TLS12_RSA_SCHEMES: [SignatureScheme; 6] = [
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
];

#[cfg(feature = "tls12")]
pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common:        CipherSuiteCommon {
            suite:         CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            hash_provider: hash::SHA256,
        },
        kx:            rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign:          &TLS12_ECDSA_SCHEMES,
        aead_alg:      &aead::gcm::Tls12Aes128Gcm,
        hmac_provider: hmac::SHA256,
    });

#[cfg(feature = "tls12")]
pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common:        CipherSuiteCommon {
            suite:         CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            hash_provider: hash::SHA384,
        },
        kx:            rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign:          &TLS12_ECDSA_SCHEMES,
        hmac_provider: hmac::SHA384,
        aead_alg:      &aead::gcm::Tls12Aes256Gcm,
    });

#[cfg(feature = "tls12")]
pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common:        CipherSuiteCommon {
            suite:         CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: hash::SHA256,
        },
        hmac_provider: hmac::SHA256,
        kx:            rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign:          &TLS12_ECDSA_SCHEMES,
        aead_alg:      &aead::chacha20::Chacha20Poly1305,
    });

#[cfg(feature = "tls12")]
const TLS_ECDHE_ECDSA_SUITES: &[SupportedCipherSuite] = &[
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
];

#[cfg(feature = "tls12")]
pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common:        CipherSuiteCommon {
            suite:         CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            hash_provider: hash::SHA256,
        },
        kx:            rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign:          &TLS12_RSA_SCHEMES,
        aead_alg:      &aead::gcm::Tls12Aes128Gcm,
        hmac_provider: hmac::SHA256,
    });

#[cfg(feature = "tls12")]
pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common:        CipherSuiteCommon {
            suite:         CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            hash_provider: hash::SHA384,
        },
        kx:            rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign:          &TLS12_RSA_SCHEMES,
        hmac_provider: hmac::SHA384,
        aead_alg:      &aead::gcm::Tls12Aes256Gcm,
    });

#[cfg(feature = "tls12")]
pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common:        CipherSuiteCommon {
            suite:         CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: hash::SHA256,
        },
        kx:            rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign:          &TLS12_RSA_SCHEMES,
        hmac_provider: hmac::SHA256,
        aead_alg:      &aead::chacha20::Chacha20Poly1305,
    });

#[cfg(feature = "tls12")]
const TLS_ECDHE_RSA_SUITES: &[SupportedCipherSuite] = &[
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

#[cfg(feature = "tls12")]
const TLS12_SUITES: &[SupportedCipherSuite] = misc::const_concat_slices!(
    SupportedCipherSuite,
    TLS_ECDHE_ECDSA_SUITES,
    TLS_ECDHE_RSA_SUITES
);

#[cfg(not(feature = "tls12"))]
const TLS12_SUITES: &[SupportedCipherSuite] = &[];

pub const TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common:        CipherSuiteCommon {
            suite:         CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: hash::SHA256,
        },
        hmac_provider: hmac::SHA256,
        aead_alg:      &aead::gcm::Tls13Aes128Gcm,
    });

pub const TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common:        CipherSuiteCommon {
            suite:         CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: hash::SHA384,
        },
        hmac_provider: hmac::SHA384,
        aead_alg:      &aead::gcm::Tls13Aes256Gcm,
    });

const TLS13_AES_SUITES: &[SupportedCipherSuite] =
    &[TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384];

pub const TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common:        CipherSuiteCommon {
            suite:         CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: hash::SHA256,
        },
        hmac_provider: hmac::SHA256,
        aead_alg:      &aead::chacha20::Chacha20Poly1305,
    });

const TLS13_SUITES: &[SupportedCipherSuite] = misc::const_concat_slices!(
    SupportedCipherSuite,
    TLS13_AES_SUITES,
    &[TLS13_CHACHA20_POLY1305_SHA256]
);

static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = misc::const_concat_slices!(
    SupportedCipherSuite,
    if cfg!(feature = "tls12") {
        TLS12_SUITES
    } else {
        &[]
    },
    TLS13_SUITES,
);

mod aead;
mod hash;
mod hmac;
mod kx;
mod misc;
pub mod sign;
mod verify;
