#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::alloc_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::std_instead_of_core
)]

extern crate alloc;

use alloc::sync::Arc;

#[cfg(feature = "tls12")]
use rustls::SignatureScheme;
use rustls::{
    crypto::{CryptoProvider, GetRandomFailed, SupportedKxGroup},
    CipherSuite, CipherSuiteCommon, SupportedCipherSuite, Tls13CipherSuite,
};

#[derive(Debug)]
pub struct Provider;

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

    fn load_private_key(
        &self,
        key_der: pki_types::PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        let p256 =
            |_| sign::ecdsa::EcdsaSigningKeyP256::try_from(&key_der).map(|x| Arc::new(x) as _);
        let p384 =
            |_| sign::ecdsa::EcdsaSigningKeyP384::try_from(&key_der).map(|x| Arc::new(x) as _);
        let ed25519 =
            |_| sign::eddsa::Ed25519SigningKey::try_from(&key_der).map(|x| Arc::new(x) as _);
        let rsa = |_| sign::rsa::RsaSigningKey::try_from(&key_der).map(|x| Arc::new(x) as _);

        p256(()).or_else(p384).or_else(ed25519).or_else(rsa)
    }

    fn signature_verification_algorithms(&self) -> rustls::WebPkiSupportedAlgorithms {
        verify::ALGORITHMS
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
        common:       CipherSuiteCommon {
            suite:         CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            hash_provider: hash::SHA256,
        },
        kx:            rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign:          &TLS12_ECDSA_SCHEMES,
        aead_alg:      &aead::gcm::Gcm::<aes_gcm::Aes128Gcm>::DEFAULT,
        hmac_provider: hmac::SHA256,
    });

#[cfg(feature = "tls12")]
pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common:       CipherSuiteCommon {
            suite:         CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            hash_provider: hash::SHA384,
        },
        kx:            rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign:          &TLS12_ECDSA_SCHEMES,
        hmac_provider: hmac::SHA384,
        aead_alg:      &aead::gcm::Gcm::<aes_gcm::Aes256Gcm>::DEFAULT,
    });

#[cfg(feature = "tls12")]
pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common:       CipherSuiteCommon {
            suite:         CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: hash::SHA256,
        },
        prf_provider: &rustls::crypto::tls12::PrfUsingHmac(hmac::SHA256),
        kx:           rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign:         &TLS12_ECDSA_SCHEMES,
        aead_alg:     &aead::chacha20::Chacha20Poly1305,
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
        common:       CipherSuiteCommon {
            suite:         CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            hash_provider: hash::SHA256,
        },
        kx:            rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign:          &TLS12_RSA_SCHEMES,
        aead_alg:      &aead::gcm::Gcm::<aes_gcm::Aes128Gcm>::DEFAULT,
        hmac_provider: hmac::SHA256,
    });

#[cfg(feature = "tls12")]
pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common:       CipherSuiteCommon {
            suite:         CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            hash_provider: hash::SHA384,
        },
        kx:            rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign:          &TLS12_RSA_SCHEMES,
        hmac_provider: hmac::SHA384,
        aead_alg:      &aead::gcm::Gcm::<aes_gcm::Aes256Gcm>::DEFAULT,
    });

#[cfg(feature = "tls12")]
pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common:       CipherSuiteCommon {
            suite:         CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: hash::SHA256,
        },
        kx:           rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign:         &TLS12_RSA_SCHEMES,
        prf_provider: &rustls::crypto::tls12::PrfUsingHmac(hmac::SHA256),
        aead_alg:     &aead::chacha20::Chacha20Poly1305,
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
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(hmac::SHA256),
        aead_alg:      &aead::gcm::Tls13Aes128Gcm,
    });

pub const TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common:        CipherSuiteCommon {
            suite:         CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: hash::SHA384,
        },
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(hmac::SHA384),
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
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(hmac::SHA256),
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
