#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::sync::Arc;
use sha2::{Sha256, Sha384};

pub struct Provider;

impl Provider {
    pub fn certificate_verifier(
        roots: rustls::RootCertStore,
    ) -> Arc<dyn rustls::client::ServerCertVerifier> {
        Arc::new(rustls::client::WebPkiServerVerifier::new_with_algorithms(
            roots,
            verify::ALGORITHMS,
        ))
    }
}

impl rustls::crypto::CryptoProvider for Provider {
    type KeyExchange = kx::KeyExchange;

    fn fill_random(bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(bytes)
            .map_err(|_| rustls::crypto::GetRandomFailed)
    }

    fn default_cipher_suites() -> &'static [rustls::SupportedCipherSuite] {
        &ALL_CIPHER_SUITES
    }
}

static ALL_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS13_AES_128_GCM_SHA256,
    TLS13_AES_256_GCM_SHA384,
    TLS13_AES_128_CCM_SHA256,
    #[cfg(feature = "tls12")]
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    #[cfg(feature = "tls12")]
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    // Warning: the following cipher suites are buggy at the moment
    // #[cfg(feature = "tls12")] TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    // #[cfg(feature = "tls12")] TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
];

pub static TLS13_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::cipher_suite::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::Hash::<Sha256>::DEFAULT,
        },
        hmac_provider: &hmac::Hmac::<Sha256>::DEFAULT,
        aead_alg: &aead::Aead::<chacha20poly1305::ChaCha20Poly1305>::DEFAULT,
    });

pub static TLS13_AES_128_CCM_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::cipher_suite::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS13_AES_128_CCM_SHA256,
            hash_provider: &hash::Hash::<Sha256>::DEFAULT,
        },
        hmac_provider: &hmac::Hmac::<Sha256>::DEFAULT,
        aead_alg: &aead::Aead::<aes_gcm::Aes128Gcm>::DEFAULT,
    });

pub static TLS13_AES_128_GCM_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::cipher_suite::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &hash::Hash::<Sha256>::DEFAULT,
        },
        hmac_provider: &hmac::Hmac::<Sha256>::DEFAULT,
        aead_alg: &aead::Aead::<aes_gcm::Aes128Gcm>::DEFAULT,
    });

pub static TLS13_AES_256_GCM_SHA384: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::cipher_suite::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &hash::Hash::<Sha384>::DEFAULT,
        },
        hmac_provider: &hmac::Hmac::<Sha384>::DEFAULT,
        aead_alg: &aead::Aead::<aes_gcm::Aes256Gcm>::DEFAULT,
    });

#[cfg(feature = "tls12")]
pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: rustls::cipher_suite::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::Hash::<Sha256>::DEFAULT,
        },
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: &[
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
        ],
        hmac_provider: &hmac::Hmac::<Sha256>::DEFAULT,
        aead_alg: &aead::Aead::<chacha20poly1305::ChaCha20Poly1305>::DEFAULT,
    });
#[cfg(feature = "tls12")]
pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: rustls::cipher_suite::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::Hash::<Sha256>::DEFAULT,
        },
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: &[
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ],
        hmac_provider: &hmac::Hmac::<Sha256>::DEFAULT,
        aead_alg: &aead::Aead::<chacha20poly1305::ChaCha20Poly1305>::DEFAULT,
    });

// TODO
// #[cfg(feature = "tls12")] pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: rustls::SupportedCipherSuite =
//     rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
//         common: rustls::cipher_suite::CipherSuiteCommon {
//             suite: rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
//             hash_provider: &hash::Hash::<Sha384>::DEFAULT,
//         },
//         kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
//         sign: &[
//             rustls::SignatureScheme::RSA_PSS_SHA384,
//             rustls::SignatureScheme::RSA_PKCS1_SHA384,
//         ],
//         hmac_provider: &hmac::Hmac::<Sha384>::DEFAULT,
//         aead_alg: &aead::Aead::<aes_gcm::Aes256Gcm>::DEFAULT,
//     });

// #[cfg(feature = "tls12")] pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: rustls::SupportedCipherSuite =
//     rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
//         common: rustls::cipher_suite::CipherSuiteCommon {
//             suite: rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
//             hash_provider: &hash::Hash::<Sha384>::DEFAULT,
//         },
//         kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
//         sign: &[
//             rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
//             rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
//             rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
//         ],
//         hmac_provider: &hmac::Hmac::<Sha384>::DEFAULT,
//         aead_alg: &aead::Aead::<aes_gcm::Aes256Gcm>::DEFAULT,
//     });

mod aead;
mod hash;
mod hmac;
mod kx;
pub mod sign;
mod verify;
