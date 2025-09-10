#[cfg(feature = "hash-sha256")]
use crate::tls13::aead::CHACHA20_POLY1305;
use crate::{hash, hmac};
use rustls::crypto::{CipherSuiteCommon, tls13::HkdfUsingHmac};
use rustls::{CipherSuite, SupportedCipherSuite, Tls13CipherSuite};

#[cfg(feature = "hash-sha256")]
pub const TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HkdfUsingHmac(hmac::SHA256),
        aead_alg: CHACHA20_POLY1305,
        quic: None,
    });
