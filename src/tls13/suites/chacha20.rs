use crate::aead::ChaCha20Poly1305;
use crate::{hash, hmac};
use rustls::crypto::{tls13::HkdfUsingHmac, CipherSuiteCommon};
use rustls::{CipherSuite, SupportedCipherSuite, Tls13CipherSuite};

pub const TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HkdfUsingHmac(hmac::SHA256),
        aead_alg: &ChaCha20Poly1305,
        quic: None,
    });
