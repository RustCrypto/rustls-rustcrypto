use crate::aead::gcm::{Aes128Gcm, Aes256Gcm};
use crate::{hash, hmac};
use rustls::crypto::{tls13::HkdfUsingHmac, CipherSuiteCommon};
use rustls::{CipherSuite, SupportedCipherSuite, Tls13CipherSuite};

pub const TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HkdfUsingHmac(hmac::SHA256),
        aead_alg: &Aes128Gcm,
        quic: None,
    });

pub const TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: hash::SHA384,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HkdfUsingHmac(hmac::SHA384),
        aead_alg: &Aes256Gcm,
        quic: None,
    });

pub const TLS13_AES_SUITES: &[SupportedCipherSuite] =
    &[TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384];
