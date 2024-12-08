#[cfg(feature = "aes-ccm")]
use crate::aead::Aes128Ccm;
#[cfg(feature = "aes-gcm")]
use crate::aead::{Aes128Gcm, Aes256Gcm, Aes128Ccm8};
use crate::const_concat_slices;
use crate::{hash, hmac};
use rustls::crypto::{tls13::HkdfUsingHmac, CipherSuiteCommon};
use rustls::{CipherSuite, SupportedCipherSuite, Tls13CipherSuite};

#[cfg(feature = "aes-gcm")]
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

#[cfg(feature = "aes-gcm")]
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

#[cfg(feature = "aes-ccm")]
pub const TLS13_AES_128_CCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_CCM_SHA256,
            hash_provider: hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HkdfUsingHmac(hmac::SHA256),
        aead_alg: &Aes128Ccm,
        quic: None,
    });

#[cfg(feature = "aes-ccm")]
pub const TLS13_AES_128_CCM_8_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_CCM_8_SHA256,
            hash_provider: hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HkdfUsingHmac(hmac::SHA256),
        aead_alg: &Aes128Ccm8,
        quic: None,
    });

pub const TLS13_AES_SUITES: &[SupportedCipherSuite] = const_concat_slices!(
    SupportedCipherSuite,
    {
        #[cfg(feature = "aes-gcm")]
        {
            &[TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384]
        }

        #[cfg(not(feature = "aes-gcm"))]
        {
            &[]
        }
    },
    {
        #[cfg(feature = "aes-ccm")]
        {
            &[TLS13_AES_128_CCM_SHA256, TLS13_AES_128_CCM_8_SHA256]
        }

        #[cfg(not(feature = "aes-ccm"))]
        {
            &[]
        }
    },
    &[]
);
