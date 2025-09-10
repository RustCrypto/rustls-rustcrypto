use crate::const_concat_slices;
#[cfg(all(feature = "ccm", feature = "hash-sha256"))]
use crate::tls13::aead::ccm::{AES_128_CCM, AES_128_CCM_8};
#[cfg(all(feature = "gcm", feature = "hash-sha256"))]
use crate::tls13::aead::gcm::AES_128_GCM;
#[cfg(all(feature = "gcm", feature = "hash-sha384"))]
use crate::tls13::aead::gcm::AES_256_GCM;
use crate::{hash, hmac};
use rustls::crypto::{CipherSuiteCommon, tls13::HkdfUsingHmac};
use rustls::{CipherSuite, SupportedCipherSuite, Tls13CipherSuite};

#[cfg(all(feature = "gcm", feature = "hash-sha256"))]
pub const TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HkdfUsingHmac(hmac::SHA256),
        aead_alg: AES_128_GCM,
        quic: None,
    });

#[cfg(all(feature = "gcm", feature = "hash-sha384"))]
pub const TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: hash::SHA384,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HkdfUsingHmac(hmac::SHA384),
        aead_alg: AES_256_GCM,
        quic: None,
    });

#[cfg(all(feature = "ccm", feature = "hash-sha256"))]
pub const TLS13_AES_128_CCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_CCM_SHA256,
            hash_provider: hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HkdfUsingHmac(hmac::SHA256),
        aead_alg: AES_128_CCM,
        quic: None,
    });

#[cfg(all(feature = "ccm", feature = "hash-sha256"))]
pub const TLS13_AES_128_CCM_8_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_CCM_8_SHA256,
            hash_provider: hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HkdfUsingHmac(hmac::SHA256),
        aead_alg: AES_128_CCM_8,
        quic: None,
    });

pub const TLS13_AES_SUITES: &[SupportedCipherSuite] = const_concat_slices!(
    SupportedCipherSuite,
    {
        #[cfg(feature = "gcm")]
        {
            &[
                #[cfg(feature = "hash-sha256")]
                TLS13_AES_128_GCM_SHA256,
                #[cfg(feature = "hash-sha384")]
                TLS13_AES_256_GCM_SHA384,
            ]
        }

        #[cfg(not(feature = "gcm"))]
        {
            &[]
        }
    },
    {
        #[cfg(feature = "ccm")]
        {
            &[
                #[cfg(feature = "hash-sha256")]
                TLS13_AES_128_CCM_SHA256,
                #[cfg(feature = "hash-sha256")]
                TLS13_AES_128_CCM_8_SHA256,
            ]
        }

        #[cfg(not(feature = "ccm"))]
        {
            &[]
        }
    },
    &[]
);
