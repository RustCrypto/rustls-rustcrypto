use crate::const_concat_slices;
use crate::feature_slice;
#[cfg(all(feature = "ccm", feature = "hash-sha256"))]
use crate::tls13::aead::ccm::{AES_128_CCM, AES_128_CCM_8};
#[cfg(all(feature = "gcm", feature = "hash-sha256"))]
use crate::tls13::aead::gcm::AES_128_GCM;
#[cfg(all(feature = "gcm", feature = "hash-sha384"))]
use crate::tls13::aead::gcm::AES_256_GCM;
use crate::tls13_cipher_suite;
use crate::{hash, hmac};
use rustls::crypto::{CipherSuiteCommon, tls13::HkdfUsingHmac};
use rustls::{CipherSuite, SupportedCipherSuite, Tls13CipherSuite};

#[cfg(all(feature = "gcm", feature = "hash-sha256"))]
tls13_cipher_suite!(
    TLS13_AES_128_GCM_SHA256,
    CipherSuite::TLS13_AES_128_GCM_SHA256,
    hash::SHA256,
    HkdfUsingHmac(hmac::SHA256),
    AES_128_GCM
);

#[cfg(all(feature = "gcm", feature = "hash-sha384"))]
tls13_cipher_suite!(
    TLS13_AES_256_GCM_SHA384,
    CipherSuite::TLS13_AES_256_GCM_SHA384,
    hash::SHA384,
    HkdfUsingHmac(hmac::SHA384),
    AES_256_GCM
);

#[cfg(all(feature = "ccm", feature = "hash-sha256"))]
tls13_cipher_suite!(
    TLS13_AES_128_CCM_SHA256,
    CipherSuite::TLS13_AES_128_CCM_SHA256,
    hash::SHA256,
    HkdfUsingHmac(hmac::SHA256),
    AES_128_CCM
);

#[cfg(all(feature = "ccm", feature = "hash-sha256"))]
tls13_cipher_suite!(
    TLS13_AES_128_CCM_8_SHA256,
    CipherSuite::TLS13_AES_128_CCM_8_SHA256,
    hash::SHA256,
    HkdfUsingHmac(hmac::SHA256),
    AES_128_CCM_8
);

pub const TLS13_AES_SUITES: &[SupportedCipherSuite] = const_concat_slices!(
    SupportedCipherSuite,
    feature_slice!(
        [feature = "gcm"],
        &[
            #[cfg(feature = "hash-sha256")]
            SupportedCipherSuite::Tls13(&TLS13_AES_128_GCM_SHA256),
            #[cfg(feature = "hash-sha384")]
            SupportedCipherSuite::Tls13(&TLS13_AES_256_GCM_SHA384),
        ]
    ),
    feature_slice!(
        [feature = "ccm"],
        &[
            #[cfg(feature = "hash-sha256")]
            SupportedCipherSuite::Tls13(&TLS13_AES_128_CCM_SHA256),
            #[cfg(feature = "hash-sha256")]
            SupportedCipherSuite::Tls13(&TLS13_AES_128_CCM_8_SHA256),
        ]
    )
);
