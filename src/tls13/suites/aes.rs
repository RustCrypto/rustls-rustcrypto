use crate::const_concat_slices;
use crate::feature_eval_expr;
use crate::feature_slice;
use crate::tls13_cipher_suite;
use crate::{hash, hmac};
use rustls::crypto::{CipherSuiteCommon, tls13::HkdfUsingHmac};
use rustls::{CipherSuite, SupportedCipherSuite, Tls13CipherSuite};

#[cfg(all(feature = "ccm", feature = "hash-sha256", feature = "quic"))]
use crate::aead::aes::Aes128Ccm;
#[cfg(all(feature = "gcm", feature = "hash-sha256", feature = "quic"))]
use crate::aead::aes::Aes128Gcm;
#[cfg(all(feature = "gcm", feature = "hash-sha384", feature = "quic"))]
use crate::aead::aes::Aes256Gcm;
#[cfg(all(feature = "ccm", feature = "hash-sha256"))]
use crate::tls13::aead::ccm::{AES_128_CCM, AES_128_CCM_8};
#[cfg(all(feature = "gcm", feature = "hash-sha256"))]
use crate::tls13::aead::gcm::AES_128_GCM;
#[cfg(all(feature = "gcm", feature = "hash-sha384"))]
use crate::tls13::aead::gcm::AES_256_GCM;

#[cfg(all(feature = "gcm", feature = "hash-sha256"))]
tls13_cipher_suite!(
    TLS13_AES_128_GCM_SHA256,
    CipherSuite::TLS13_AES_128_GCM_SHA256,
    hash::SHA256,
    HkdfUsingHmac(hmac::SHA256),
    AES_128_GCM,
    feature_eval_expr!([feature = "quic"], Some(&crate::quic::QuicCrypto::<Aes128Gcm>::DEFAULT), else None)
);

#[cfg(all(feature = "gcm", feature = "hash-sha384"))]
tls13_cipher_suite!(
    TLS13_AES_256_GCM_SHA384,
    CipherSuite::TLS13_AES_256_GCM_SHA384,
    hash::SHA384,
    HkdfUsingHmac(hmac::SHA384),
    AES_256_GCM,
    feature_eval_expr!([feature = "quic"], Some(&crate::quic::QuicCrypto::<Aes256Gcm>::DEFAULT), else None)
);

#[cfg(all(feature = "ccm", feature = "hash-sha256"))]
tls13_cipher_suite!(
    TLS13_AES_128_CCM_SHA256,
    CipherSuite::TLS13_AES_128_CCM_SHA256,
    hash::SHA256,
    HkdfUsingHmac(hmac::SHA256),
    AES_128_CCM,
    feature_eval_expr!([feature = "quic"], Some(&crate::quic::QuicCrypto::<Aes128Ccm>::DEFAULT), else None)
);

#[cfg(all(feature = "ccm", feature = "hash-sha256"))]
tls13_cipher_suite!(
    TLS13_AES_128_CCM_8_SHA256,
    CipherSuite::TLS13_AES_128_CCM_8_SHA256,
    hash::SHA256,
    HkdfUsingHmac(hmac::SHA256),
    AES_128_CCM_8,
    // The AEAD for that ciphersuite, AEAD_AES_128_CCM_8 [CCM], does not produce a large
    // enough authentication tag for use with the header protection designs
    // provided (see Section 5.4).  All other ciphersuites defined in
    // [TLS13] have a 16-byte authentication tag and produce an output 16
    // bytes larger than their input.
    None
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
