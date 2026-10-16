use crate::{
    TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
};
use rustls::{CipherSuite, SupportedCipherSuite};

#[test]
fn aes_gcm_confidentiality_limits_match_the_reference_providers() {
    let limits = [
        (
            &TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            1 << 24,
        ),
        (
            &TLS13_AES_256_GCM_SHA384,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
            1 << 24,
        ),
        #[cfg(feature = "tls12")]
        (
            &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            1 << 24,
        ),
        #[cfg(feature = "tls12")]
        (
            &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            1 << 24,
        ),
    ];
    for (suite, suite_id, expected) in limits {
        let actual = match suite {
            SupportedCipherSuite::Tls13(inner) => inner.common.confidentiality_limit,
            SupportedCipherSuite::Tls12(inner) => inner.common.confidentiality_limit,
        };
        assert_eq!(actual, expected, "{suite_id:?}");
    }
}
