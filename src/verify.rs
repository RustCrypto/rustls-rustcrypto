use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::SignatureScheme;

#[cfg(any(feature = "p256", feature = "p384"))]
use self::ecdsa::*;
use self::eddsa::ED25519;
#[cfg(feature = "rsa")]
use self::rsa::*;

pub static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        #[cfg(feature = "p256")]
        ECDSA_P256_SHA256,
        #[cfg(feature = "p256")]
        ECDSA_P256_SHA384,
        #[cfg(feature = "p384")]
        ECDSA_P384_SHA256,
        #[cfg(feature = "p384")]
        ECDSA_P384_SHA384,
        ED25519,
        #[cfg(feature = "rsa")]
        RSA_PKCS1_SHA256,
        #[cfg(feature = "rsa")]
        RSA_PKCS1_SHA384,
        #[cfg(feature = "rsa")]
        RSA_PKCS1_SHA512,
        #[cfg(feature = "rsa")]
        RSA_PSS_SHA256,
        #[cfg(feature = "rsa")]
        RSA_PSS_SHA384,
        #[cfg(feature = "rsa")]
        RSA_PSS_SHA512,
    ],
    mapping: &[
        #[cfg(feature = "p384")]
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[
                ECDSA_P384_SHA384,
                #[cfg(feature = "p256")]
                ECDSA_P256_SHA384,
            ],
        ),
        #[cfg(feature = "p256")]
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[
                ECDSA_P256_SHA256,
                #[cfg(feature = "p384")]
                ECDSA_P384_SHA256,
            ],
        ),
        (SignatureScheme::ED25519, &[ED25519]),
        #[cfg(feature = "rsa")]
        (SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
        #[cfg(feature = "rsa")]
        (SignatureScheme::RSA_PKCS1_SHA384, &[RSA_PKCS1_SHA384]),
        #[cfg(feature = "rsa")]
        (SignatureScheme::RSA_PKCS1_SHA512, &[RSA_PKCS1_SHA512]),
        #[cfg(feature = "rsa")]
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        #[cfg(feature = "rsa")]
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        #[cfg(feature = "rsa")]
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
    ],
};

#[cfg(any(feature = "p256", feature = "p384"))]
pub mod ecdsa;
pub mod eddsa;
#[cfg(feature = "rsa")]
pub mod rsa;
