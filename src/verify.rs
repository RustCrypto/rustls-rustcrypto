use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::SignatureScheme;

#[cfg(feature = "p256")]
use self::ecdsa::{ECDSA_P256_SHA256, ECDSA_P256_SHA384};
#[cfg(feature = "p384")]
use self::ecdsa::{ECDSA_P384_SHA256, ECDSA_P384_SHA384};
#[cfg(feature = "ed25519")]
use self::eddsa::ED25519;
#[cfg(feature = "rsa")]
use self::rsa::{
    RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256, RSA_PSS_SHA384,
    RSA_PSS_SHA512,
};

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
        #[cfg(feature = "ed25519")]
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
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[
                #[cfg(feature = "p384")]
                ECDSA_P384_SHA384,
                #[cfg(feature = "p256")]
                ECDSA_P256_SHA384
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[
                #[cfg(feature = "p256")]
                ECDSA_P256_SHA256,
                #[cfg(feature = "p384")]
                ECDSA_P384_SHA256
            ],
        ),
        #[cfg(feature = "ed25519")]
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
#[cfg(feature = "ed25519")]
pub mod eddsa;
#[cfg(feature = "rsa")]
pub mod rsa;
