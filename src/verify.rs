use core::array::TryFromSliceError;

use self::ecdsa::nist::{
    ECDSA_P256_SHA256, ECDSA_P256_SHA384, ECDSA_P384_SHA256, ECDSA_P384_SHA384,
};
use self::eddsa::ed25519::ED25519;
use self::rsa::{
    RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256, RSA_PSS_SHA384,
    RSA_PSS_SHA512,
};
use derive_more::From;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::SignatureScheme;

#[derive(From)]
pub(crate) enum Error {
    Signature,
    TryFromSlice(TryFromSliceError),
    Der,
    Pkcs1,
}

impl From<signature::Error> for Error {
    fn from(_: signature::Error) -> Self {
        Self::Signature
    }
}

impl From<der::Error> for Error {
    fn from(_: der::Error) -> Self {
        Self::Der
    }
}

impl From<pkcs1::Error> for Error {
    fn from(_: pkcs1::Error) -> Self {
        Self::Pkcs1
    }
}

pub static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ECDSA_P256_SHA256,
        ECDSA_P256_SHA384,
        ECDSA_P384_SHA256,
        ECDSA_P384_SHA384,
        ED25519,
        RSA_PKCS1_SHA256,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA512,
        RSA_PSS_SHA256,
        RSA_PSS_SHA384,
        RSA_PSS_SHA512,
    ],
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[ECDSA_P384_SHA384, ECDSA_P256_SHA384],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[ECDSA_P256_SHA256, ECDSA_P384_SHA256],
        ),
        (SignatureScheme::ED25519, &[ED25519]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[RSA_PKCS1_SHA512]),
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
    ],
};

pub mod ecdsa;
pub mod eddsa;
pub mod rsa;
