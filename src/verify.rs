use core::array::TryFromSliceError;

use crate::const_concat_slices;
use crate::feature_slice;

use pki_types::SignatureVerificationAlgorithm;
use rustls::SignatureScheme;
use rustls::crypto::WebPkiSupportedAlgorithms;

pub(crate) enum Error {
    #[cfg(feature = "signature")]
    Signature,
    TryFromSlice,
    #[cfg(feature = "der")]
    Der,
    #[cfg(feature = "pkcs1")]
    Pkcs1,
}

#[cfg(feature = "signature")]
impl From<signature::Error> for Error {
    fn from(_: signature::Error) -> Self {
        Self::Signature
    }
}

#[cfg(feature = "der")]
impl From<der::Error> for Error {
    fn from(_: der::Error) -> Self {
        Self::Der
    }
}

#[cfg(feature = "pkcs1")]
impl From<pkcs1::Error> for Error {
    fn from(_: pkcs1::Error) -> Self {
        Self::Pkcs1
    }
}

impl From<TryFromSliceError> for Error {
    fn from(_: TryFromSliceError) -> Self {
        Self::TryFromSlice
    }
}

pub const ALL: &[&dyn SignatureVerificationAlgorithm] = const_concat_slices!(
    &dyn SignatureVerificationAlgorithm,
    feature_slice!(
        [feature = "verify-ecdsa-nist"],
        &[
            #[cfg(all(feature = "ecdsa-p256", feature = "hash-sha256"))]
            ecdsa::nist::ECDSA_P256_SHA256,
            #[cfg(all(feature = "ecdsa-p256", feature = "hash-sha384"))]
            ecdsa::nist::ECDSA_P256_SHA384,
            #[cfg(all(feature = "ecdsa-p256", feature = "hash-sha512"))]
            ecdsa::nist::ECDSA_P256_SHA512,
            #[cfg(all(feature = "ecdsa-p384", feature = "hash-sha256"))]
            ecdsa::nist::ECDSA_P384_SHA256,
            #[cfg(all(feature = "ecdsa-p384", feature = "hash-sha384"))]
            ecdsa::nist::ECDSA_P384_SHA384,
            #[cfg(all(feature = "ecdsa-p384", feature = "hash-sha512"))]
            ecdsa::nist::ECDSA_P384_SHA512,
            #[cfg(all(feature = "ecdsa-p521", feature = "hash-sha256"))]
            ecdsa::nist::ECDSA_P521_SHA256,
            #[cfg(all(feature = "ecdsa-p521", feature = "hash-sha384"))]
            ecdsa::nist::ECDSA_P521_SHA384,
            #[cfg(all(feature = "ecdsa-p521", feature = "hash-sha512"))]
            ecdsa::nist::ECDSA_P521_SHA512,
        ]
    ),
    feature_slice!(
        [feature = "verify-eddsa"],
        &[
            #[cfg(all(feature = "eddsa-ed25519", feature = "hash-sha256"))]
            eddsa::ed25519::ED25519,
            #[cfg(all(feature = "eddsa-ed448", feature = "hash-sha512"))]
            eddsa::ed448::ED448,
        ]
    ),
    feature_slice!(
        [feature = "rsa-pkcs1"],
        &[
            #[cfg(feature = "hash-sha256")]
            rsa::RSA_PKCS1_SHA256,
            #[cfg(feature = "hash-sha384")]
            rsa::RSA_PKCS1_SHA384,
            #[cfg(feature = "hash-sha512")]
            rsa::RSA_PKCS1_SHA512,
        ]
    ),
    feature_slice!(
        [feature = "rsa-pss"],
        &[
            #[cfg(feature = "hash-sha256")]
            rsa::RSA_PSS_SHA256,
            #[cfg(feature = "hash-sha384")]
            rsa::RSA_PSS_SHA384,
            #[cfg(feature = "hash-sha512")]
            rsa::RSA_PSS_SHA512,
        ]
    ),
);

pub const MAPPING: &[(SignatureScheme, &[&dyn SignatureVerificationAlgorithm])] = const_concat_slices!(
    (SignatureScheme, &[&dyn SignatureVerificationAlgorithm],),
    feature_slice!(
        [feature = "verify-ecdsa-nist"],
        &[
            #[cfg(all(feature = "ecdsa-p384", feature = "hash-sha384"))]
            (
                SignatureScheme::ECDSA_NISTP384_SHA384,
                &[
                    ecdsa::nist::ECDSA_P384_SHA384,
                    #[cfg(feature = "ecdsa-p256")]
                    ecdsa::nist::ECDSA_P256_SHA384,
                    #[cfg(feature = "ecdsa-p521")]
                    ecdsa::nist::ECDSA_P521_SHA384,
                ],
            ),
            #[cfg(all(feature = "ecdsa-p521", feature = "hash-sha512"))]
            (
                SignatureScheme::ECDSA_NISTP521_SHA512,
                &[
                    ecdsa::nist::ECDSA_P521_SHA512,
                    #[cfg(feature = "ecdsa-p256")]
                    ecdsa::nist::ECDSA_P256_SHA512,
                    #[cfg(feature = "ecdsa-p384")]
                    ecdsa::nist::ECDSA_P384_SHA512,
                ],
            ),
            #[cfg(all(feature = "ecdsa-p256", feature = "hash-sha256"))]
            (
                SignatureScheme::ECDSA_NISTP256_SHA256,
                &[
                    ecdsa::nist::ECDSA_P256_SHA256,
                    #[cfg(feature = "ecdsa-p384")]
                    ecdsa::nist::ECDSA_P384_SHA256,
                    #[cfg(feature = "ecdsa-p521")]
                    ecdsa::nist::ECDSA_P521_SHA256,
                ],
            ),
        ]
    ),
    feature_slice!(
        [all(feature = "rsa-pkcs1", feature = "verify-rsa")],
        &[
            #[cfg(feature = "hash-sha256")]
            (SignatureScheme::RSA_PKCS1_SHA256, &[rsa::RSA_PKCS1_SHA256]),
            #[cfg(feature = "hash-sha384")]
            (SignatureScheme::RSA_PKCS1_SHA384, &[rsa::RSA_PKCS1_SHA384]),
            #[cfg(feature = "hash-sha512")]
            (SignatureScheme::RSA_PKCS1_SHA512, &[rsa::RSA_PKCS1_SHA512]),
        ]
    ),
    feature_slice!(
        [all(feature = "rsa-pss", feature = "verify-rsa")],
        &[
            #[cfg(feature = "hash-sha256")]
            (SignatureScheme::RSA_PSS_SHA256, &[rsa::RSA_PSS_SHA256]),
            #[cfg(feature = "hash-sha384")]
            (SignatureScheme::RSA_PSS_SHA384, &[rsa::RSA_PSS_SHA384]),
            #[cfg(feature = "hash-sha512")]
            (SignatureScheme::RSA_PSS_SHA512, &[rsa::RSA_PSS_SHA512]),
        ]
    ),
    feature_slice!(
        [feature = "verify-eddsa"],
        &[
            #[cfg(all(feature = "eddsa-ed25519", feature = "hash-sha256"))]
            (SignatureScheme::ED25519, &[eddsa::ed25519::ED25519]),
            #[cfg(all(feature = "eddsa-ed448", feature = "hash-sha512"))]
            (SignatureScheme::ED448, &[eddsa::ed448::ED448]),
        ]
    ),
);

pub const ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: const_concat_slices!(
        &dyn SignatureVerificationAlgorithm,
        ALL,
        feature_slice!(
            [feature = "eddsa"],
            &[
                #[cfg(feature = "eddsa-ed25519")]
                eddsa::ed25519::ED25519,
                #[cfg(feature = "eddsa-ed448")]
                eddsa::ed448::ED448,
            ]
        )
    ),
    mapping: const_concat_slices!(
        (SignatureScheme, &[&dyn SignatureVerificationAlgorithm],),
        MAPPING,
        feature_slice!(
            [feature = "eddsa"],
            &[
                #[cfg(feature = "eddsa-ed25519")]
                (SignatureScheme::ED25519, &[eddsa::ed25519::ED25519]),
                #[cfg(feature = "eddsa-ed448")]
                (SignatureScheme::ED448, &[eddsa::ed448::ED448]),
            ]
        )
    ),
};

#[cfg(feature = "ecdsa")]
pub mod ecdsa;

#[cfg(feature = "eddsa")]
pub mod eddsa;

#[cfg(feature = "rsa")]
pub mod rsa;
