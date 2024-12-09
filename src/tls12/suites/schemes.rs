#[cfg(any(feature = "ecdsa", feature = "rsa"))]
use rustls::SignatureScheme;

#[cfg(feature = "ecdsa")]
pub const TLS12_ECDSA_SCHEMES: &[SignatureScheme] = &[
    #[cfg(all(feature = "ecdsa-p256", feature = "hash-sha256"))]
    SignatureScheme::ECDSA_NISTP256_SHA256,
    #[cfg(all(feature = "ecdsa-p384", feature = "hash-sha384"))]
    SignatureScheme::ECDSA_NISTP384_SHA384,
    #[cfg(all(feature = "ecdsa-p521", feature = "hash-sha512"))]
    SignatureScheme::ECDSA_NISTP521_SHA512,
    #[cfg(feature = "eddsa-ed25519")]
    SignatureScheme::ED25519,
];

#[cfg(feature = "rsa")]
pub const TLS12_RSA_SCHEMES: &[SignatureScheme] = &[
    #[cfg(all(feature = "rsa-pkcs1", feature = "hash-sha256"))]
    SignatureScheme::RSA_PKCS1_SHA256,
    #[cfg(all(feature = "rsa-pkcs1", feature = "hash-sha384"))]
    SignatureScheme::RSA_PKCS1_SHA384,
    #[cfg(all(feature = "rsa-pkcs1", feature = "hash-sha512"))]
    SignatureScheme::RSA_PKCS1_SHA512,
    #[cfg(all(feature = "rsa-pss", feature = "hash-sha256"))]
    SignatureScheme::RSA_PSS_SHA256,
    #[cfg(all(feature = "rsa-pss", feature = "hash-sha384"))]
    SignatureScheme::RSA_PSS_SHA384,
    #[cfg(all(feature = "rsa-pss", feature = "hash-sha512"))]
    SignatureScheme::RSA_PSS_SHA512,
];
