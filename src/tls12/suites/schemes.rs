#[cfg(any(feature = "ecdsa", feature = "rsa"))]
use rustls::SignatureScheme;

#[cfg(feature = "ecdsa")]
pub const TLS12_ECDSA_SCHEMES: &[SignatureScheme] = &[
    #[cfg(feature = "p256")]
    SignatureScheme::ECDSA_NISTP256_SHA256,
    #[cfg(feature = "p384")]
    SignatureScheme::ECDSA_NISTP384_SHA384,
    #[cfg(feature = "p521")]
    SignatureScheme::ECDSA_NISTP521_SHA512,
    #[cfg(feature = "ed25519")]
    SignatureScheme::ED25519,
];

#[cfg(feature = "rsa")]
pub const TLS12_RSA_SCHEMES: &[SignatureScheme] = &[
    #[cfg(feature = "rsa-pkcs1")]
    SignatureScheme::RSA_PKCS1_SHA256,
    #[cfg(feature = "rsa-pkcs1")]
    SignatureScheme::RSA_PKCS1_SHA384,
    #[cfg(feature = "rsa-pkcs1")]
    SignatureScheme::RSA_PKCS1_SHA512,
    #[cfg(feature = "rsa-pss")]
    SignatureScheme::RSA_PSS_SHA256,
    #[cfg(feature = "rsa-pss")]
    SignatureScheme::RSA_PSS_SHA384,
    #[cfg(feature = "rsa-pss")]
    SignatureScheme::RSA_PSS_SHA512,
];
