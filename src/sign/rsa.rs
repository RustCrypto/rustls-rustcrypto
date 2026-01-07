#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::ToString, sync::Arc};

use rsa::RsaPrivateKey;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

#[cfg(feature = "hash-sha256")]
use sha2::Sha256;
#[cfg(feature = "hash-sha384")]
use sha2::Sha384;
#[cfg(feature = "hash-sha512")]
use sha2::Sha512;

#[cfg(feature = "der")]
use pki_types::PrivateKeyDer;

/// Errors that can occur when loading an RSA private key
#[derive(Debug, thiserror::Error)]
pub enum RsaKeyError {
    /// Failed to decode PKCS#8 private key
    #[cfg(feature = "pkcs8")]
    #[error("failed to decrypt PKCS#8 private key: {0}")]
    Pkcs8(::pkcs8::Error),

    /// Failed to decode PKCS#1 private key
    #[cfg(all(feature = "pkcs8", feature = "pkcs1"))]
    #[error("failed to decrypt PKCS#1 private key: {0}")]
    Pkcs1(#[from] ::pkcs1::Error),

    /// RSA does not support SEC-1 keys
    #[error("RSA does not support SEC-1 key")]
    Sec1NotSupported,

    /// Key format not supported
    #[error("key format not supported")]
    NotSupported,
}

#[cfg(feature = "pkcs8")]
impl From<::pkcs8::Error> for RsaKeyError {
    fn from(e: ::pkcs8::Error) -> Self {
        Self::Pkcs8(e)
    }
}

impl From<RsaKeyError> for rustls::Error {
    fn from(e: RsaKeyError) -> Self {
        rustls::Error::General(e.to_string())
    }
}

const ALL_RSA_SCHEMES: &[SignatureScheme] = &[
    #[cfg(all(feature = "rsa-pss", feature = "hash-sha512"))]
    SignatureScheme::RSA_PSS_SHA512,
    #[cfg(all(feature = "rsa-pss", feature = "hash-sha384"))]
    SignatureScheme::RSA_PSS_SHA384,
    #[cfg(all(feature = "rsa-pss", feature = "hash-sha256"))]
    SignatureScheme::RSA_PSS_SHA256,
    #[cfg(all(feature = "rsa-pkcs1", feature = "hash-sha512"))]
    SignatureScheme::RSA_PKCS1_SHA512,
    #[cfg(all(feature = "rsa-pkcs1", feature = "hash-sha384"))]
    SignatureScheme::RSA_PKCS1_SHA384,
    #[cfg(all(feature = "rsa-pkcs1", feature = "hash-sha256"))]
    SignatureScheme::RSA_PKCS1_SHA256,
];

#[derive(Debug, Clone)]
pub struct RsaSigningKey(RsaPrivateKey);

#[cfg(feature = "der")]
impl TryFrom<&PrivateKeyDer<'_>> for RsaSigningKey {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        let pkey = match value {
            #[cfg(feature = "pkcs8")]
            PrivateKeyDer::Pkcs8(der) => {
                use pkcs8::DecodePrivateKey;
                RsaPrivateKey::from_pkcs8_der(der.secret_pkcs8_der()).map_err(Into::into)
            }
            #[cfg(all(feature = "pkcs8", feature = "pkcs1"))]
            PrivateKeyDer::Pkcs1(der) => {
                use pkcs1::DecodeRsaPrivateKey;
                RsaPrivateKey::from_pkcs1_der(der.secret_pkcs1_der()).map_err(Into::into)
            }
            PrivateKeyDer::Sec1(_) => Err(RsaKeyError::Sec1NotSupported),
            _ => Err(RsaKeyError::NotSupported),
        };

        pkey.map(Self).map_err(Into::into)
    }
}

impl SigningKey for RsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        ALL_RSA_SCHEMES
            .iter()
            .find(|scheme| offered.contains(scheme))
            .and_then(|&scheme| {
                macro_rules! signer {
                    ($key:ty) => {{
                        Some(Box::new(super::rand::GenericRandomizedSigner {
                            _marker: Default::default(),
                            key: Arc::new(<$key>::new(self.0.clone())),
                            scheme,
                        }) as Box<_>)
                    }};
                }

                match scheme {
                    #[cfg(all(feature = "rsa-pss", feature = "hash-sha512"))]
                    SignatureScheme::RSA_PSS_SHA512 => signer! {::rsa::pss::SigningKey::<Sha512>},
                    #[cfg(all(feature = "rsa-pss", feature = "hash-sha384"))]
                    SignatureScheme::RSA_PSS_SHA384 => signer! {::rsa::pss::SigningKey::<Sha384>},
                    #[cfg(all(feature = "rsa-pss", feature = "hash-sha256"))]
                    SignatureScheme::RSA_PSS_SHA256 => signer! {::rsa::pss::SigningKey::<Sha256>},
                    #[cfg(all(feature = "rsa-pkcs1", feature = "hash-sha512"))]
                    SignatureScheme::RSA_PKCS1_SHA512 => {
                        signer! {::rsa::pkcs1v15::SigningKey::<Sha512>}
                    }
                    #[cfg(all(feature = "rsa-pkcs1", feature = "hash-sha384"))]
                    SignatureScheme::RSA_PKCS1_SHA384 => {
                        signer! {::rsa::pkcs1v15::SigningKey::<Sha384>}
                    }
                    #[cfg(all(feature = "rsa-pkcs1", feature = "hash-sha256"))]
                    SignatureScheme::RSA_PKCS1_SHA256 => {
                        signer! {::rsa::pkcs1v15::SigningKey::<Sha256>}
                    }
                    _ => None,
                }
            })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}
