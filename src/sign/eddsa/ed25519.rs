#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::ToString, sync::Arc};

use crate::sign::GenericSigner;
use core::marker::PhantomData;
use ed25519_dalek::SigningKey;
use rustls::{SignatureAlgorithm, SignatureScheme, sign::Signer};

#[cfg(feature = "der")]
use pki_types::PrivateKeyDer;

/// Errors that can occur when loading an Ed25519 private key
#[derive(Debug, thiserror::Error)]
pub enum Ed25519KeyError {
    /// Failed to decode PKCS#8 private key
    #[cfg(feature = "pkcs8")]
    #[error("failed to decrypt PKCS#8 private key: {0}")]
    Pkcs8(::pkcs8::Error),

    /// ED25519 does not support SEC-1 keys
    #[error("ED25519 does not support SEC-1 key")]
    Sec1NotSupported,

    /// ED25519 does not support PKCS#1 keys
    #[error("ED25519 does not support PKCS#1 key")]
    Pkcs1NotSupported,

    /// Key format not supported
    #[error("key format not supported")]
    NotSupported,
}

#[cfg(feature = "pkcs8")]
impl From<::pkcs8::Error> for Ed25519KeyError {
    fn from(e: ::pkcs8::Error) -> Self {
        Self::Pkcs8(e)
    }
}

impl From<Ed25519KeyError> for rustls::Error {
    fn from(e: Ed25519KeyError) -> Self {
        rustls::Error::General(e.to_string())
    }
}

#[derive(Debug)]
pub struct Ed25519SigningKey(Arc<SigningKey>);

#[cfg(feature = "der")]
impl TryFrom<&PrivateKeyDer<'_>> for Ed25519SigningKey {
    type Error = Ed25519KeyError;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        let pkey = match value {
            #[cfg(feature = "pkcs8")]
            PrivateKeyDer::Pkcs8(der) => {
                use pkcs8::DecodePrivateKey;
                SigningKey::from_pkcs8_der(der.secret_pkcs8_der()).map_err(Into::into)
            }

            // (chat log from tony in zulip)
            // Per RFC 8410, only PKCS#8 is supported for ED25519 keys
            // https://datatracker.ietf.org/doc/html/rfc8410#section-7
            // So no SEC 1 support for ED25519 (despite we do have it compile before?!)
            PrivateKeyDer::Sec1(_) => Err(Ed25519KeyError::Sec1NotSupported),
            PrivateKeyDer::Pkcs1(_) => Err(Ed25519KeyError::Pkcs1NotSupported),
            _ => Err(Ed25519KeyError::NotSupported),
        };
        pkey.map(|kp| Self(Arc::new(kp)))
    }
}

impl rustls::sign::SigningKey for Ed25519SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        const SCHEME: SignatureScheme = SignatureScheme::ED25519;
        if offered.contains(&SCHEME) {
            Some(Box::new(GenericSigner {
                _marker: PhantomData,
                key: self.0.clone(),
                scheme: SCHEME,
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}
