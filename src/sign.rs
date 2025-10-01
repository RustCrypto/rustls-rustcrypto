#[cfg(feature = "alloc")]
use alloc::{string::ToString, sync::Arc, vec::Vec};
use core::marker::PhantomData;

use pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{Error, SignatureScheme};
use signature::SignatureEncoding;

/// Errors that can occur in the signing module
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// Signing operation failed
    #[error("signing failed: {0}")]
    SigningFailed(signature::Error),

    /// Key type not supported
    #[error("key type not supported")]
    NotSupported,
}

impl From<signature::Error> for SignError {
    fn from(e: signature::Error) -> Self {
        Self::SigningFailed(e)
    }
}

impl From<SignError> for rustls::Error {
    fn from(e: SignError) -> Self {
        rustls::Error::General(e.to_string())
    }
}

#[derive(Debug)]
pub struct GenericSigner<S, T>
where
    S: SignatureEncoding,
    T: signature::Signer<S>,
{
    _marker: PhantomData<S>,
    key: Arc<T>,
    scheme: SignatureScheme,
}

impl<S, T> Signer for GenericSigner<S, T>
where
    S: SignatureEncoding + Send + Sync + core::fmt::Debug,
    T: signature::Signer<S> + Send + Sync + core::fmt::Debug,
{
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.key
            .try_sign(message)
            .map_err(SignError::SigningFailed)
            .map(|sig: S| sig.to_vec())
            .map_err(Into::into)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// Extract any supported key from the given DER input.
///
/// # Errors
///
/// Returns an error if the key couldn't be decoded.
#[allow(unused_variables)]
pub fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, SignError> {
    #[cfg(feature = "sign-rsa")]
    if let Ok(key) = rsa::RsaSigningKey::try_from(der) {
        return Ok(Arc::new(key) as _);
    }

    #[cfg(feature = "sign-ecdsa-nist")]
    if let Ok(key) = any_ecdsa_type(der) {
        return Ok(key);
    }

    #[cfg(feature = "sign-eddsa")]
    if let Ok(key) = any_eddsa_type(der) {
        return Ok(key);
    }

    Err(SignError::NotSupported)
}

/// Extract any supported ECDSA key from the given DER input.
///
/// # Errors
///
/// Returns an error if the key couldn't be decoded.
#[allow(unused_variables)]
#[cfg(feature = "sign-ecdsa-nist")]
pub fn any_ecdsa_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, SignError> {
    #[cfg(all(feature = "der", feature = "ecdsa-p256"))]
    if let Ok(key) = ecdsa::nist::EcdsaSigningKeyP256::try_from(der) {
        return Ok(Arc::new(key) as _);
    }
    #[cfg(all(feature = "der", feature = "ecdsa-p384"))]
    if let Ok(key) = ecdsa::nist::EcdsaSigningKeyP384::try_from(der) {
        return Ok(Arc::new(key) as _);
    }

    Err(SignError::NotSupported)
}

/// Extract any supported EDDSA key from the given DER input.
///
/// # Errors
///
/// Returns an error if the key couldn't be decoded.
#[allow(unused_variables)]
#[cfg(feature = "sign-eddsa")]
pub fn any_eddsa_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, SignError> {
    #[cfg(all(feature = "der", feature = "eddsa-ed25519"))]
    if let Ok(key) = eddsa::ed25519::Ed25519SigningKey::try_from(der) {
        return Ok(Arc::new(key) as _);
    }

    #[cfg(all(feature = "der", feature = "eddsa-ed448"))]
    if let Ok(key) = eddsa::ed448::Ed448SigningKey::try_from(der) {
        return Ok(Arc::new(key) as _);
    }

    Err(SignError::NotSupported)
}

#[cfg(feature = "ecdsa")]
pub mod ecdsa;
#[cfg(feature = "eddsa")]
pub mod eddsa;
#[cfg(feature = "rsa")]
pub mod rsa;

#[cfg(feature = "rand")]
pub mod rand;
