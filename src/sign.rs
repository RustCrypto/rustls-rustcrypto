#[cfg(feature = "alloc")]
use alloc::{sync::Arc, vec::Vec};
use core::marker::PhantomData;

use pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{Error, SignatureScheme};
use signature::SignatureEncoding;

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
            .map_err(|_| rustls::Error::General("signing failed".into()))
            .map(|sig: S| sig.to_vec())
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
pub fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, rustls::Error> {
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

    Err(rustls::Error::General("not supported".into()))
}

/// Extract any supported ECDSA key from the given DER input.
///
/// # Errors
///
/// Returns an error if the key couldn't be decoded.
#[allow(unused_variables)]
#[cfg(feature = "sign-ecdsa-nist")]
pub fn any_ecdsa_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, rustls::Error> {
    #[cfg(all(feature = "der", feature = "ecdsa-p256"))]
    if let Ok(key) = ecdsa::nist::EcdsaSigningKeyP256::try_from(der) {
        return Ok(Arc::new(key) as _);
    }
    #[cfg(all(feature = "der", feature = "ecdsa-p384"))]
    if let Ok(key) = ecdsa::nist::EcdsaSigningKeyP384::try_from(der) {
        return Ok(Arc::new(key) as _);
    }

    Err(rustls::Error::General("not supported".into()))
}

/// Extract any supported EDDSA key from the given DER input.
///
/// # Errors
///
/// Returns an error if the key couldn't be decoded.
#[allow(unused_variables)]
#[cfg(feature = "sign-eddsa")]
pub fn any_eddsa_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, rustls::Error> {
    #[cfg(all(feature = "der", feature = "eddsa-ed25519"))]
    if let Ok(key) = eddsa::ed25519::Ed25519SigningKey::try_from(der) {
        return Ok(Arc::new(key) as _);
    }

    #[cfg(all(feature = "der", feature = "eddsa-ed448"))]
    if let Ok(key) = eddsa::ed448::Ed448SigningKey::try_from(der) {
        return Ok(Arc::new(key) as _);
    }

    Err(rustls::Error::General("not supported".into()))
}

#[cfg(feature = "ecdsa")]
pub mod ecdsa;
#[cfg(feature = "eddsa")]
pub mod eddsa;
#[cfg(feature = "rsa")]
pub mod rsa;

#[cfg(feature = "rand")]
pub mod rand;
