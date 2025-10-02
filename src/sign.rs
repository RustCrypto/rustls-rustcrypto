#[cfg(feature = "alloc")]
use alloc::{sync::Arc, vec::Vec};
use core::marker::PhantomData;

#[cfg(feature = "p256")]
use self::ecdsa::EcdsaSigningKeyP256;
#[cfg(feature = "p384")]
use self::ecdsa::EcdsaSigningKeyP384;
#[cfg(feature = "ed25519")]
use self::eddsa::Ed25519SigningKey;
#[cfg(feature = "rsa")]
use self::rsa::RsaSigningKey;

use pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{Error, SignatureScheme};
use signature::{RandomizedSigner, SignatureEncoding};

#[derive(Debug)]
pub struct GenericRandomizedSigner<S, T>
where
    S: SignatureEncoding,
    T: RandomizedSigner<S>,
{
    _marker: PhantomData<S>,
    key: Arc<T>,
    scheme: SignatureScheme,
}

impl<T, S> Signer for GenericRandomizedSigner<S, T>
where
    S: SignatureEncoding + Send + Sync + core::fmt::Debug,
    T: RandomizedSigner<S> + Send + Sync + core::fmt::Debug,
{
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.key
            .try_sign_with_rng(&mut rand_core::OsRng, message)
            .map_err(|_| rustls::Error::General("signing failed".into()))
            .map(|sig: S| sig.to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
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
#[allow(unused_variables, reason = "the argument is unused if all features are disabled")]
pub fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, rustls::Error> {
    #[cfg(feature = "rsa")]
    if let Ok(key) = RsaSigningKey::try_from(der) {
        return Ok(Arc::new(key));
    }

    #[cfg(any(feature = "p256", feature = "p384"))]
    if let Ok(key) = any_ecdsa_type(der) {
        return Ok(key);
    }

    #[cfg(feature = "ed25519")]
    if let Ok(key) = any_eddsa_type(der) {
        return Ok(key);
    }

    Err(rustls::Error::General("unsupported private key format".into()))
}

#[cfg(any(feature = "p256", feature = "p384"))]
/// Extract any supported ECDSA key from the given DER input.
///
/// # Errors
///
/// Returns an error if the key couldn't be decoded.
pub fn any_ecdsa_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, rustls::Error> {
    #[cfg(feature = "p256")]
    if let Ok(key) = EcdsaSigningKeyP256::try_from(der) {
        return Ok(Arc::new(key));
    }

    #[cfg(feature = "p384")]
    if let Ok(key) = EcdsaSigningKeyP384::try_from(der) {
        return Ok(Arc::new(key));
    }

    Err(rustls::Error::General("unsupported private key format".into()))
}

#[cfg(feature = "ed25519")]
/// Extract any supported EDDSA key from the given DER input.
///
/// # Errors
///
/// Returns an error if the key couldn't be decoded.
pub fn any_eddsa_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, rustls::Error> {
    // TODO: Add support for Ed448
    Ed25519SigningKey::try_from(der).map(|x| Arc::new(x) as _)
}

#[cfg(any(feature = "p256", feature = "p384"))]
pub mod ecdsa;
#[cfg(feature = "ed25519")]
pub mod eddsa;
#[cfg(feature = "rsa")]
pub mod rsa;
