#[cfg(feature = "alloc")]
use alloc::{sync::Arc, vec::Vec};
use core::marker::PhantomData;

#[cfg(feature = "p256")]
use self::ecdsa::EcdsaSigningKeyP256;
#[cfg(feature = "p384")]
use self::ecdsa::EcdsaSigningKeyP384;
use self::eddsa::Ed25519SigningKey;
#[cfg(feature = "rsa")]
use self::rsa::RsaSigningKey;

#[cfg(any(feature = "p256", feature = "p384", feature = "rsa"))]
use getrandom::rand_core::UnwrapErr;
use pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{Error, SignatureScheme};
use signature::SignatureEncoding;

#[cfg(any(feature = "p256", feature = "p384", feature = "rsa"))]
use signature::RandomizedSigner;

#[cfg(any(feature = "p256", feature = "p384", feature = "rsa"))]
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

#[cfg(any(feature = "p256", feature = "p384", feature = "rsa"))]
impl<T, S> Signer for GenericRandomizedSigner<S, T>
where
    S: SignatureEncoding + Send + Sync + core::fmt::Debug,
    T: RandomizedSigner<S> + Send + Sync + core::fmt::Debug,
{
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut rng = UnwrapErr(getrandom::SysRng);
        self.key
            .try_sign_with_rng(&mut rng, message)
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
pub fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, rustls::Error> {
    #[cfg(feature = "rsa")]
    if let Ok(key) = RsaSigningKey::try_from(der) {
        return Ok(Arc::new(key) as _);
    }
    #[cfg(any(feature = "p256", feature = "p384"))]
    if let Ok(key) = any_ecdsa_type(der) {
        return Ok(key);
    }
    any_eddsa_type(der)
}

/// Extract any supported ECDSA key from the given DER input.
///
/// # Errors
///
/// Returns an error if the key couldn't be decoded.
#[cfg(any(feature = "p256", feature = "p384"))]
pub fn any_ecdsa_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, rustls::Error> {
    #[cfg(feature = "p256")]
    let p256 = |_| EcdsaSigningKeyP256::try_from(der).map(|x| Arc::new(x) as _);
    #[cfg(feature = "p384")]
    let p384 = |_| EcdsaSigningKeyP384::try_from(der).map(|x| Arc::new(x) as _);

    #[cfg(all(feature = "p256", feature = "p384"))]
    {
        p256(()).or_else(p384)
    }
    #[cfg(all(feature = "p256", not(feature = "p384")))]
    {
        p256(())
    }
    #[cfg(all(not(feature = "p256"), feature = "p384"))]
    {
        p384(())
    }
}

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
pub mod eddsa;
#[cfg(feature = "rsa")]
pub mod rsa;
