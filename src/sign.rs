use alloc::{sync::Arc, vec::Vec};
use core::{fmt, marker::PhantomData};

use pki_types::PrivateKeyDer;
use rustls::{
    sign::{Signer, SigningKey},
    Error, SignatureScheme,
};
use signature::{RandomizedSigner, SignatureEncoding};

use self::{
    ecdsa::{EcdsaSigningKeyP256, EcdsaSigningKeyP384},
    eddsa::Ed25519SigningKey,
    rsa::RsaSigningKey,
};

#[derive(Debug)]
pub struct GenericRandomizedSigner<S, T>
where
    S: SignatureEncoding,
    T: RandomizedSigner<S>,
{
    _marker: PhantomData<S>,
    key:     Arc<T>,
    scheme:  SignatureScheme,
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
    key:     Arc<T>,
    scheme:  SignatureScheme,
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

#[derive(Debug)]
pub struct SignError(());

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("sign error")
    }
}

pub fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, SignError> {
    if let Ok(rsa) = RsaSigningKey::try_from(der) {
        Ok(Arc::new(rsa))
    } else if let Ok(ecdsa) = any_ecdsa_type(der) {
        Ok(ecdsa)
    } else if let Ok(eddsa) = any_eddsa_type(der) {
        Ok(eddsa)
    } else {
        Err(SignError(()))
    }
}

pub fn any_ecdsa_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, SignError> {
    if let Ok(ecdsa_p256) = EcdsaSigningKeyP256::try_from(der) {
        return Ok(Arc::new(ecdsa_p256));
    }

    if let Ok(ecdsa_p384) = EcdsaSigningKeyP384::try_from(der) {
        return Ok(Arc::new(ecdsa_p384));
    }

    Err(SignError(()))
}

pub fn any_eddsa_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, SignError> {
    if let Ok(ed25519) = Ed25519SigningKey::try_from(der) {
        return Ok(Arc::new(ed25519));
    }

    // TODO: Add support for Ed448

    Err(SignError(()))
}

pub mod ecdsa;
pub mod eddsa;
pub mod rsa;
