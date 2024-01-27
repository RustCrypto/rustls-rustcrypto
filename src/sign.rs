use alloc::{sync::Arc, vec::Vec};
use core::marker::PhantomData;

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

pub fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, rustls::Error> {
    let rsa = |_| RsaSigningKey::try_from(der).map(|x| Arc::new(x) as _);

    rsa(())
        .or_else(|_| any_ecdsa_type(der))
        .or_else(|_| any_eddsa_type(der))
}

pub fn any_ecdsa_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, rustls::Error> {
    let p256 = |_| EcdsaSigningKeyP256::try_from(der).map(|x| Arc::new(x) as _);
    let p384 = |_| EcdsaSigningKeyP384::try_from(der).map(|x| Arc::new(x) as _);
    p256(()).or_else(p384)
}

pub fn any_eddsa_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, rustls::Error> {
    let ed25519 = |_| Ed25519SigningKey::try_from(der).map(|x| Arc::new(x) as _);

    // TODO: Add support for Ed448

    ed25519(())
}

pub mod ecdsa;
pub mod eddsa;
pub mod rsa;
