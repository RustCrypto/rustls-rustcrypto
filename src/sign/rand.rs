#[cfg(feature = "alloc")]
use alloc::{string::ToString, sync::Arc, vec::Vec};
use core::marker::PhantomData;

use rustls::sign::Signer;
use rustls::{Error, SignatureScheme};
use signature::{RandomizedSigner, SignatureEncoding};

/// Error that occurs during signing
#[derive(Debug, thiserror::Error)]
#[error("signing failed: {0}")]
pub struct SigningError(signature::Error);

impl From<signature::Error> for SigningError {
    fn from(e: signature::Error) -> Self {
        Self(e)
    }
}

impl From<SigningError> for rustls::Error {
    fn from(e: SigningError) -> Self {
        rustls::Error::General(e.to_string())
    }
}

#[derive(Debug)]
pub struct GenericRandomizedSigner<S, T>
where
    S: SignatureEncoding,
    T: RandomizedSigner<S>,
{
    pub(crate) _marker: PhantomData<S>,
    pub(crate) key: Arc<T>,
    pub(crate) scheme: SignatureScheme,
}

impl<T, S> Signer for GenericRandomizedSigner<S, T>
where
    S: SignatureEncoding + Send + Sync + core::fmt::Debug,
    T: RandomizedSigner<S> + Send + Sync + core::fmt::Debug,
{
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.key
            .try_sign_with_rng(&mut rand_core::OsRng, message)
            .map_err(SigningError::from)
            .map(|sig: S| sig.to_vec())
            .map_err(Into::into)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
