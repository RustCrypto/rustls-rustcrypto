#[cfg(feature = "alloc")]
use alloc::{sync::Arc, vec::Vec};
use core::marker::PhantomData;

use rustls::sign::Signer;
use rustls::{Error, SignatureScheme};
use signature::{RandomizedSigner, SignatureEncoding};

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
            .map_err(|_| rustls::Error::General("signing failed".into()))
            .map(|sig: S| sig.to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
