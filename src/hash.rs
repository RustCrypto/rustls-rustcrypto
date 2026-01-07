#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use core::marker::PhantomData;
use digest::{Digest, OutputSizeUser};

/// Trait to provide hash algorithm for different hash types
pub trait HashAlgorithm {
    const ALGORITHM: rustls::crypto::hash::HashAlgorithm;
}

// Generic hash implementation
#[derive(Default)]
pub struct GenericHash<H> {
    _phantom: PhantomData<H>,
}

impl<H> GenericHash<H> {
    pub const DEFAULT: Self = Self {
        _phantom: PhantomData,
    };
}

impl<H> rustls::crypto::hash::Hash for GenericHash<H>
where
    H: Digest + OutputSizeUser + Clone + Send + Sync + 'static + HashAlgorithm,
{
    fn start(&self) -> Box<dyn rustls::crypto::hash::Context> {
        Box::new(GenericHashContext(H::new()))
    }

    fn hash(&self, data: &[u8]) -> rustls::crypto::hash::Output {
        rustls::crypto::hash::Output::new(&H::digest(data)[..])
    }

    fn output_len(&self) -> usize {
        <H as OutputSizeUser>::output_size()
    }

    fn algorithm(&self) -> rustls::crypto::hash::HashAlgorithm {
        H::ALGORITHM
    }
}

pub struct GenericHashContext<H>(H);

impl<H> rustls::crypto::hash::Context for GenericHashContext<H>
where
    H: Digest + Clone + Send + Sync + 'static,
{
    fn fork_finish(&self) -> rustls::crypto::hash::Output {
        rustls::crypto::hash::Output::new(&self.0.clone().finalize()[..])
    }

    fn fork(&self) -> Box<dyn rustls::crypto::hash::Context> {
        Box::new(GenericHashContext(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> rustls::crypto::hash::Output {
        rustls::crypto::hash::Output::new(&self.0.finalize()[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

/// Macro to generate hash constants
macro_rules! impl_hash {
    ($name:ident, $hash:ty) => {
        impl HashAlgorithm for $hash {
            const ALGORITHM: rustls::crypto::hash::HashAlgorithm =
                rustls::crypto::hash::HashAlgorithm::$name;
        }

        pub const $name: &dyn rustls::crypto::hash::Hash = &GenericHash::<$hash>::DEFAULT;
    };
}

// Generate hash constants using macro
#[cfg(feature = "hash-sha224")]
impl_hash!(SHA224, ::sha2::Sha224);
#[cfg(feature = "hash-sha256")]
impl_hash!(SHA256, ::sha2::Sha256);
#[cfg(feature = "hash-sha384")]
impl_hash!(SHA384, ::sha2::Sha384);
#[cfg(feature = "hash-sha512")]
impl_hash!(SHA512, ::sha2::Sha512);
