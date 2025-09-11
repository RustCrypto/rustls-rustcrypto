#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use core::marker::PhantomData;
use digest::{Digest, OutputSizeUser};
use rustls::crypto::{self, hash};

/// Trait to provide hash algorithm for different hash types
pub trait HashAlgorithm {
    const ALGORITHM: hash::HashAlgorithm;
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

impl<H> hash::Hash for GenericHash<H>
where
    H: Digest + OutputSizeUser + Clone + Send + Sync + 'static + HashAlgorithm,
{
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(GenericHashContext(H::new()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&H::digest(data)[..])
    }

    fn output_len(&self) -> usize {
        <H as OutputSizeUser>::output_size()
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        H::ALGORITHM
    }
}

// Implement HashAlgorithm trait for each hash type
#[cfg(feature = "hash-sha224")]
impl HashAlgorithm for ::sha2::Sha224 {
    const ALGORITHM: hash::HashAlgorithm = hash::HashAlgorithm::SHA224;
}

#[cfg(feature = "hash-sha256")]
impl HashAlgorithm for ::sha2::Sha256 {
    const ALGORITHM: hash::HashAlgorithm = hash::HashAlgorithm::SHA256;
}

#[cfg(feature = "hash-sha384")]
impl HashAlgorithm for ::sha2::Sha384 {
    const ALGORITHM: hash::HashAlgorithm = hash::HashAlgorithm::SHA384;
}

#[cfg(feature = "hash-sha512")]
impl HashAlgorithm for ::sha2::Sha512 {
    const ALGORITHM: hash::HashAlgorithm = hash::HashAlgorithm::SHA512;
}

pub struct GenericHashContext<H>(H);

impl<H> hash::Context for GenericHashContext<H>
where
    H: Digest + Clone + Send + Sync + 'static,
{
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().finalize()[..])
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(GenericHashContext(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finalize()[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

/// Macro to generate hash constants
macro_rules! hash_const {
    ($name:ident, $hash:ty, $feature:literal) => {
        #[cfg(feature = $feature)]
        pub const $name: &dyn crypto::hash::Hash = &GenericHash::<$hash>::DEFAULT;
    };
}

// Generate hash constants using macro
hash_const!(SHA224, ::sha2::Sha224, "hash-sha224");
hash_const!(SHA256, ::sha2::Sha256, "hash-sha256");
hash_const!(SHA384, ::sha2::Sha384, "hash-sha384");
hash_const!(SHA512, ::sha2::Sha512, "hash-sha512");
