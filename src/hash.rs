use alloc::boxed::Box;
use core::marker::PhantomData;

use hmac::digest::OutputSizeUser;
use rustls::crypto::hash;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

trait Algorithm {
    const ALGORITHM: hash::HashAlgorithm;
}

pub struct Hash<D>(PhantomData<D>);

impl<D> Hash<D> {
    pub const DEFAULT: Self = Self(PhantomData);
}

impl<D> hash::Hash for Hash<D>
where
    D: Send + Sync + Digest + Clone + 'static,
    Hash<D>: Algorithm,
{
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(HashContext(D::new()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&D::digest(data)[..])
    }

    fn output_len(&self) -> usize {
        <D as OutputSizeUser>::output_size()
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        <Self as Algorithm>::ALGORITHM
    }
}

struct HashContext<D>(D);

impl<D> hash::Context for HashContext<D>
where
    D: Sync + Send + Clone + Digest + 'static,
{
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().finalize()[..])
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(HashContext(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finalize()[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

impl Algorithm for Hash<Sha224> {
    const ALGORITHM: hash::HashAlgorithm = hash::HashAlgorithm::SHA224;
}

impl Algorithm for Hash<Sha256> {
    const ALGORITHM: hash::HashAlgorithm = hash::HashAlgorithm::SHA256;
}

impl Algorithm for Hash<Sha384> {
    const ALGORITHM: hash::HashAlgorithm = hash::HashAlgorithm::SHA384;
}

impl Algorithm for Hash<Sha512> {
    const ALGORITHM: hash::HashAlgorithm = hash::HashAlgorithm::SHA512;
}
