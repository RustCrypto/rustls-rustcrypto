#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use digest::{Digest, OutputSizeUser};
use preinterpret::preinterpret;
use rustls::crypto::{self, hash};

macro_rules! impl_hash {
    ($name:ident, $ty:ty, $algo:ty) => {
        preinterpret! {
            [!set! #hash_name = [!ident! Hash_ $name]]
            [!set! #hash_content_name = [!ident! HashContent_ $name]]

            #[allow(non_camel_case_types)]
            pub struct #hash_name;

            impl hash::Hash for #hash_name {
                fn start(&self) -> Box<dyn hash::Context> {
                    Box::new(#hash_content_name($ty::new()))
                }

                fn hash(&self, data: &[u8]) -> hash::Output {
                    hash::Output::new(&$ty::digest(data)[..])
                }

                fn output_len(&self) -> usize {
                    <$ty as OutputSizeUser>::output_size()
                }

                fn algorithm(&self) -> hash::HashAlgorithm {
                    $algo
                }
            }

            #[allow(non_camel_case_types)]
            pub struct #hash_content_name($ty);

            impl hash::Context for #hash_content_name {
                fn fork_finish(&self) -> hash::Output {
                    hash::Output::new(&self.0.clone().finalize()[..])
                }

                fn fork(&self) -> Box<dyn hash::Context> {
                    Box::new(#hash_content_name(self.0.clone()))
                }

                fn finish(self: Box<Self>) -> hash::Output {
                    hash::Output::new(&self.0.finalize()[..])
                }

                fn update(&mut self, data: &[u8]) {
                    self.0.update(data);
                }
            }

            pub const $name: &dyn crypto::hash::Hash = &#hash_name;
        }
    };
}

#[cfg(feature = "hash-sha224")]
impl_hash! {SHA224, ::sha2::Sha224, hash::HashAlgorithm::SHA224}
#[cfg(feature = "hash-sha256")]
impl_hash! {SHA256, ::sha2::Sha256, hash::HashAlgorithm::SHA256}
#[cfg(feature = "hash-sha384")]
impl_hash! {SHA384, ::sha2::Sha384, hash::HashAlgorithm::SHA384}
#[cfg(feature = "hash-sha512")]
impl_hash! {SHA512, ::sha2::Sha512, hash::HashAlgorithm::SHA512}
