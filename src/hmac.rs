#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use core::marker::PhantomData;
use crypto_common::OutputSizeUser;
use hmac::{EagerHash, Hmac};
use rustls::crypto::hmac::{Hmac as RustlsHmac, Key, Tag};

pub trait HmacHash: EagerHash + Send + Sync + 'static {}

impl<T> HmacHash for T where T: EagerHash + Send + Sync + 'static {}

pub struct GenericHmac<H: HmacHash> {
    _phantom: PhantomData<H>,
}

impl<H: HmacHash> GenericHmac<H> {
    pub const DEFAULT: Self = Self {
        _phantom: PhantomData,
    };
}

impl<H> RustlsHmac for GenericHmac<H>
where
    H: HmacHash,
    <H as EagerHash>::Core: Send + Sync,
{
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(GenericHmacKey::<H>(
            <::hmac::Hmac<H> as hmac::KeyInit>::new_from_slice(key)
                .expect("Invalid key length for HMAC"),
        ))
    }

    fn hash_output_len(&self) -> usize {
        <H as OutputSizeUser>::output_size()
    }
}

pub struct GenericHmacKey<H: HmacHash>(Hmac<H>);

impl<H> Key for GenericHmacKey<H>
where
    H: HmacHash,
    <H as EagerHash>::Core: Send + Sync,
{
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        use ::hmac::Mac;
        let mut ctx = self.0.clone();
        ctx.update(first);
        for m in middle {
            ctx.update(m);
        }
        ctx.update(last);
        Tag::new(&ctx.finalize().into_bytes()[..])
    }

    fn tag_len(&self) -> usize {
        <H as OutputSizeUser>::output_size()
    }
}

/// Macro to generate HMAC constants
macro_rules! hmac_const {
    ($name:ident, $hash:ty) => {
        pub const $name: &GenericHmac<$hash> = &GenericHmac::DEFAULT;
    };
}

// Generate HMAC constants using macro
hmac_const!(SHA256, ::sha2::Sha256);
hmac_const!(SHA384, ::sha2::Sha384);
hmac_const!(SHA512, ::sha2::Sha512);
