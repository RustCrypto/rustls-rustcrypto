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

#[cfg(feature = "hash-sha256")]
pub const SHA256: &dyn RustlsHmac = &GenericHmac::<::sha2::Sha256> {
    _phantom: PhantomData,
};

#[cfg(feature = "hash-sha384")]
pub const SHA384: &dyn RustlsHmac = &GenericHmac::<::sha2::Sha384> {
    _phantom: PhantomData,
};

#[cfg(feature = "hash-sha512")]
pub const SHA512: &dyn RustlsHmac = &GenericHmac::<::sha2::Sha512> {
    _phantom: PhantomData,
};
