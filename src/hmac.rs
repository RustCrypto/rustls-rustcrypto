use alloc::boxed::Box;
use core::marker::PhantomData;

use block_buffer::Eager;
use crypto_common::{BlockSizeUser, OutputSizeUser};
use digest::{
    core_api::{BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
    HashMarker,
};
use hmac::Mac;
use rustls::crypto;
use typenum::{IsLess, Le, NonZero, U256};

pub struct Hmac<D>(PhantomData<D>);

impl<D> Hmac<D> {
    pub const DEFAULT: Self = Self(PhantomData);
}

impl<D> crypto::hmac::Hmac for Hmac<D>
where
    D: Send + Sync + OutputSizeUser + CoreProxy + 'static,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone
        + Send
        + Sync,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(HmacKey(hmac::Hmac::<D>::new_from_slice(key).unwrap()))
    }

    fn hash_output_len(&self) -> usize {
        D::output_size()
    }
}

pub struct HmacKey<D>(D);

impl<D> crypto::hmac::Key for HmacKey<D>
where
    D: Mac + Sync + Send + Clone,
{
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let mut ctx = self.0.clone();
        ctx.update(first);
        for m in middle {
            ctx.update(m);
        }
        ctx.update(last);
        crypto::hmac::Tag::new(&ctx.finalize().into_bytes()[..])
    }

    fn tag_len(&self) -> usize {
        D::output_size()
    }
}
