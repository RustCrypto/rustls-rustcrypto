#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use crypto_common::OutputSizeUser;
use hmac::{KeyInit, Mac};
use paste::paste;
use rustls::crypto;
use sha2::{Sha256, Sha384, Sha512};

macro_rules! impl_hmac {
    (
        $name: ident,
        $ty: ty
    ) => {
        paste! {
            #[allow(non_camel_case_types)]
            struct [<Hmac_ $ty>];

            impl crypto::hmac::Hmac for [<Hmac_ $ty>] {
                fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
                    Box::new([<HmacKey_ $ty>](
                        hmac::Hmac::<$ty>::new_from_slice(key).unwrap(),
                    ))
                }

                fn hash_output_len(&self) -> usize {
                    $ty::output_size()
                }
            }

            #[allow(non_camel_case_types)]
            struct [<HmacKey_ $ty>](hmac::Hmac<$ty>);

            impl crypto::hmac::Key for [<HmacKey_ $ty>] {
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
                    $ty::output_size()
                }
            }
            pub const $name: &dyn crypto::hmac::Hmac = &[<Hmac_ $ty>];
        }
    };
}

impl_hmac! {SHA256, Sha256}
impl_hmac! {SHA384, Sha384}
impl_hmac! {SHA512, Sha512}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha512_hmac_provider() {
        assert_eq!(SHA512.hash_output_len(), 64);
        let key = SHA512.with_key(b"key");
        assert_eq!(key.tag_len(), 64);
        let tag = key.sign_concat(b"a", &[], b"b");
        assert_eq!(tag.as_ref().len(), 64);
    }
}
