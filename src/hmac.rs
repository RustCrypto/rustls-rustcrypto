#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use crypto_common::OutputSizeUser;
use paste::paste;
use rustls::crypto::hmac::{Hmac, Key, Tag};

macro_rules! impl_hmac {
    (
        $name: ident,
        $ty: ty
    ) => {
        paste! {
            #[allow(non_camel_case_types)]
            pub struct [<Hmac_ $name>];

            impl Hmac for [<Hmac_ $name>] {
                fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
                    use ::hmac::Mac;
                    Box::new([<HmacKey_ $name>](
                        ::hmac::Hmac::<$ty>::new_from_slice(key).unwrap(),
                    ))
                }

                fn hash_output_len(&self) -> usize {
                    $ty::output_size()
                }
            }

            #[allow(non_camel_case_types)]
            pub struct [<HmacKey_ $name>](::hmac::Hmac<$ty>);

            impl Key for [<HmacKey_ $name>] {
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
                    $ty::output_size()
                }
            }
            pub const $name: &dyn Hmac = &[<Hmac_ $name>];
        }
    };
}

impl_hmac! {SHA256, ::sha2::Sha256}
impl_hmac! {SHA384, ::sha2::Sha384}
// impl_hmac! {SHA512, Sha512}
