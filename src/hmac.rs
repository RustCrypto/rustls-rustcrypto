#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use crypto_common::KeyInit;
use crypto_common::OutputSizeUser;
use preinterpret::preinterpret;
use rustls::crypto::hmac::{Hmac, Key, Tag};

macro_rules! impl_hmac {
    (
        $name: ident,
        $ty: ty
    ) => {
        preinterpret! {
            [!set! #hmac_type_name = [!ident! Hmac_ $name]]
            [!set! #hmac_key_type_name = [!ident! HmacKey_ $name]]

            #[allow(non_camel_case_types)]
            pub struct #hmac_type_name;

            impl Hmac for #hmac_type_name {
                fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
                    Box::new(#hmac_key_type_name(
                        ::hmac::Hmac::<$ty>::new_from_slice(key).expect("Invalid key length for HMAC"),
                    ))
                }

                fn hash_output_len(&self) -> usize {
                    $ty::output_size()
                }
            }

            #[allow(non_camel_case_types)]
            pub struct #hmac_key_type_name(::hmac::Hmac<$ty>);

            impl Key for #hmac_key_type_name {
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
            pub const $name: &dyn Hmac = &#hmac_type_name;
        }
    };
}

#[cfg(feature = "hash-sha256")]
impl_hmac! {SHA256, ::sha2::Sha256}
#[cfg(feature = "hash-sha384")]
impl_hmac! {SHA384, ::sha2::Sha384}
#[cfg(feature = "hash-sha512")]
impl_hmac! {SHA512, ::sha2::Sha512}
