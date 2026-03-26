use super::explicit_nonce::Tls12AeadAlgorithmWithExplicitNonce;

macro_rules! impl_ccm {
    ($name:ident, $type:ty) => {
        pub const $name: &Tls12AeadAlgorithmWithExplicitNonce<$type> =
            &Tls12AeadAlgorithmWithExplicitNonce::DEFAULT;
    };
}

impl_ccm!(AES_128_CCM, crate::aead::aes::Aes128Ccm);
impl_ccm!(AES_256_CCM, crate::aead::aes::Aes256Ccm);
impl_ccm!(AES_128_CCM_8, crate::aead::aes::Aes128Ccm8);
impl_ccm!(AES_256_CCM_8, crate::aead::aes::Aes256Ccm8);
