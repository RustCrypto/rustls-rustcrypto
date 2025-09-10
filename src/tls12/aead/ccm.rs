use const_default::ConstDefault;

use super::common::Tls12AeadAlgorithmWithExplicitNonce;

pub const AES_128_CCM: &Tls12AeadAlgorithmWithExplicitNonce<crate::aead::aes::Aes128Ccm> =
    &ConstDefault::DEFAULT;
pub const AES_256_CCM: &Tls12AeadAlgorithmWithExplicitNonce<crate::aead::aes::Aes256Ccm> =
    &ConstDefault::DEFAULT;
pub const AES_128_CCM_8: &Tls12AeadAlgorithmWithExplicitNonce<crate::aead::aes::Aes128Ccm8> =
    &ConstDefault::DEFAULT;
pub const AES_256_CCM_8: &Tls12AeadAlgorithmWithExplicitNonce<crate::aead::aes::Aes256Ccm8> =
    &ConstDefault::DEFAULT;
