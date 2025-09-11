use super::common::Tls12AeadAlgorithmWithExplicitNonce;

pub const AES_128_CCM: &Tls12AeadAlgorithmWithExplicitNonce<crate::aead::aes::Aes128Ccm> =
    &Tls12AeadAlgorithmWithExplicitNonce::DEFAULT;
pub const AES_256_CCM: &Tls12AeadAlgorithmWithExplicitNonce<crate::aead::aes::Aes256Ccm> =
    &Tls12AeadAlgorithmWithExplicitNonce::DEFAULT;
pub const AES_128_CCM_8: &Tls12AeadAlgorithmWithExplicitNonce<crate::aead::aes::Aes128Ccm8> =
    &Tls12AeadAlgorithmWithExplicitNonce::DEFAULT;
pub const AES_256_CCM_8: &Tls12AeadAlgorithmWithExplicitNonce<crate::aead::aes::Aes256Ccm8> =
    &Tls12AeadAlgorithmWithExplicitNonce::DEFAULT;
