use super::common::Tls13AeadAlgorithmCommon;

pub const AES_128_CCM: &Tls13AeadAlgorithmCommon<crate::aead::aes::Aes128Ccm> =
    &Tls13AeadAlgorithmCommon::DEFAULT;
pub const AES_128_CCM_8: &Tls13AeadAlgorithmCommon<crate::aead::aes::Aes128Ccm8> =
    &Tls13AeadAlgorithmCommon::DEFAULT;
