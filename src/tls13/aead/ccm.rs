use super::common::Tls13AeadAlgorithmCommon;
use crate::aead;

pub const AES_128_CCM: &Tls13AeadAlgorithmCommon<aead::aes::Aes128Ccm> =
    &Tls13AeadAlgorithmCommon::DEFAULT;
pub const AES_128_CCM_8: &Tls13AeadAlgorithmCommon<aead::aes::Aes128Ccm8> =
    &Tls13AeadAlgorithmCommon::DEFAULT;
