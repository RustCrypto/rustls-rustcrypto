use const_default::ConstDefault;

use super::common::Tls13AeadAlgorithmCommon;
use crate::aead;

pub const AES_128_CCM: &Tls13AeadAlgorithmCommon<aead::aes::Aes128Ccm> = &ConstDefault::DEFAULT;
pub const AES_128_CCM_8: &Tls13AeadAlgorithmCommon<aead::aes::Aes128Ccm8> = &ConstDefault::DEFAULT;
