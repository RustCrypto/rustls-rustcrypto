use const_default::ConstDefault;
use rustls::ConnectionTrafficSecrets;
use rustls::crypto::cipher::{self, AeadKey, Iv};

use super::common::{Extractor, Tls12AeadAlgorithmWithExplicitNonce};

pub struct Aes128Extractor;
impl Extractor for Aes128Extractor {
    fn extract(
        key: AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm {
            key,
            iv: Iv::copy(iv),
        })
    }
}

pub struct Aes256Extractor;
impl Extractor for Aes256Extractor {
    fn extract(
        key: AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes256Gcm {
            key,
            iv: Iv::copy(iv),
        })
    }
}

pub const AES_128_GCM: &Tls12AeadAlgorithmWithExplicitNonce<
    crate::aead::aes::Aes128Gcm,
    Aes128Extractor,
> = &ConstDefault::DEFAULT;
pub const AES_256_GCM: &Tls12AeadAlgorithmWithExplicitNonce<
    crate::aead::aes::Aes256Gcm,
    Aes256Extractor,
> = &ConstDefault::DEFAULT;
