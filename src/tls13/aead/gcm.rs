use rustls::{
    ConnectionTrafficSecrets,
    crypto::cipher::{self, AeadKey, Iv},
};

use crate::aead;
use crate::tls13::aead::common::{Extractor, Tls13AeadAlgorithmCommon};

pub struct Aes128GcmExtractor;

impl Extractor for Aes128GcmExtractor {
    fn extract(
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
    }
}

pub struct Aes256GcmExtractor;

impl Extractor for Aes256GcmExtractor {
    fn extract(
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv })
    }
}

pub const AES_128_GCM: &Tls13AeadAlgorithmCommon<aead::aes::Aes128Gcm, Aes128GcmExtractor> =
    &Tls13AeadAlgorithmCommon::DEFAULT;
pub const AES_256_GCM: &Tls13AeadAlgorithmCommon<aead::aes::Aes256Gcm, Aes256GcmExtractor> =
    &Tls13AeadAlgorithmCommon::DEFAULT;
