use rustls::{
    ConnectionTrafficSecrets,
    crypto::cipher::{self, AeadKey, Iv},
};

use crate::tls13::aead::common::{Extractor, Tls13AeadAlgorithmCommon};

macro_rules! impl_gcm_aead {
    ($const_name:ident, $extractor_name:ident, $variant:ident, $type:ty) => {
        pub struct $extractor_name;

        impl Extractor for $extractor_name {
            fn extract(
                key: AeadKey,
                iv: Iv,
            ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
                Ok(ConnectionTrafficSecrets::$variant { key, iv })
            }
        }

        pub const $const_name: &Tls13AeadAlgorithmCommon<$type, $extractor_name> =
            &Tls13AeadAlgorithmCommon::DEFAULT;
    };
}

impl_gcm_aead!(
    AES_128_GCM,
    Aes128GcmExtractor,
    Aes128Gcm,
    crate::aead::aes::Aes128Gcm
);
impl_gcm_aead!(
    AES_256_GCM,
    Aes256GcmExtractor,
    Aes256Gcm,
    crate::aead::aes::Aes256Gcm
);
