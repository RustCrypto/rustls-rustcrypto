use rustls::ConnectionTrafficSecrets;
use rustls::crypto::cipher::{self, AeadKey, Iv};

use super::explicit_nonce::{Extractor, Tls12AeadAlgorithmWithExplicitNonce};

macro_rules! tls12_gcm_aead {
    ($const_name:ident, $extractor_name:ident, $variant:ident, $type:ty) => {
        pub struct $extractor_name;
        impl Extractor for $extractor_name {
            fn extract(
                key: AeadKey,
                iv: &[u8],
                _explicit: &[u8],
            ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
                Ok(ConnectionTrafficSecrets::$variant {
                    key,
                    iv: Iv::copy(iv),
                })
            }
        }

        pub const $const_name: &Tls12AeadAlgorithmWithExplicitNonce<$type, $extractor_name> =
            &Tls12AeadAlgorithmWithExplicitNonce::DEFAULT;
    };
}

tls12_gcm_aead!(
    AES_128_GCM,
    Aes128GcmExtractor,
    Aes128Gcm,
    crate::aead::aes::Aes128Gcm
);
tls12_gcm_aead!(
    AES_256_GCM,
    Aes256GcmExtractor,
    Aes256Gcm,
    crate::aead::aes::Aes256Gcm
);
