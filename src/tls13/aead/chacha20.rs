use const_default::ConstDefault;
use rustls::ConnectionTrafficSecrets;
use rustls::crypto::cipher::{AeadKey, Iv, UnsupportedOperationError};

use crate::tls13::aead::common::{Extractor, Tls13AeadAlgorithmCommon};

pub struct ChaCha20Poly1305Extractor;

impl Extractor for ChaCha20Poly1305Extractor {
    fn extract(
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

pub const CHACHA20_POLY1305: &Tls13AeadAlgorithmCommon<
    chacha20poly1305::ChaCha20Poly1305,
    ChaCha20Poly1305Extractor,
> = &ConstDefault::DEFAULT;
