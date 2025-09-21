use aead::AeadInOut;
#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use crate::aead::{DecryptBufferAdapter, EncryptBufferAdapter};

use ::chacha20poly1305::KeyInit;
use rustls::{
    ConnectionTrafficSecrets,
    crypto::cipher::{
        self, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, KeyBlockShape,
        MessageDecrypter, MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage,
        PrefixedPayload, Tls12AeadAlgorithm, UnsupportedOperationError, make_tls12_aad,
    },
};

pub const CHACHAPOLY1305_OVERHEAD: usize = 16;
pub struct ChaCha20Poly1305;

pub struct Tls12AeadAlgorithmChacha20Poly1305Adapter(chacha20poly1305::ChaCha20Poly1305, Iv);

impl Tls12AeadAlgorithm for ChaCha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        Box::new(Tls12AeadAlgorithmChacha20Poly1305Adapter(
            ::chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("key should be valid"),
            Iv::copy(iv),
        ))
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(Tls12AeadAlgorithmChacha20Poly1305Adapter(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("key should be valid"),
            Iv::copy(iv),
        ))
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32,
            fixed_iv_len: 12,
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
            key,
            iv: Iv::copy(iv),
        })
    }
}

impl MessageEncrypter for Tls12AeadAlgorithmChacha20Poly1305Adapter {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let mut payload =
            PrefixedPayload::with_capacity(self.encrypted_payload_len(m.payload.len()));

        payload.extend_from_chunks(&m.payload);

        self.0
            .encrypt_in_place(
                &cipher::Nonce::new(&self.1, seq).0.into(),
                &make_tls12_aad(seq, m.typ, m.version, m.payload.len()),
                &mut EncryptBufferAdapter::PrefixedPayload(&mut payload),
            )
            .map(|_| OutboundOpaqueMessage::new(m.typ, m.version, payload))
            .map_err(|_| rustls::Error::EncryptError)
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + CHACHAPOLY1305_OVERHEAD
    }
}

impl MessageDecrypter for Tls12AeadAlgorithmChacha20Poly1305Adapter {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        self.0
            .decrypt_in_place(
                &cipher::Nonce::new(&self.1, seq).0.into(),
                &make_tls12_aad(
                    seq,
                    m.typ,
                    m.version,
                    m.payload.len() - CHACHAPOLY1305_OVERHEAD,
                ),
                &mut DecryptBufferAdapter::BorrowedPayload(&mut m.payload),
            )
            .map_err(|_| rustls::Error::DecryptError)?;

        Ok(m.into_plain_message())
    }
}
