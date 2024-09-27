#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use crate::aead::{DecryptBufferAdapter, EncryptBufferAdapter};
use chacha20poly1305::{AeadInPlace, KeyInit};
use rustls::crypto::cipher::{
    self, make_tls12_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter,
    MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    UnsupportedOperationError,
};
use rustls::crypto::cipher::{KeyBlockShape, Tls12AeadAlgorithm, NONCE_LEN};
use rustls::ConnectionTrafficSecrets;

use super::{ChaCha20Poly1305, CHACHAPOLY1305_OVERHEAD};

struct CipherAdapter(chacha20poly1305::ChaCha20Poly1305, Iv);

impl Tls12AeadAlgorithm for ChaCha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        Box::new(CipherAdapter(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("key should be valid"),
            Iv::copy(iv),
        ))
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(CipherAdapter(
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
        // This should always be true because KeyBlockShape and the Iv nonce len are in
        // agreement.
        debug_assert_eq!(NONCE_LEN, iv.len());
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
            key,
            iv: Iv::new(iv[..].try_into().expect("conversion should succeed")),
        })
    }
}

impl MessageEncrypter for CipherAdapter {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        payload.extend_from_chunks(&m.payload);

        let nonce: chacha20poly1305::Nonce = cipher::Nonce::new(&self.1, seq).0.into();
        let aad = make_tls12_aad(seq, m.typ, m.version, m.payload.len());

        self.0
            .encrypt_in_place(&nonce, &aad, &mut EncryptBufferAdapter(&mut payload))
            .map_err(|_| rustls::Error::EncryptError)
            .map(|_| OutboundOpaqueMessage::new(m.typ, m.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + CHACHAPOLY1305_OVERHEAD
    }
}

impl MessageDecrypter for CipherAdapter {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &m.payload;
        let nonce: chacha20poly1305::Nonce = cipher::Nonce::new(&self.1, seq).0.into();
        let aad = make_tls12_aad(
            seq,
            m.typ,
            m.version,
            payload.len() - CHACHAPOLY1305_OVERHEAD,
        );

        let payload = &mut m.payload;
        self.0
            .decrypt_in_place(&nonce, &aad, &mut DecryptBufferAdapter(payload))
            .map_err(|_| rustls::Error::DecryptError)?;

        Ok(m.into_plain_message())
    }
}
