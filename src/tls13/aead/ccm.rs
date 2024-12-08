#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use crate::aead::{Aes128Ccm, Aes128Ccm8, DecryptBufferAdapter, EncryptBufferAdapter};
use aead::AeadInPlace;
use crypto_common::{KeyInit, KeySizeUser};
use paste::paste;
use rustls::crypto::cipher::{
    self, make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, MessageDecrypter,
    MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};

macro_rules! impl_ccm {
($name: ident, $aead: ty, $overhead: expr) => {
    paste! {
        impl Tls13AeadAlgorithm for $name {
            fn encrypter(&self, key: AeadKey, iv: cipher::Iv) -> Box<dyn MessageEncrypter> {
                Box::new([<CipherAdapter $name>](
                    $aead::new_from_slice(key.as_ref()).unwrap(),
                    iv,
                ))
            }

            fn decrypter(&self, key: AeadKey, iv: cipher::Iv) -> Box<dyn MessageDecrypter> {
                Box::new([<CipherAdapter $name>](
                    $aead::new_from_slice(key.as_ref()).unwrap(),
                    iv,
                ))
            }

            fn key_len(&self) -> usize {
                $aead::key_size()
            }
            fn extract_keys(
                &self,
                _: AeadKey,
                _: cipher::Iv,
            ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
                Err(UnsupportedOperationError)
            }
        }

        pub struct [<CipherAdapter $name>]($aead, cipher::Iv);

        impl MessageEncrypter for [<CipherAdapter $name>] {
            fn encrypt(&mut self, m: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, rustls::Error> {
                let total_len = self.encrypted_payload_len(m.payload.len());
                let mut payload = PrefixedPayload::with_capacity(total_len);

                let nonce = cipher::Nonce::new(&self.1, seq).0;
                let aad = make_tls13_aad(total_len);
                payload.extend_from_chunks(&m.payload);
                payload.extend_from_slice(&m.typ.to_array());

                self.0
                    .encrypt_in_place(&nonce.into(), &aad, &mut EncryptBufferAdapter(&mut payload))
                    .map_err(|_| rustls::Error::EncryptError)
                    .map(|_| OutboundOpaqueMessage::new(
                        ContentType::ApplicationData,
                        ProtocolVersion::TLSv1_2,
                        payload,
                    ))
            }

            fn encrypted_payload_len(&self, payload_len: usize) -> usize {
                payload_len + 1 + $overhead
            }
        }

        impl MessageDecrypter for [<CipherAdapter $name>] {
            fn decrypt<'a>(&mut self, mut m: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, rustls::Error> {
                let payload = &mut m.payload;
                let nonce = cipher::Nonce::new(&self.1, seq).0;
                let aad = make_tls13_aad(payload.len());

                self.0
                    .decrypt_in_place(&nonce.into(), &aad, &mut DecryptBufferAdapter(payload))
                    .map_err(|_| rustls::Error::DecryptError)?;

                m.into_tls13_unpadded_message()
            }
        }

    }
};
}

impl_ccm! {Aes128Ccm, crate::aead::aes::Aes128Ccm, 16}
impl_ccm! {Aes128Ccm8, crate::aead::aes::Aes128Ccm8, 8}
