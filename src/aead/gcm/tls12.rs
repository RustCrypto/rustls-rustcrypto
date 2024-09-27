#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use aead::{AeadCore, AeadInPlace};
use crypto_common::typenum::Unsigned;
use crypto_common::{KeyInit, KeySizeUser};
use paste::paste;
use rustls::crypto::cipher::{
    self, make_tls12_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, KeyBlockShape,
    MessageDecrypter, MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage,
    PrefixedPayload, Tls12AeadAlgorithm,
};
use rustls::ConnectionTrafficSecrets;

use super::{Aes128Gcm, Aes256Gcm};

const TLS12_GCM_EXPLICIT_NONCE_LEN: usize = 8;

const TLS12_GCM_OVERHEAD: usize = TLS12_GCM_EXPLICIT_NONCE_LEN + 16;

macro_rules! impl_gcm {
    ($name: ident, $aead: ty, $nonce_pos: expr, $overhead: expr) => {
        paste! {
            impl Tls12AeadAlgorithm for $name {
                fn encrypter(&self, key: AeadKey, write_iv: &[u8], explicit: &[u8]) -> Box<dyn MessageEncrypter> {
                    Box::new([<CipherAdapter $name Encrypter>](
                        $aead::new_from_slice(key.as_ref()).unwrap(),
                        {
                            let mut iv: [u8; 12] = [0; 12];
                            iv[..4].copy_from_slice(write_iv);
                            iv[4..].copy_from_slice(explicit);
                            iv
                        },
                    ))
                }

                fn decrypter(&self, dec_key: AeadKey, dec_iv: &[u8]) -> Box<dyn MessageDecrypter> {
                    Box::new([<CipherAdapter $name Decrypter>](
                        $aead::new_from_slice(dec_key.as_ref()).unwrap(),
                        dec_iv.try_into().unwrap(),
                    ))
                }

                fn key_block_shape(&self) -> KeyBlockShape {
                    KeyBlockShape {
                        enc_key_len:        $aead::key_size(),
                        fixed_iv_len:       4,
                        explicit_nonce_len: 8,
                    }
                }

                fn extract_keys(
                    &self,
                    key: AeadKey,
                    iv: &[u8],
                    _explicit: &[u8],
                ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
                    Ok(ConnectionTrafficSecrets::$name {
                        key,
                        iv: Iv::new(iv[..].try_into().unwrap()),
                    })
                }
            }

            struct [<CipherAdapter $name Encrypter>]($aead, [u8; 12]);

            impl MessageEncrypter for [<CipherAdapter $name Encrypter>] {
                fn encrypt(&mut self, m: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, rustls::Error> {
                    let total_len = self.encrypted_payload_len(m.payload.len());
                    let mut payload = PrefixedPayload::with_capacity(total_len);

                    let nonce = cipher::Nonce::new(&self.1.into(), seq).0;
                    let aad = make_tls12_aad(seq, m.typ, m.version, m.payload.len());
                    payload.extend_from_slice(&nonce.as_ref()[4..]); // explicit
                    payload.extend_from_chunks(&m.payload);

                    self.0
                        .encrypt_in_place_detached(&nonce.into(), &aad, &mut payload.as_mut()[$nonce_pos..])
                        .map(|tag| payload.extend(tag.as_ref() as &[u8]))
                        .map_err(|_| rustls::Error::EncryptError)
                        .map(|_| OutboundOpaqueMessage::new(m.typ, m.version, payload))
                }
                fn encrypted_payload_len(&self, payload_len: usize) -> usize {
                    payload_len + $nonce_pos + <$aead as AeadCore>::TagSize::USIZE
                }
            }

            struct [<CipherAdapter $name Decrypter>]($aead, [u8; 4]);

            impl MessageDecrypter for [<CipherAdapter $name Decrypter>] {
                fn decrypt<'a>(&mut self, mut m: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, rustls::Error> {
                    type TagSize = <$aead as AeadCore>::TagSize;

                    let payload = &m.payload;

                    if payload.len() < $overhead {
                        return Err(rustls::Error::DecryptError);
                    }

                    let nonce: aead::Nonce<$aead> = {
                        let mut nonce = [0u8; 12];
                        nonce[..4].copy_from_slice(&self.1); // dec_iv
                        nonce[4..].copy_from_slice(&payload[..$nonce_pos]);
                        nonce.into()
                    };

                    let aad = make_tls12_aad(seq, m.typ, m.version, payload.len() - $overhead);

                    let payload = &mut m.payload;
                    let tag_pos = {
                        let payload = &mut payload[$nonce_pos..];
                        let tag_pos = payload.len() - TagSize::to_usize();
                        let (msg, tag) = payload.split_at_mut(tag_pos);

                        let tag = aes_gcm::Tag::<TagSize>::from_slice(tag);
                        self.0
                            .decrypt_in_place_detached(&nonce, &aad, msg, tag)
                            .map_err(|_| rustls::Error::DecryptError)?;
                        tag_pos
                    };

                    // We defer the truncation to here, because we may inadvertently shifted the
                    // original data if the decryption failed. Another way to avoid this is
                    // to clone the payload slice starting after the explicit nonce,
                    // but this will cause an additional cloning and copying
                    payload.rotate_left($nonce_pos);
                    payload.truncate(tag_pos);
                    Ok(m.into_plain_message())
                }
            }
        }
    };
}

impl_gcm! {Aes128Gcm, aes_gcm::Aes128Gcm, TLS12_GCM_EXPLICIT_NONCE_LEN, TLS12_GCM_OVERHEAD}
impl_gcm! {Aes256Gcm, aes_gcm::Aes256Gcm, TLS12_GCM_EXPLICIT_NONCE_LEN, TLS12_GCM_OVERHEAD}
