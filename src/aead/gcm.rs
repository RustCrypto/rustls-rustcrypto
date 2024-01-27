use alloc::{boxed::Box, vec::Vec};

use aead::AeadInPlace;
use crypto_common::{KeyInit, KeySizeUser};
use paste::paste;
use rustls::{
    crypto::cipher::{
        self, AeadKey, BorrowedPlainMessage, MessageDecrypter, MessageEncrypter, OpaqueMessage,
        PlainMessage, Tls13AeadAlgorithm,
    },
    ConnectionTrafficSecrets, ContentType, ProtocolVersion,
};
#[cfg(feature = "tls12")]
use {
    aead::AeadCore, crypto_common::typenum::Unsigned, rustls::crypto::cipher::Iv,
    rustls::crypto::cipher::KeyBlockShape, rustls::crypto::cipher::Tls12AeadAlgorithm,
};

macro_rules! impl_gcm_tls13 {
    ($name: ident, $aead: ty, $overhead: expr) => {
        paste! {
            pub struct [<Tls13 $name>];

            impl Tls13AeadAlgorithm for [<Tls13 $name>] {
                fn encrypter(&self, key: AeadKey, iv: cipher::Iv) -> Box<dyn MessageEncrypter> {
                    Box::new([<Tls13Cipher $name>](
                        $aead::new_from_slice(key.as_ref()).unwrap(),
                        iv,
                    ))
                }

                fn decrypter(&self, key: AeadKey, iv: cipher::Iv) -> Box<dyn MessageDecrypter> {
                    Box::new([<Tls13Cipher $name>](
                        $aead::new_from_slice(key.as_ref()).unwrap(),
                        iv,
                    ))
                }

                fn key_len(&self) -> usize {
                    $aead::key_size()
                }
                fn extract_keys(
                    &self,
                    key: AeadKey,
                    iv: cipher::Iv,
                ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
                    Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv })
                }
            }

            struct [<Tls13Cipher $name>]($aead, cipher::Iv);

            impl MessageEncrypter for [<Tls13Cipher $name>] {
                fn encrypt(&mut self, m: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, rustls::Error> {
                    let total_len = self.encrypted_payload_len(m.payload.len());

                    // construct a TLSInnerPlaintext
                    let mut payload = Vec::with_capacity(total_len);
                    payload.extend_from_slice(m.payload);
                    payload.push(m.typ.get_u8());

                    let nonce = cipher::Nonce::new(&self.1, seq).0;
                    let aad = cipher::make_tls13_aad(total_len);

                    self.0
                        .encrypt_in_place(&nonce.into(), &aad, &mut payload)
                        .map_err(|_| rustls::Error::EncryptError)
                        .and_then(|()| {
                            Ok(OpaqueMessage::new(
                                ContentType::ApplicationData,
                                ProtocolVersion::TLSv1_2,
                                payload,
                            ))
                        })
                }

                fn encrypted_payload_len(&self, payload_len: usize) -> usize {
                    payload_len + 1 + $overhead
                }
            }

            impl MessageDecrypter for [<Tls13Cipher $name>] {
                fn decrypt(&mut self, mut m: OpaqueMessage, seq: u64) -> Result<PlainMessage, rustls::Error> {
                    let payload = m.payload_mut();
                    let nonce = cipher::Nonce::new(&self.1, seq).0;
                    let aad = cipher::make_tls13_aad(payload.len());

                    self.0
                        .decrypt_in_place(&nonce.into(), &aad, payload)
                        .map_err(|_| rustls::Error::DecryptError)?;

                    m.into_tls13_unpadded_message()
                }
            }

        }
    };
}

#[cfg(feature = "tls12")]
macro_rules! impl_gcm_tls12 {
    ($name: ident, $aead: ty, $overhead: expr) => {
        paste! {
            #[cfg(feature = "tls12")]
            pub struct [<Tls12 $name>];

            #[cfg(feature = "tls12")]
            impl Tls12AeadAlgorithm for [<Tls12 $name>] {
                fn encrypter(&self, key: AeadKey, write_iv: &[u8], explicit: &[u8]) -> Box<dyn MessageEncrypter> {
                    Box::new([<Tls12Cipher $name Encrypter>](
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
                    Box::new([<Tls12Cipher $name Decrypter>](
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
                    Ok(ConnectionTrafficSecrets::Aes128Gcm {
                        key,
                        iv: Iv::new(iv[..].try_into().unwrap()),
                    })
                }
            }

            #[cfg(feature = "tls12")]
            struct [<Tls12Cipher $name Encrypter>]($aead, [u8; 12]);

            #[cfg(feature = "tls12")]
            impl MessageEncrypter for [<Tls12Cipher $name Encrypter>] {
                fn encrypt(&mut self, m: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, rustls::Error> {
                    let nonce = cipher::Nonce::new(&self.1.into(), seq).0;
                    let aad = cipher::make_tls12_aad(seq, m.typ, m.version, m.payload.len());

                    let total_len = self.encrypted_payload_len(m.payload.len());
                    let explicit_nonce_len = 8;
                    let mut payload = Vec::with_capacity(explicit_nonce_len + total_len);
                    payload.extend_from_slice(&nonce.as_ref()[4..]); // explicit
                    payload.extend_from_slice(m.payload);

                    self.0
                        .encrypt_in_place_detached(&nonce.into(), &aad, &mut payload[explicit_nonce_len..])
                        .map(|tag| payload.extend(tag.as_ref() as &[u8]))
                        .map_err(|_| rustls::Error::EncryptError)
                        .and_then(|_| Ok(OpaqueMessage::new(m.typ, m.version, payload)))
                }
                fn encrypted_payload_len(&self, payload_len: usize) -> usize {
                    payload_len + <$aead as AeadCore>::TagSize::USIZE
                }
            }

            #[cfg(feature = "tls12")]
            struct [<Tls12Cipher $name Decrypter>]($aead, [u8; 4]);

            #[cfg(feature = "tls12")]
            impl MessageDecrypter for [<Tls12Cipher $name Decrypter>] {
                fn decrypt(&mut self, mut m: OpaqueMessage, seq: u64) -> Result<PlainMessage, rustls::Error> {
                    type TagSize = <$aead as AeadCore>::TagSize;

                    let payload = m.payload();

                    if payload.len() < $overhead {
                        return Err(rustls::Error::DecryptError);
                    }

                    let explicit_nonce_len = 8;

                    let nonce: aead::Nonce<$aead> = {
                        let mut nonce = [0u8; 12];
                        nonce[..4].copy_from_slice(&self.1); // dec_iv
                        nonce[4..].copy_from_slice(&payload[..explicit_nonce_len]);
                        nonce.into()
                    };

                    let aad = cipher::make_tls12_aad(seq, m.typ, m.version, payload.len() - $overhead);

                    let payload = m.payload_mut();
                    let tag_pos = {
                        let payload = &mut payload[explicit_nonce_len..];
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
                    payload.rotate_left(8);
                    payload.truncate(tag_pos);
                    Ok(m.into_plain_message())
                }
            }
        }
    };
}

impl_gcm_tls13! {Aes128Gcm, aes_gcm::Aes128Gcm, 16}
impl_gcm_tls13! {Aes256Gcm, aes_gcm::Aes256Gcm, 16}

#[cfg(feature = "tls12")]
impl_gcm_tls12! {Aes128Gcm, aes_gcm::Aes128Gcm, 24}

#[cfg(feature = "tls12")]
impl_gcm_tls12! {Aes256Gcm, aes_gcm::Aes256Gcm, 24}
