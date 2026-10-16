#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use super::{DecryptBufferAdapter, EncryptBufferAdapter};

use aead::AeadInOut;
use crypto_common::{KeyInit, KeySizeUser};
use paste::paste;
use rustls::crypto::cipher::{
    self, AeadKey, InboundOpaqueMessage, InboundPlainMessage, MessageDecrypter, MessageEncrypter,
    OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};

#[cfg(feature = "tls12")]
use {
    aead::AeadCore,
    crypto_common::typenum::Unsigned,
    rustls::crypto::cipher::{Iv, KeyBlockShape, Tls12AeadAlgorithm},
};

#[cfg(feature = "tls12")]
const TLS12_GCM_EXPLICIT_NONCE_LEN: usize = 8;

#[cfg(feature = "tls12")]
const TLS12_GCM_OVERHEAD: usize = TLS12_GCM_EXPLICIT_NONCE_LEN + 16;

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
                    Ok(ConnectionTrafficSecrets::$name { key, iv })
                }
            }

            struct [<Tls13Cipher $name>]($aead, cipher::Iv);

            impl MessageEncrypter for [<Tls13Cipher $name>] {
                fn encrypt(&mut self, m: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, rustls::Error> {
                    let total_len = self.encrypted_payload_len(m.payload.len());
                    let mut payload = PrefixedPayload::with_capacity(total_len);

                    let nonce = cipher::Nonce::new(&self.1, seq).0;
                    let aad = cipher::make_tls13_aad(total_len);
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

            impl MessageDecrypter for [<Tls13Cipher $name>] {
                fn decrypt<'a>(&mut self, mut m: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, rustls::Error> {
                    let payload = &mut m.payload;
                    let nonce = cipher::Nonce::new(&self.1, seq).0;
                    let aad = cipher::make_tls13_aad(payload.len());

                    self.0
                        .decrypt_in_place(&nonce.into(), &aad, &mut DecryptBufferAdapter(payload))
                        .map_err(|_| rustls::Error::DecryptError)?;

                    m.into_tls13_unpadded_message()
                }
            }

        }
    };
}

#[cfg(feature = "tls12")]
macro_rules! impl_gcm_tls12 {
    ($name: ident, $aead: ty, $nonce: expr, $overhead: expr) => {
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
                    explicit: &[u8],
                ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
                    if iv.len() != 4 || explicit.len() != 8 {
                        return Err(cipher::UnsupportedOperationError);
                    }
                    let mut full_iv = [0u8; 12];
                    full_iv[..4].copy_from_slice(iv);
                    full_iv[4..].copy_from_slice(explicit);
                    Ok(ConnectionTrafficSecrets::$name {
                        key,
                        iv: Iv::new(full_iv),
                    })
                }
            }

            #[cfg(feature = "tls12")]
            struct [<Tls12Cipher $name Encrypter>]($aead, [u8; 12]);

            #[cfg(feature = "tls12")]
            impl MessageEncrypter for [<Tls12Cipher $name Encrypter>] {
                fn encrypt(&mut self, m: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, rustls::Error> {
                    let total_len = self.encrypted_payload_len(m.payload.len());
                    let mut payload = PrefixedPayload::with_capacity(total_len);

                    let nonce = cipher::Nonce::new(&self.1.into(), seq).0;
                    let aad = cipher::make_tls12_aad(seq, m.typ, m.version, m.payload.len());
                    payload.extend_from_slice(&nonce.as_ref()[4..]); // explicit
                    payload.extend_from_chunks(&m.payload);

                    self.0
                        .encrypt_inout_detached(&nonce.into(), &aad, (&mut payload.as_mut()[$nonce..]).into())
                        .map(|tag| payload.extend(tag.as_ref() as &[u8]))
                        .map_err(|_| rustls::Error::EncryptError)
                        .map(|_| OutboundOpaqueMessage::new(m.typ, m.version, payload))
                }
                fn encrypted_payload_len(&self, payload_len: usize) -> usize {
                    payload_len + $nonce + <$aead as AeadCore>::TagSize::USIZE
                }
            }

            #[cfg(feature = "tls12")]
            struct [<Tls12Cipher $name Decrypter>]($aead, [u8; 4]);

            #[cfg(feature = "tls12")]
            impl MessageDecrypter for [<Tls12Cipher $name Decrypter>] {
                fn decrypt<'a>(&mut self, mut m: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, rustls::Error> {
                    type TagSize = <$aead as AeadCore>::TagSize;

                    let payload = &m.payload;

                    if payload.len() < $overhead {
                        return Err(rustls::Error::DecryptError);
                    }

                    let nonce: aead::Nonce<$aead> = {
                        let mut nonce = [0u8; 12];
                        nonce[..4].copy_from_slice(&self.1); // dec_iv
                        nonce[4..].copy_from_slice(&payload[..$nonce]);
                        nonce.into()
                    };

                    let aad = cipher::make_tls12_aad(seq, m.typ, m.version, payload.len() - $overhead);

                    let payload = &mut m.payload;
                    let tag_pos = {
                        let payload = &mut payload[$nonce..];
                        let tag_pos = payload.len() - TagSize::to_usize();
                        let (msg, tag) = payload.split_at_mut(tag_pos);

                        let tag = aes_gcm::Tag::<TagSize>::try_from(&*tag)
                            .map_err(|_| rustls::Error::DecryptError)?;
                        self.0
                            .decrypt_inout_detached(&nonce, &aad, msg.into(), &tag)
                            .map_err(|_| rustls::Error::DecryptError)?;
                        tag_pos
                    };

                    // We defer the truncation to here, because we may inadvertently shifted the
                    // original data if the decryption failed. Another way to avoid this is
                    // to clone the payload slice starting after the explicit nonce,
                    // but this will cause an additional cloning and copying
                    payload.rotate_left($nonce);
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
impl_gcm_tls12! {Aes128Gcm, aes_gcm::Aes128Gcm, TLS12_GCM_EXPLICIT_NONCE_LEN, TLS12_GCM_OVERHEAD}

#[cfg(feature = "tls12")]
impl_gcm_tls12! {Aes256Gcm, aes_gcm::Aes256Gcm, TLS12_GCM_EXPLICIT_NONCE_LEN, TLS12_GCM_OVERHEAD}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::{
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    };
    use rustls::{CipherSuite, ConnectionTrafficSecrets, SupportedCipherSuite};

    const KEY_256: [u8; 32] = [0x42; 32];

    fn tls13_alg(suite: &'static SupportedCipherSuite) -> &'static dyn Tls13AeadAlgorithm {
        match suite {
            SupportedCipherSuite::Tls13(inner) => inner.aead_alg,
            SupportedCipherSuite::Tls12(_) => unreachable!(),
        }
    }

    fn tls12_alg(suite: &'static SupportedCipherSuite) -> &'static dyn Tls12AeadAlgorithm {
        match suite {
            SupportedCipherSuite::Tls12(inner) => inner.aead_alg,
            SupportedCipherSuite::Tls13(_) => unreachable!(),
        }
    }

    fn assert_tls13_secret(suite: &'static SupportedCipherSuite, suite_id: CipherSuite) {
        let iv = Iv::new([0u8; 12]);
        let secret = tls13_alg(suite)
            .extract_keys(AeadKey::from(KEY_256), iv)
            .unwrap();
        match (suite_id, secret) {
            (
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                ConnectionTrafficSecrets::Aes128Gcm { iv, .. },
            ) => assert_eq!(iv.as_ref(), &[0u8; 12]),
            (
                CipherSuite::TLS13_AES_256_GCM_SHA384,
                ConnectionTrafficSecrets::Aes256Gcm { iv, .. },
            ) => assert_eq!(iv.as_ref(), &[0u8; 12]),
            (suite_id, _) => panic!("{suite_id:?} yielded the wrong secret shape"),
        }
    }

    #[test]
    fn tls13_extract_keys_reports_the_negotiated_algorithm() {
        assert_tls13_secret(&TLS13_AES_128_GCM_SHA256, CipherSuite::TLS13_AES_128_GCM_SHA256);
        assert_tls13_secret(&TLS13_AES_256_GCM_SHA384, CipherSuite::TLS13_AES_256_GCM_SHA384);
    }

    #[cfg(feature = "tls12")]
    fn assert_tls12_secret(
        suite: &'static SupportedCipherSuite,
        suite_id: CipherSuite,
        fixed_iv: [u8; 4],
        explicit: [u8; 8],
    ) {
        let secret = tls12_alg(suite)
            .extract_keys(AeadKey::from(KEY_256), &fixed_iv, &explicit)
            .unwrap();
        let mut expected_iv = [0u8; 12];
        expected_iv[..4].copy_from_slice(&fixed_iv);
        expected_iv[4..].copy_from_slice(&explicit);
        match (suite_id, secret) {
            (
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                ConnectionTrafficSecrets::Aes128Gcm { iv, .. },
            ) => assert_eq!(iv.as_ref(), &expected_iv),
            (
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                ConnectionTrafficSecrets::Aes256Gcm { iv, .. },
            ) => assert_eq!(iv.as_ref(), &expected_iv),
            (suite_id, _) => panic!("{suite_id:?} yielded the wrong secret shape"),
        }
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn tls12_extract_keys_assembles_the_iv_from_fixed_and_explicit_parts() {
        assert_tls12_secret(
            &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            [1, 2, 3, 4],
            [5, 6, 7, 8, 9, 10, 11, 12],
        );
        assert_tls12_secret(
            &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            [9, 8, 7, 6],
            [5, 4, 3, 2, 1, 0, 255, 128],
        );
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn tls12_extract_keys_rejects_malformed_key_block_slices() {
        let alg = tls12_alg(&TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        let explicit = [0u8; 8];

        assert!(alg
            .extract_keys(AeadKey::from(KEY_256), &[1, 2, 3], &explicit)
            .is_err());
        assert!(alg
            .extract_keys(AeadKey::from(KEY_256), &[1, 2, 3, 4, 5], &explicit)
            .is_err());

        let fixed_iv = [1u8, 2, 3, 4];
        assert!(alg
            .extract_keys(AeadKey::from(KEY_256), &fixed_iv, &[1, 2, 3, 4, 5, 6, 7])
            .is_err());
        assert!(alg
            .extract_keys(
                AeadKey::from(KEY_256),
                &fixed_iv,
                &[1, 2, 3, 4, 5, 6, 7, 8, 9]
            )
            .is_err());
    }
}
