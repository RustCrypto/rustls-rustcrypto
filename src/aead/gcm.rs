use alloc::{boxed::Box, vec::Vec};
use core::marker::PhantomData;

use aead::AeadInPlace;
use crypto_common::{KeyInit, KeySizeUser};
use rustls::{
    crypto::cipher::{
        self, AeadKey, BorrowedPlainMessage, MessageDecrypter, MessageEncrypter, OpaqueMessage,
        PlainMessage, Tls13AeadAlgorithm,
    },
    ConnectionTrafficSecrets, ContentType, ProtocolVersion,
};
#[cfg(feature = "tls12")]
use {
    aead::AeadCore, aes_gcm::AesGcm, generic_array::ArrayLength, rustls::crypto::cipher::Iv,
    rustls::crypto::cipher::KeyBlockShape, rustls::crypto::cipher::Tls12AeadAlgorithm,
};

type NonceType = [u8; 12];

trait AeadMetaTls13 {
    const OVERHEAD: usize;
}

#[cfg(feature = "tls12")]
trait AeadMetaTls12 {
    const OVERHEAD: usize;

    fn key_block_shape() -> KeyBlockShape;
}

pub struct Gcm<T>(PhantomData<T>);

impl<T> Gcm<T> {
    pub const DEFAULT: Self = Self(PhantomData);
}

impl Tls13AeadAlgorithm for Gcm<aes_gcm::Aes128Gcm> {
    fn encrypter(&self, key: AeadKey, iv: cipher::Iv) -> Box<dyn MessageEncrypter> {
        Box::new(AeadCipherTls13(
            aes_gcm::Aes128Gcm::new_from_slice(key.as_ref()).unwrap(),
            iv,
        ))
    }

    fn decrypter(&self, key: AeadKey, iv: cipher::Iv) -> Box<dyn MessageDecrypter> {
        Box::new(AeadCipherTls13(
            aes_gcm::Aes128Gcm::new_from_slice(key.as_ref()).unwrap(),
            iv,
        ))
    }

    fn key_len(&self) -> usize {
        aes_gcm::Aes128Gcm::key_size()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: cipher::Iv,
    ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
    }
}

impl Tls13AeadAlgorithm for Gcm<aes_gcm::Aes256Gcm> {
    fn encrypter(&self, key: AeadKey, iv: cipher::Iv) -> Box<dyn MessageEncrypter> {
        Box::new(AeadCipherTls13(
            aes_gcm::Aes256Gcm::new_from_slice(key.as_ref()).unwrap(),
            iv,
        ))
    }

    fn decrypter(&self, key: AeadKey, iv: cipher::Iv) -> Box<dyn MessageDecrypter> {
        Box::new(AeadCipherTls13(
            aes_gcm::Aes256Gcm::new_from_slice(key.as_ref()).unwrap(),
            iv,
        ))
    }

    fn key_len(&self) -> usize {
        aes_gcm::Aes256Gcm::key_size()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: cipher::Iv,
    ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv })
    }
}

#[cfg(feature = "tls12")]
impl Tls12AeadAlgorithm for Gcm<aes_gcm::Aes128Gcm> {
    fn encrypter(
        &self,
        key: AeadKey,
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        Box::new(AeadCipherTls12(
            aes_gcm::Aes128Gcm::new_from_slice(key.as_ref()).unwrap(),
            {
                let mut iv = NonceType::default();
                iv[..4].copy_from_slice(write_iv);
                iv[4..].copy_from_slice(explicit);
                iv
            },
        ))
    }

    fn decrypter(&self, dec_key: AeadKey, dec_iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(AeadCipherTls12(
            aes_gcm::Aes128Gcm::new_from_slice(dec_key.as_ref()).unwrap(),
            {
                let mut dec_salt = NonceType::default();
                dec_salt[..4].copy_from_slice(dec_iv);
                dec_salt
            },
        ))
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        AeadCipherTls12::<aes_gcm::Aes128Gcm>::key_block_shape()
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
impl Tls12AeadAlgorithm for Gcm<aes_gcm::Aes256Gcm> {
    fn encrypter(
        &self,
        key: AeadKey,
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        Box::new(AeadCipherTls12(
            aes_gcm::Aes256Gcm::new_from_slice(key.as_ref()).unwrap(),
            {
                let mut iv = NonceType::default();
                iv[..4].copy_from_slice(write_iv);
                iv[4..].copy_from_slice(explicit);
                iv
            },
        ))
    }

    fn decrypter(&self, dec_key: AeadKey, dec_iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(AeadCipherTls12(
            aes_gcm::Aes256Gcm::new_from_slice(dec_key.as_ref()).unwrap(),
            {
                let mut dec_salt = NonceType::default();
                dec_salt[..4].copy_from_slice(dec_iv);
                dec_salt
            },
        ))
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        AeadCipherTls12::<aes_gcm::Aes256Gcm>::key_block_shape()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes256Gcm {
            key,
            iv: Iv::new(iv[..].try_into().unwrap()),
        })
    }
}

struct AeadCipherTls13<T>(T, cipher::Iv);

impl<T> MessageDecrypter for AeadCipherTls13<T>
where
    T: Send + Sync + AeadInPlace,
    aead::Nonce<T>: From<NonceType>,
{
    fn decrypt(&self, mut m: OpaqueMessage, seq: u64) -> Result<PlainMessage, rustls::Error> {
        let payload = m.payload_mut();
        let nonce = cipher::Nonce::new(&self.1, seq).0;
        let aad = cipher::make_tls13_aad(payload.len());

        self.0
            .decrypt_in_place(&nonce.into(), &aad, payload)
            .map_err(|_| rustls::Error::DecryptError)?;

        m.into_tls13_unpadded_message()
    }
}

impl<T> MessageEncrypter for AeadCipherTls13<T>
where
    T: Send + Sync + AeadInPlace,
    aead::Nonce<T>: From<NonceType>,
    AeadCipherTls13<T>: AeadMetaTls13,
{
    fn encrypt(&self, m: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, rustls::Error> {
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
            .and_then(|_| {
                Ok(OpaqueMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    payload,
                ))
            })
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + <Self as AeadMetaTls13>::OVERHEAD
    }
}

#[cfg(feature = "tls12")]
struct AeadCipherTls12<T>(T, NonceType);

#[cfg(feature = "tls12")]
impl<Aes, NonceSize, TagSize> MessageEncrypter for AeadCipherTls12<AesGcm<Aes, NonceSize, TagSize>>
where
    Aes: Send + Sync + 'static,
    NonceSize: Send + Sync + ArrayLength<u8>,
    AesGcm<Aes, NonceSize, TagSize>: AeadInPlace + KeyInit,
    AeadCipherTls12<AesGcm<Aes, NonceSize, TagSize>>: AeadMetaTls12,
    aead::Nonce<AesGcm<Aes, NonceSize, TagSize>>: From<NonceType>,
    TagSize: Send + Sync + aes_gcm::TagSize,
{
    fn encrypt(&self, m: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, rustls::Error> {
        let nonce = cipher::Nonce::new(&self.1.into(), seq).0;
        let aad = cipher::make_tls12_aad(seq, m.typ, m.version, m.payload.len());

        let total_len = self.encrypted_payload_len(m.payload.len());
        let explicit_nonce_len = Self::key_block_shape().explicit_nonce_len;
        let mut payload = Vec::with_capacity(explicit_nonce_len + total_len);
        payload.extend_from_slice(&nonce.as_ref()[4..]);
        payload.extend_from_slice(m.payload);

        self.0
            .encrypt_in_place_detached(&nonce.into(), &aad, &mut payload[explicit_nonce_len..])
            .map(|tag| payload.extend(tag.as_ref()))
            .map_err(|_| rustls::Error::EncryptError)
            .and_then(|_| Ok(OpaqueMessage::new(m.typ, m.version, payload)))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + TagSize::USIZE
    }
}

#[cfg(feature = "tls12")]
impl<Aes, NonceSize, TagSize> MessageDecrypter for AeadCipherTls12<AesGcm<Aes, NonceSize, TagSize>>
where
    Aes: Send + Sync + 'static,
    NonceSize: Send + Sync + ArrayLength<u8>,
    AesGcm<Aes, NonceSize, TagSize>: AeadInPlace + KeyInit,
    AeadCipherTls12<AesGcm<Aes, NonceSize, TagSize>>: AeadMetaTls12,
    aead::Nonce<AesGcm<Aes, NonceSize, TagSize>>: From<NonceType>,
    TagSize: Send + Sync + aes_gcm::TagSize,
{
    fn decrypt(&self, mut m: OpaqueMessage, seq: u64) -> Result<PlainMessage, rustls::Error> {
        let payload = m.payload();

        if payload.len() < <Self as AeadMetaTls12>::OVERHEAD {
            return Err(rustls::Error::DecryptError);
        }

        let explicit_nonce_len = Self::key_block_shape().explicit_nonce_len;

        let nonce: aead::Nonce<AesGcm<Aes, NonceSize, TagSize>> = {
            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&self.1[..4]);
            nonce[4..].copy_from_slice(&payload[..explicit_nonce_len]);
            nonce.into()
        };

        let aad = cipher::make_tls12_aad(
            seq,
            m.typ,
            m.version,
            payload.len() - <Self as AeadMetaTls12>::OVERHEAD,
        );

        let payload = m.payload_mut();
        let tag_pos = {
            let payload = &mut payload[explicit_nonce_len..];
            let tag_pos = payload.len() - TagSize::to_usize();
            let (msg, tag) = payload.split_at_mut(tag_pos);

            let tag =
                aes_gcm::Tag::<<AesGcm<Aes, NonceSize, TagSize> as AeadCore>::TagSize>::from_slice(
                    tag,
                );
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

impl AeadMetaTls13 for AeadCipherTls13<aes_gcm::Aes128Gcm> {
    const OVERHEAD: usize = 16;
}

impl AeadMetaTls13 for AeadCipherTls13<aes_gcm::Aes256Gcm> {
    const OVERHEAD: usize = 16;
}

#[cfg(feature = "tls12")]
impl AeadMetaTls12 for AeadCipherTls12<aes_gcm::Aes128Gcm> {
    const OVERHEAD: usize = 24;

    fn key_block_shape() -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len:        aes_gcm::Aes128Gcm::key_size(),
            fixed_iv_len:       4,
            explicit_nonce_len: 8,
        }
    }
}

#[cfg(feature = "tls12")]
impl AeadMetaTls12 for AeadCipherTls12<aes_gcm::Aes256Gcm> {
    const OVERHEAD: usize = 24;

    fn key_block_shape() -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len:        aes_gcm::Aes256Gcm::key_size(),
            fixed_iv_len:       4,
            explicit_nonce_len: 8,
        }
    }
}
