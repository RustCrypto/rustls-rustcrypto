use alloc::{boxed::Box, vec::Vec};
use core::marker::PhantomData;

use aead::{AeadCore, AeadInPlace};
use aes_gcm::AesGcm;
use chacha20poly1305::ChaChaPoly1305;
use crypto_common::{KeyInit, KeySizeUser};
use generic_array::ArrayLength;
use rustls::{
    crypto::cipher::{
        self, AeadKey, BorrowedPlainMessage, KeyBlockShape, MessageDecrypter, MessageEncrypter,
        OpaqueMessage, PlainMessage, Tls12AeadAlgorithm, Tls13AeadAlgorithm,
    },
    ContentType, ProtocolVersion,
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

pub struct Aead<T>(PhantomData<T>);

impl<T> Aead<T> {
    pub const DEFAULT: Self = Self(PhantomData);
}

impl<T> Tls13AeadAlgorithm for Aead<T>
where
    T: Send + Sync + KeyInit + KeySizeUser + AeadInPlace + 'static,
    aead::Nonce<T>: From<NonceType>,
    AeadCipherTls13<T>: AeadMetaTls13,
{
    fn encrypter(&self, key: AeadKey, iv: cipher::Iv) -> Box<dyn MessageEncrypter> {
        Box::new(AeadCipherTls13(
            T::new_from_slice(key.as_ref()).unwrap(),
            iv,
        ))
    }

    fn decrypter(&self, key: AeadKey, iv: cipher::Iv) -> Box<dyn MessageDecrypter> {
        Box::new(AeadCipherTls13(
            T::new_from_slice(key.as_ref()).unwrap(),
            iv,
        ))
    }

    fn key_len(&self) -> usize {
        T::key_size()
    }
}

#[cfg(feature = "tls12")]
impl<Aes, NonceSize> Tls12AeadAlgorithm for Aead<AesGcm<Aes, NonceSize>>
where
    Aes: Send + Sync + 'static,
    NonceSize: Send + Sync + ArrayLength<u8>,
    AesGcm<Aes, NonceSize>: AeadInPlace + KeyInit,
    AeadCipherTls12<AesGcm<Aes, NonceSize>>: AeadMetaTls12,
    aead::Nonce<AesGcm<Aes, NonceSize>>: From<NonceType>,
{
    fn encrypter(
        &self,
        key: AeadKey,
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        Box::new(AeadCipherTls12(
            AesGcm::<Aes, NonceSize>::new_from_slice(key.as_ref()).unwrap(),
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
            AesGcm::<Aes, NonceSize>::new_from_slice(dec_key.as_ref()).unwrap(),
            {
                let mut dec_salt = NonceType::default();
                dec_salt[..4].copy_from_slice(dec_iv);
                dec_salt
            },
        ))
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        AeadCipherTls12::<AesGcm<Aes, NonceSize>>::key_block_shape()
    }
}

#[cfg(feature = "tls12")]
impl<C, N> Tls12AeadAlgorithm for Aead<ChaChaPoly1305<C, N>>
where
    C: Send + Sync + 'static,
    N: Send + Sync + ArrayLength<u8>,
    ChaChaPoly1305<C, N>: AeadInPlace,
    AeadCipherTls12<ChaChaPoly1305<C, N>>: AeadMetaTls12,
    aead::Nonce<ChaChaPoly1305<C, N>>: From<NonceType>,
{
    fn encrypter(&self, key: AeadKey, _iv: &[u8], _extra: &[u8]) -> Box<dyn MessageEncrypter> {
        Box::new(AeadCipherTls12(
            ChaChaPoly1305::<C, N>::new_from_slice(key.as_ref()).unwrap(),
            {
                let mut nonce = NonceType::default();
                nonce.copy_from_slice(key.as_ref());
                nonce
            },
        ))
    }

    fn decrypter(&self, key: AeadKey, _iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let mut nonce = NonceType::default();
        nonce.copy_from_slice(key.as_ref());
        Box::new(AeadCipherTls12(
            ChaChaPoly1305::<C, N>::new_from_slice(key.as_ref()).unwrap(),
            nonce,
        ))
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        AeadCipherTls12::<ChaChaPoly1305<C, N>>::key_block_shape()
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
        let total_len = m.payload.len() + 1 + <Self as AeadMetaTls13>::OVERHEAD;

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
}

#[cfg(feature = "tls12")]
struct AeadCipherTls12<T>(T, NonceType);

#[cfg(feature = "tls12")]
impl<C, N> MessageEncrypter for AeadCipherTls12<ChaChaPoly1305<C, N>>
where
    C: Send + Sync + 'static,
    N: Send + Sync + ArrayLength<u8>,
    ChaChaPoly1305<C, N>: AeadInPlace,
    AeadCipherTls12<ChaChaPoly1305<C, N>>: AeadMetaTls12,
    aead::Nonce<ChaChaPoly1305<C, N>>: From<NonceType>,
{
    fn encrypt(&self, m: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, rustls::Error> {
        let total_len = m.payload.len() + <Self as AeadMetaTls12>::OVERHEAD;

        let mut payload = Vec::with_capacity(total_len);
        payload.extend_from_slice(m.payload);

        let nonce = cipher::Nonce::new(&self.1.into(), seq).0;
        let aad = cipher::make_tls12_aad(seq, m.typ, m.version, payload.len());

        self.0
            .encrypt_in_place(&nonce.into(), &aad, &mut payload)
            .map_err(|_| rustls::Error::EncryptError)
            .and_then(|_| Ok(OpaqueMessage::new(m.typ, m.version, payload)))
    }
}

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

        let total_len = m.payload.len() + TagSize::USIZE;
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
}

#[cfg(feature = "tls12")]
impl<C, N> MessageDecrypter for AeadCipherTls12<ChaChaPoly1305<C, N>>
where
    C: Send + Sync + 'static,
    N: Send + Sync + ArrayLength<u8>,
    ChaChaPoly1305<C, N>: AeadInPlace,
    AeadCipherTls12<ChaChaPoly1305<C, N>>: AeadMetaTls12,
    aead::Nonce<ChaChaPoly1305<C, N>>: From<NonceType>,
{
    fn decrypt(&self, mut m: OpaqueMessage, seq: u64) -> Result<PlainMessage, rustls::Error> {
        let payload = m.payload();
        let nonce = cipher::Nonce::new(&self.1.into(), seq).0;
        let aad = cipher::make_tls12_aad(
            seq,
            m.typ,
            m.version,
            payload.len() - <Self as AeadMetaTls12>::OVERHEAD,
        );

        let payload = m.payload_mut();
        self.0
            .decrypt_in_place(&nonce.into(), &aad, payload)
            .map_err(|_| rustls::Error::DecryptError)?;

        Ok(m.into_plain_message())
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

impl AeadMetaTls13 for AeadCipherTls13<chacha20poly1305::ChaCha20Poly1305> {
    const OVERHEAD: usize = 16;
}

#[cfg(feature = "tls12")]
impl AeadMetaTls12 for AeadCipherTls12<chacha20poly1305::ChaCha20Poly1305> {
    const OVERHEAD: usize = 16;

    fn key_block_shape() -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len:        32,
            fixed_iv_len:       12,
            explicit_nonce_len: 0,
        }
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
