use core::marker::PhantomData;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use ::aead::{AeadInOut, Nonce, Tag};
use ::crypto_common::KeyInit;
use rustls::ConnectionTrafficSecrets;
use rustls::crypto::cipher::{
    self, AeadKey, InboundOpaqueMessage, InboundPlainMessage, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls12AeadAlgorithm, make_tls12_aad,
};
use typenum::Unsigned;

/// Length of the explicit nonce in TLS 1.2 AEAD.
const EXPLICIT_NONCE_LEN: usize = 8;

/// TLS 1.2 AEAD Encrypter.
/// Wraps an AEAD cipher and the initialization vector for encryption.
pub struct Tls12AeadEncrypterWithExplicitNonce<A> {
    /// The underlying AEAD cipher.
    pub aead: A,
    /// The initialization vector (12 bytes).
    pub iv: [u8; 12],
}

impl<A> MessageEncrypter for Tls12AeadEncrypterWithExplicitNonce<A>
where
    A: AeadInOut + Send + Sync,
{
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        let aad = make_tls12_aad(seq, m.typ, m.version, m.payload.len());

        let nonce = cipher::Nonce::new(&self.iv.into(), seq).0;
        payload.extend_from_slice(&nonce.as_ref()[4..]); // explicit nonce
        payload.extend_from_chunks(&m.payload);

        let tag = self
            .aead
            .encrypt_inout_detached(
                &Nonce::<A>::try_from(&nonce[..]).map_err(|_| rustls::Error::EncryptError)?,
                &aad,
                (&mut payload.as_mut()[EXPLICIT_NONCE_LEN..]).into(),
            )
            .map_err(|_| rustls::Error::EncryptError)?;
        payload.extend(&tag);
        Ok(OutboundOpaqueMessage::new(m.typ, m.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + EXPLICIT_NONCE_LEN + A::TagSize::USIZE
    }
}

pub struct Tls12AeadDecrypterWithExplicitNonce<A> {
    /// The underlying AEAD cipher.
    pub aead: A,
    /// The decryption initialization vector (4 bytes).
    pub dec_iv: [u8; 4],
}

impl<A> MessageDecrypter for Tls12AeadDecrypterWithExplicitNonce<A>
where
    A: AeadInOut + Send + Sync,
{
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        macro_rules! nonce_tag_len {
            () => {{ EXPLICIT_NONCE_LEN + A::TagSize::USIZE }};
        }

        // The payload must be large enough to hold the explicit nonce and the AEAD tag.
        if m.payload.len() < nonce_tag_len!() {
            return Err(rustls::Error::DecryptError);
        }
        // Calculate the length of the plaintext.
        let plaintext_len = m.payload.len() - nonce_tag_len!();

        // Split the payload into the ciphertext and tag.
        if let Some((nonce, ciphertext_and_tag)) =
            m.payload.split_at_mut_checked(EXPLICIT_NONCE_LEN)
            && let Some((ciphertext, tag)) = ciphertext_and_tag.split_at_mut_checked(plaintext_len)
        {
            // Decrypt the ciphertext in place.
            self.aead
                .decrypt_inout_detached(
                    &Nonce::<A>::from_iter([self.dec_iv.as_ref(), nonce].concat()),
                    &make_tls12_aad(seq, m.typ, m.version, plaintext_len),
                    ciphertext.into(),
                    &Tag::<A>::try_from(&tag[..]).map_err(|_| rustls::Error::DecryptError)?,
                )
                .map_err(|_| rustls::Error::DecryptError)?;

            // The plaintext is now at an offset in the payload buffer. We need to move it
            // to the beginning of the buffer to conform to the `InboundPlainMessage` requirements.
            m.payload
                .copy_within(EXPLICIT_NONCE_LEN..EXPLICIT_NONCE_LEN + plaintext_len, 0);
            m.payload.truncate(plaintext_len);

            Ok(m.into_plain_message())
        } else {
            Err(rustls::Error::DecryptError)
        }
    }
}

pub trait Extractor {
    fn extract(
        _key: AeadKey,
        _iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
        Err(cipher::UnsupportedOperationError)
    }
}

impl Extractor for () {}

#[derive(Default)]
pub struct Tls12AeadAlgorithmWithExplicitNonce<A, E = ()> {
    _aead: PhantomData<A>,
    _extractor: PhantomData<E>,
}

impl<A, E> Tls12AeadAlgorithmWithExplicitNonce<A, E> {
    pub const DEFAULT: Self = Self {
        _aead: PhantomData,
        _extractor: PhantomData,
    };
}

impl<A, E> Tls12AeadAlgorithm for Tls12AeadAlgorithmWithExplicitNonce<A, E>
where
    A: KeyInit + AeadInOut + Send + Sync + 'static,
    E: Extractor + Send + Sync + 'static,
{
    fn encrypter(
        &self,
        key: AeadKey,
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        Box::new(Tls12AeadEncrypterWithExplicitNonce::<A> {
            aead: A::new_from_slice(key.as_ref()).expect("key should be valid"),
            iv: {
                let mut iv: [u8; 12] = [0; 12];
                iv[..4].copy_from_slice(write_iv);
                iv[4..].copy_from_slice(explicit);
                iv
            },
        })
    }

    fn decrypter(&self, dec_key: AeadKey, dec_iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(Tls12AeadDecrypterWithExplicitNonce::<A> {
            aead: A::new_from_slice(dec_key.as_ref()).expect("key should be valid"),
            dec_iv: dec_iv.try_into().expect("iv should be valid"),
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: A::key_size(),
            fixed_iv_len: 4,
            explicit_nonce_len: EXPLICIT_NONCE_LEN,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
        E::extract(key, iv, explicit)
    }
}
