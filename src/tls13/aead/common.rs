use core::marker::PhantomData;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use aead::{AeadInOut, KeyInit, Nonce};
use rustls::{
    ConnectionTrafficSecrets, ContentType, ProtocolVersion,
    crypto::cipher::{
        self, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter,
        MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
        Tls13AeadAlgorithm, make_tls13_aad,
    },
};
use typenum::Unsigned;

use crate::aead::{DecryptBufferAdapter, EncryptBufferAdapter};

pub struct Tls13AeadEncrypter<A> {
    aead: A,
    iv: Iv,
}

impl<A> MessageEncrypter for Tls13AeadEncrypter<A>
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

        payload.extend_from_chunks(&m.payload);
        payload.extend_from_slice(&m.typ.to_array());

        self.aead
            .encrypt_in_place(
                &Nonce::<A>::try_from(&cipher::Nonce::new(&self.iv, seq).0[..])
                    .map_err(|_| rustls::Error::EncryptError)?,
                &make_tls13_aad(total_len),
                &mut EncryptBufferAdapter(&mut payload),
            )
            .map_err(|_| rustls::Error::EncryptError)
            .map(|_| {
                OutboundOpaqueMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    payload,
                )
            })
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + A::TagSize::USIZE
    }
}

pub struct Tls13AeadDecrypter<A> {
    aead: A,
    iv: Iv,
}

impl<A> MessageDecrypter for Tls13AeadDecrypter<A>
where
    A: AeadInOut + Send + Sync,
{
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        self.aead
            .decrypt_in_place(
                &Nonce::<A>::try_from(&cipher::Nonce::new(&self.iv, seq).0[..])
                    .map_err(|_| rustls::Error::DecryptError)?,
                &make_tls13_aad(m.payload.len()),
                &mut DecryptBufferAdapter(&mut m.payload),
            )
            .map_err(|_| rustls::Error::DecryptError)?;

        m.into_tls13_unpadded_message()
    }
}

pub trait Extractor {
    fn extract(
        _key: AeadKey,
        _iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
        Err(cipher::UnsupportedOperationError)
    }
}

impl Extractor for () {}

#[derive(Default)]
pub struct Tls13AeadAlgorithmCommon<A, E = ()> {
    _aead: PhantomData<A>,
    _extractor: PhantomData<E>,
}

impl<A, E> Tls13AeadAlgorithmCommon<A, E> {
    pub const DEFAULT: Self = Self {
        _aead: PhantomData,
        _extractor: PhantomData,
    };
}

impl<A, E> Tls13AeadAlgorithm for Tls13AeadAlgorithmCommon<A, E>
where
    A: KeyInit + AeadInOut + Send + Sync + 'static,
    E: Extractor + Send + Sync + 'static,
{
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13AeadEncrypter::<A> {
            aead: A::new_from_slice(key.as_ref()).expect("Invalid key length for AEAD algorithm"),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13AeadDecrypter::<A> {
            aead: A::new_from_slice(key.as_ref()).expect("Invalid key length for AEAD algorithm"),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        A::key_size()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
        E::extract(key, iv)
    }
}
