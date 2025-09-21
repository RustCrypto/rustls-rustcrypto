use aead::Buffer;
use rustls::crypto::cipher::{BorrowedPayload, PrefixedPayload};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "gcm")]
pub mod gcm;

#[cfg(feature = "ccm")]
pub mod ccm;

#[macro_use]
pub(crate) mod common;

#[cfg(feature = "tinyvec")]
use tinyvec::SliceVec;

pub(crate) enum EncryptBufferAdapter<'a> {
    PrefixedPayload(&'a mut PrefixedPayload),
    #[cfg(feature = "quic")]
    Vec(Vec<u8>),
}

impl AsRef<[u8]> for EncryptBufferAdapter<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            EncryptBufferAdapter::PrefixedPayload(payload) => payload.as_ref(),
            #[cfg(feature = "quic")]
            EncryptBufferAdapter::Vec(payload) => payload.as_ref(),
        }
    }
}

impl AsMut<[u8]> for EncryptBufferAdapter<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            EncryptBufferAdapter::PrefixedPayload(payload) => payload.as_mut(),
            #[cfg(feature = "quic")]
            EncryptBufferAdapter::Vec(payload) => payload.as_mut(),
        }
    }
}

impl Buffer for EncryptBufferAdapter<'_> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aead::Result<()> {
        match self {
            EncryptBufferAdapter::PrefixedPayload(payload) => payload.extend_from_slice(other),
            #[cfg(feature = "quic")]
            EncryptBufferAdapter::Vec(payload) => payload.extend_from_slice(other),
        }
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        match self {
            EncryptBufferAdapter::PrefixedPayload(payload) => payload.truncate(len),
            #[cfg(feature = "quic")]
            EncryptBufferAdapter::Vec(payload) => payload.truncate(len),
        }
    }
}

pub(crate) enum DecryptBufferAdapter<'a, 'p> {
    BorrowedPayload(&'a mut BorrowedPayload<'p>),
    #[cfg(feature = "tinyvec")]
    Slice(SliceVec<'a, u8>),
}

impl AsRef<[u8]> for DecryptBufferAdapter<'_, '_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            DecryptBufferAdapter::BorrowedPayload(payload) => payload,
            #[cfg(feature = "tinyvec")]
            DecryptBufferAdapter::Slice(slice) => slice,
        }
    }
}

impl AsMut<[u8]> for DecryptBufferAdapter<'_, '_> {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            DecryptBufferAdapter::BorrowedPayload(payload) => payload,
            #[cfg(feature = "tinyvec")]
            DecryptBufferAdapter::Slice(slice) => slice,
        }
    }
}

impl Buffer for DecryptBufferAdapter<'_, '_> {
    fn extend_from_slice(&mut self, _: &[u8]) -> aead::Result<()> {
        unreachable!("not used by `AeadInPlace::decrypt_in_place`")
    }

    fn truncate(&mut self, len: usize) {
        match self {
            DecryptBufferAdapter::BorrowedPayload(payload) => payload.truncate(len),
            #[cfg(feature = "tinyvec")]
            DecryptBufferAdapter::Slice(payload) => payload.truncate(len),
        }
    }
}

#[cfg(feature = "aes")]
pub mod aes;
