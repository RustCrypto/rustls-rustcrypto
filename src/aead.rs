use aead::Buffer;
use rustls::crypto::cipher::{BorrowedPayload, PrefixedPayload};

pub const CHACHAPOLY1305_OVERHEAD: usize = 16;

pub struct ChaCha20Poly1305;
pub struct Aes128Gcm;
pub struct Aes256Gcm;

pub(crate) struct EncryptBufferAdapter<'a>(pub(crate) &'a mut PrefixedPayload);

impl AsRef<[u8]> for EncryptBufferAdapter<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for EncryptBufferAdapter<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl Buffer for EncryptBufferAdapter<'_> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aead::Result<()> {
        self.0.extend_from_slice(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }
}

pub(crate) struct DecryptBufferAdapter<'a, 'p>(pub(crate) &'a mut BorrowedPayload<'p>);

impl AsRef<[u8]> for DecryptBufferAdapter<'_, '_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl AsMut<[u8]> for DecryptBufferAdapter<'_, '_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0
    }
}

impl Buffer for DecryptBufferAdapter<'_, '_> {
    fn extend_from_slice(&mut self, _: &[u8]) -> aead::Result<()> {
        unreachable!("not used by `AeadInPlace::decrypt_in_place`")
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }
}
