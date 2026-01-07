#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::ToString};

use crate::aead::{DecryptBufferAdapter, EncryptBufferAdapter};
use aead::{AeadCore, AeadInOut, KeyInit};
use enum_dispatch::enum_dispatch;
use rustls::Error;
use rustls::crypto::cipher::{AeadKey, Iv, Nonce};
use rustls::quic;
use typenum::Unsigned;

#[cfg(feature = "aes-ccm")]
use crate::aead::aes::Aes128Ccm;
#[cfg(feature = "aes-gcm")]
use crate::aead::aes::{Aes128Gcm, Aes256Gcm};
#[cfg(feature = "chacha20")]
use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};
#[cfg(feature = "chacha20poly1305")]
use chacha20poly1305::ChaCha20Poly1305;
#[cfg(feature = "aes")]
use cipher::BlockCipherEncrypt;
#[cfg(feature = "chacha20")]
use cipher::StreamCipherSeek;

/// Errors that can occur in QUIC operations
#[derive(Debug, thiserror::Error)]
pub enum QuicError {
    /// Failed to convert sample to block
    #[error("failed to convert sample to block: {0}")]
    SampleToBlock(#[from] core::array::TryFromSliceError),

    /// Failed to convert encrypted block to mask
    #[error("failed to convert encrypted block to mask: {0}")]
    BlockToMask(core::array::TryFromSliceError),

    /// Failed to convert first 4 bytes of sample to counter
    #[error("failed to convert first 4 bytes of sample to counter: {0}")]
    SampleToCounter(core::array::TryFromSliceError),

    /// Invalid ChaCha20 nonce length
    #[error("invalid ChaCha20 nonce length: {0}")]
    InvalidNonceLength(core::array::TryFromSliceError),

    /// ChaCha20 seek failed
    #[cfg(feature = "chacha20")]
    #[error("ChaCha20 seek failed: {0}")]
    SeekFailed(#[from] cipher::StreamCipherError),

    /// ChaCha20 keystream failed
    #[cfg(feature = "chacha20")]
    #[error("ChaCha20 keystream failed: {0}")]
    KeystreamFailed(cipher::StreamCipherError),

    /// Invalid AES key
    #[cfg(feature = "aes")]
    #[error("invalid AES key: {0}")]
    InvalidAesKey(#[from] cipher::InvalidLength),

    /// Invalid ChaCha20-Poly1305 key
    #[cfg(feature = "chacha20")]
    #[error("invalid ChaCha20-Poly1305 key: {0}")]
    InvalidChaCha20Key(core::array::TryFromSliceError),

    /// Invalid QUIC header protection mask length
    #[error("invalid QUIC header protection mask length")]
    InvalidMaskLength,

    /// Invalid QUIC header protection packet number length
    #[error("invalid QUIC header protection packet number length")]
    InvalidPacketNumberLength,

    /// Invalid nonce for AEAD operation
    #[error("invalid nonce for AEAD operation: {0}")]
    InvalidNonce(core::array::TryFromSliceError),

    #[error("Encryption failed: {0}")]
    Encrypt(aead::Error),

    #[error("Decryption failed: {0}")]
    Decrypt(aead::Error),
}

impl From<QuicError> for rustls::Error {
    fn from(e: QuicError) -> Self {
        match e {
            QuicError::Encrypt(_) => rustls::Error::EncryptError,
            QuicError::Decrypt(_) => rustls::Error::DecryptError,
            _ => rustls::Error::General(e.to_string()),
        }
    }
}

trait HasHeaderKey {
    #[allow(clippy::new_ret_no_self)]
    fn new(key: AeadKey) -> Result<HeaderProtectionKey, QuicError>;
}

#[cfg(feature = "aes-gcm")]
impl HasHeaderKey for Aes128Gcm {
    fn new(key: AeadKey) -> Result<HeaderProtectionKey, QuicError> {
        Ok(HeaderProtectionKey::Aes128Ecb(aes::Aes128::new_from_slice(
            key.as_ref(),
        )?))
    }
}

#[cfg(feature = "aes-gcm")]
impl HasHeaderKey for Aes256Gcm {
    fn new(key: AeadKey) -> Result<HeaderProtectionKey, QuicError> {
        Ok(HeaderProtectionKey::Aes256Ecb(aes::Aes256::new_from_slice(
            key.as_ref(),
        )?))
    }
}

#[cfg(feature = "aes-ccm")]
impl HasHeaderKey for Aes128Ccm {
    fn new(key: AeadKey) -> Result<HeaderProtectionKey, QuicError> {
        Ok(HeaderProtectionKey::Aes128Ecb(aes::Aes128::new_from_slice(
            key.as_ref(),
        )?))
    }
}

#[cfg(feature = "chacha20poly1305")]
impl HasHeaderKey for ChaCha20Poly1305 {
    fn new(key: AeadKey) -> Result<HeaderProtectionKey, QuicError> {
        let key = chacha20::Key::try_from(key.as_ref()).map_err(QuicError::InvalidChaCha20Key)?;
        Ok(HeaderProtectionKey::ChaCha20(key))
    }
}

#[enum_dispatch(MaskSample)]
#[allow(clippy::large_enum_variant)]
pub enum HeaderProtectionKey {
    #[cfg(feature = "aes")]
    Aes128Ecb(aes::Aes128),
    #[cfg(feature = "aes")]
    Aes256Ecb(aes::Aes256),
    #[cfg(feature = "chacha20")]
    ChaCha20(chacha20::Key),
}

#[enum_dispatch]
trait MaskSample {
    fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5], QuicError>;
}

// 5.4.3. AES-Based Header Protection
// This section defines the packet protection algorithm for AEAD_AES_128_GCM, AEAD_AES_128_CCM, and AEAD_AES_256_GCM. AEAD_AES_128_GCM and AEAD_AES_128_CCM use 128-bit AES in Electronic Codebook (ECB) mode.
// AEAD_AES_256_GCM uses 256-bit AES in ECB mode. AES is defined in [AES].

// This algorithm samples 16 bytes from the packet ciphertext. This value is used as the input to AES-ECB. In pseudocode, the header protection function is defined as:

// header_protection(hp_key, sample):
//   mask = AES-ECB(hp_key, sample)
#[cfg(feature = "aes")]
impl MaskSample for aes::Aes128 {
    fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5], QuicError> {
        let mut block = (&sample[..16])
            .try_into()
            .map_err(QuicError::SampleToBlock)?;

        self.encrypt_block(&mut block);
        block[..5].try_into().map_err(QuicError::BlockToMask)
    }
}

#[cfg(feature = "aes")]
impl MaskSample for aes::Aes256 {
    fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5], QuicError> {
        let mut block = (&sample[..16])
            .try_into()
            .map_err(QuicError::SampleToBlock)?;

        self.encrypt_block(&mut block);
        block[..5].try_into().map_err(QuicError::BlockToMask)
    }
}

#[cfg(feature = "chacha20")]
impl MaskSample for chacha20::Key {
    fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5], QuicError> {
        // 5.4.4. ChaCha20-Based Header Protection
        // When AEAD_CHACHA20_POLY1305 is in use, header protection uses the raw ChaCha20 function as defined in Section 2.4 of [CHACHA]. This uses a 256-bit key and 16 bytes sampled from the packet protection output.
        //
        // The first 4 bytes of the sampled ciphertext are the block counter. A ChaCha20 implementation could take a 32-bit integer in place of a byte sequence, in which case, the byte sequence is interpreted as a little-endian value.
        //
        // The remaining 12 bytes are used as the nonce. A ChaCha20 implementation might take an array of three 32-bit integers in place of a byte sequence, in which case, the nonce bytes are interpreted as a sequence of 32-bit little-endian integers.
        //
        // The encryption mask is produced by invoking ChaCha20 to protect 5 zero bytes. In pseudocode, the header protection function is defined as:
        //
        // header_protection(hp_key, sample):
        //   counter = sample[0..3]
        //   nonce = sample[4..15]
        //   mask = ChaCha20(hp_key, counter, nonce, {0,0,0,0,0})

        let counter = u32::from_le_bytes(
            sample[0..4]
                .try_into()
                .map_err(QuicError::SampleToCounter)?,
        );
        let nonce = &sample[4..16];
        let mut chacha = ChaCha20::new(
            self,
            nonce.try_into().map_err(QuicError::InvalidNonceLength)?,
        );

        chacha.try_seek(counter).map_err(QuicError::SeekFailed)?;

        let mut mask = [0u8; 5];
        chacha
            .try_apply_keystream_b2b(&[0u8; 5], &mut mask)
            .map_err(QuicError::KeystreamFailed)?;

        Ok(mask)
    }
}

trait XorInPlace {
    fn xor_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        masked: bool,
    ) -> Result<(), QuicError>;
}

impl<T: MaskSample> XorInPlace for T {
    fn xor_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        masked: bool,
    ) -> Result<(), QuicError> {
        // This implements "Header Protection Application" almost verbatim.
        // <https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.1>

        let mask = self.new_mask(sample)?;

        // The `unwrap()` will not panic because `new_mask` returns a
        // non-empty result.
        let (first_mask, pn_mask) = mask.split_first().ok_or(QuicError::InvalidMaskLength)?;

        // It is OK for the `mask` to be longer than `packet_number`,
        // but a valid `packet_number` will never be longer than `mask`.
        if packet_number.len() > pn_mask.len() {
            return Err(QuicError::InvalidPacketNumberLength);
        }

        // Infallible from this point on. Before this point, `first` and
        // `packet_number` are unchanged.

        const LONG_HEADER_FORM: u8 = 0x80;
        let bits = match *first & LONG_HEADER_FORM == LONG_HEADER_FORM {
            true => 0x0f,  // Long header: 4 bits masked
            false => 0x1f, // Short header: 5 bits masked
        };

        let first_plain = *first ^ if masked { first_mask & bits } else { 0 };
        let pn_len = (first_plain & 0x03) as usize + 1;

        *first ^= first_mask & bits;
        for (dst, m) in packet_number.iter_mut().zip(pn_mask).take(pn_len) {
            *dst ^= m;
        }

        Ok(())
    }
}

impl quic::HeaderProtectionKey for HeaderProtectionKey {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, false)
            .map_err(Into::into)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, true)
            .map_err(Into::into)
    }

    #[inline]
    fn sample_len(&self) -> usize {
        16
    }
}

pub(crate) struct PacketKey<A> {
    /// Encrypts or decrypts a packet's payload
    key: A,
    /// Computes unique nonces for each packet
    iv: Iv,
    /// Confidentiality limit (see [`quic::PacketKey::confidentiality_limit`])
    confidentiality_limit: u64,
    /// Integrity limit (see [`quic::PacketKey::integrity_limit`])
    integrity_limit: u64,
}

impl<A> PacketKey<A>
where
    A: KeyInit + AeadInOut + Send + Sync,
{
    pub(crate) fn new(
        key: AeadKey,
        iv: Iv,
        confidentiality_limit: u64,
        integrity_limit: u64,
    ) -> Self {
        Self {
            key: A::new_from_slice(key.as_ref()).expect("Invalid key length for AEAD algorithm"),
            iv,
            confidentiality_limit,
            integrity_limit,
        }
    }
}

impl<A> quic::PacketKey for PacketKey<A>
where
    A: AeadInOut + Send + Sync,
{
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        let nonce_aead: cipher::Array<u8, <A as AeadCore>::NonceSize> =
            aead::Nonce::<A>::try_from(&Nonce::new(&self.iv, packet_number).0[..])
                .map_err(QuicError::InvalidNonce)?;

        // Create a buffer with the payload
        let mut buffer = EncryptBufferAdapter::Vec(payload.to_vec());

        self.key
            .encrypt_in_place(&nonce_aead, header, &mut buffer)
            .map_err(QuicError::Encrypt)?;

        let buffer = buffer.as_ref();

        // Copy the encrypted payload back
        payload.copy_from_slice(&buffer[..payload.len()]);

        // Extract the tag from the end
        Ok(quic::Tag::from(&buffer[payload.len()..]))
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let nonce_aead = aead::Nonce::<A>::try_from(&Nonce::new(&self.iv, packet_number).0[..])
            .map_err(QuicError::InvalidNonce)?;

        // Append the tag to the payload for decryption
        if payload.len() < A::TagSize::USIZE {
            return Err(QuicError::Decrypt(aead::Error).into());
        }
        let plaintext_len = payload.len() - A::TagSize::USIZE;

        self.key
            .decrypt_in_place(
                &nonce_aead,
                header,
                &mut DecryptBufferAdapter::Slice(payload.into()),
            )
            .map_err(QuicError::Decrypt)?;

        Ok(&payload[..plaintext_len])
    }

    /// Tag length for the underlying AEAD algorithm
    #[inline]
    fn tag_len(&self) -> usize {
        A::TagSize::USIZE
    }

    /// Confidentiality limit (see [`quic::PacketKey::confidentiality_limit`])
    fn confidentiality_limit(&self) -> u64 {
        self.confidentiality_limit
    }

    /// Integrity limit (see [`quic::PacketKey::integrity_limit`])
    fn integrity_limit(&self) -> u64 {
        self.integrity_limit
    }
}

pub(crate) struct QuicCrypto<A> {
    pub(crate) packet_alg: core::marker::PhantomData<A>,
    pub(crate) confidentiality_limit: u64,
    pub(crate) integrity_limit: u64,
}

impl<A> QuicCrypto<A> {
    pub const DEFAULT: Self = Self {
        packet_alg: core::marker::PhantomData,
        confidentiality_limit: u64::MAX,
        integrity_limit: u64::MAX,
    };
}

impl<A> quic::Algorithm for QuicCrypto<A>
where
    A: AeadCore + AeadInOut + KeyInit + HasHeaderKey + Send + Sync + 'static,
{
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        Box::new(PacketKey::<A>::new(
            key,
            iv,
            self.confidentiality_limit,
            self.integrity_limit,
        ))
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        Box::new(<A as HasHeaderKey>::new(key).expect("Invalid key length for header protection"))
    }

    fn aead_key_len(&self) -> usize {
        A::key_size()
    }

    fn fips(&self) -> bool {
        false // RustCrypto doesn't have FIPS certification
    }
}
