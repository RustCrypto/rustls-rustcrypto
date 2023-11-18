#![allow(clippy::duplicate_mod)]

use alloc::boxed::Box;

use rustls::{
    crypto::cipher::{AeadKey, Iv},
    quic, Error, Tls13CipherSuite,
};

pub struct HeaderProtectionKey(AeadKey);

impl HeaderProtectionKey {
    pub fn new(key: AeadKey) -> Self {
        Self(key)
    }
}

impl quic::HeaderProtectionKey for HeaderProtectionKey {
    fn encrypt_in_place(
        &self,
        _sample: &[u8],
        _first: &mut u8,
        _packet_number: &mut [u8],
    ) -> Result<(), Error> {
        todo!()
    }

    fn decrypt_in_place(
        &self,
        _sample: &[u8],
        _first: &mut u8,
        _packet_number: &mut [u8],
    ) -> Result<(), Error> {
        todo!()
    }

    #[inline]
    fn sample_len(&self) -> usize {
        todo!()
    }
}

pub struct PacketKey {
    #[allow(dead_code)]
    key:   AeadKey,
    #[allow(dead_code)]
    /// Computes unique nonces for each packet
    iv:    Iv,
    /// The cipher suite used for this packet key
    suite: &'static Tls13CipherSuite,
}

impl PacketKey {
    pub fn new(suite: &'static Tls13CipherSuite, key: AeadKey, iv: Iv) -> Self {
        Self { key, iv, suite }
    }
}

impl quic::PacketKey for PacketKey {
    fn encrypt_in_place(
        &self,
        _packet_number: u64,
        _header: &[u8],
        _payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        todo!()
    }

    /// Decrypt a QUIC packet
    ///
    /// Takes the packet `header`, which is used as the additional authenticated
    /// data, and the `payload`, which includes the authentication tag.
    ///
    /// If the return value is `Ok`, the decrypted payload can be found in
    /// `payload`, up to the length found in the return value.
    fn decrypt_in_place<'a>(
        &self,
        _packet_number: u64,
        _header: &[u8],
        _payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        todo!()
    }

    /// Number of times the packet key can be used without sacrificing
    /// confidentiality
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc9001.html#name-confidentiality-limit>.
    #[inline]
    fn confidentiality_limit(&self) -> u64 {
        self.suite.common.confidentiality_limit
    }

    /// Number of times the packet key can be used without sacrificing integrity
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc9001.html#name-integrity-limit>.
    #[inline]
    fn integrity_limit(&self) -> u64 {
        self.suite.common.integrity_limit
    }

    /// Tag length for the underlying AEAD algorithm
    #[inline]
    fn tag_len(&self) -> usize {
        todo!()
    }
}

pub struct KeyBuilder();

impl rustls::quic::Algorithm for KeyBuilder {
    fn packet_key(
        &self,
        suite: &'static Tls13CipherSuite,
        key: AeadKey,
        iv: Iv,
    ) -> Box<dyn quic::PacketKey> {
        Box::new(PacketKey::new(suite, key, iv))
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        Box::new(HeaderProtectionKey::new(key))
    }

    fn aead_key_len(&self) -> usize {
        todo!()
    }
}