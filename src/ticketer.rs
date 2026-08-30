//! Session ticket encryption using ChaCha20-Poly1305.
//!
//! Provides a [`Ticketer`] factory that wraps rustls [`TicketRotator`] with a
//! ChaCha20-Poly1305 AEAD backend for server-side TLS session resumption.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::{self, Debug, Formatter};
use core::sync::atomic::{AtomicUsize, Ordering};

use aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use getrandom::rand_core::TryRng;
use rustls::crypto::GetRandomFailed;
use rustls::server::ProducesTickets;
use rustls::ticketer::TicketRotator;
use rustls::Error;
use subtle::ConstantTimeEq;

fn try_split_at(data: &[u8], at: usize) -> Option<(&[u8], &[u8])> {
    if data.len() < at {
        None
    } else {
        Some(data.split_at(at))
    }
}

fn fill_random(buf: &mut [u8]) -> Result<(), GetRandomFailed> {
    getrandom::SysRng
        .try_fill_bytes(buf)
        .map_err(|_| GetRandomFailed)
}

/// A concrete, safe ticket creation mechanism.
#[non_exhaustive]
pub struct Ticketer {}

impl Ticketer {
    /// Make the recommended `Ticketer`. This produces tickets with a 12 hour
    /// life (via a 6-hour rotator) and randomly generated keys.
    ///
    /// The encryption mechanism used is ChaCha20-Poly1305.
    #[allow(clippy::new_ret_no_self, clippy::missing_errors_doc)]
    pub fn new() -> Result<Arc<dyn ProducesTickets>, Error> {
        Ok(Arc::new(TicketRotator::new(
            6 * 60 * 60,
            make_ticket_generator,
        )?))
    }
}

fn make_ticket_generator() -> Result<Box<dyn ProducesTickets>, GetRandomFailed> {
    Ok(Box::new(AeadTicketer::new()?))
}

/// `ProducesTickets` implementation using ChaCha20-Poly1305.
///
/// Does not enforce lifetime constraints itself; intended for use under a
/// [`TicketRotator`] that manages rotation and advertised lifetime.
struct AeadTicketer {
    key: ChaCha20Poly1305,
    key_name: [u8; 16],
    /// Tracks the largest ciphertext produced by `encrypt`, and uses it to
    /// early-reject `decrypt` queries that are too long.
    ///
    /// Accepting excessively long ciphertexts means a "Partitioning Oracle
    /// Attack" (see <https://eprint.iacr.org/2020/1491.pdf>) can be more
    /// efficient, though also note that these are thought to be cryptographically
    /// hard if the key is full-entropy (as it is here).
    maximum_ciphertext_len: AtomicUsize,
}

impl AeadTicketer {
    fn new() -> Result<Self, GetRandomFailed> {
        let mut key_bytes = [0u8; 32];
        fill_random(&mut key_bytes)?;

        let key = ChaCha20Poly1305::new_from_slice(&key_bytes).map_err(|_| GetRandomFailed)?;

        let mut key_name = [0u8; 16];
        fill_random(&mut key_name)?;

        Ok(Self {
            key,
            key_name,
            maximum_ciphertext_len: AtomicUsize::new(0),
        })
    }
}

impl ProducesTickets for AeadTicketer {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        // Not used when this ticketer is only used via a `TicketRotator` that is
        // responsible for defining and managing the lifetime of tickets.
        0
    }

    /// Encrypt `message` and return the ciphertext.
    fn encrypt(&self, message: &[u8]) -> Option<Vec<u8>> {
        // Random nonce, because a counter is a privacy leak.
        let mut nonce_buf = [0u8; 12];
        fill_random(&mut nonce_buf).ok()?;
        let nonce = nonce_buf.into();

        // ciphertext structure is:
        // key_name: [u8; 16]
        // nonce: [u8; 12]
        // message: [u8, _]
        // tag: [u8; 16]

        let mut ciphertext =
            Vec::with_capacity(self.key_name.len() + nonce_buf.len() + message.len() + 16);
        ciphertext.extend(self.key_name);
        ciphertext.extend(nonce_buf);
        ciphertext.extend(message);
        let tag = self
            .key
            .encrypt_inout_detached(
                &nonce,
                &self.key_name,
                (&mut ciphertext[self.key_name.len() + nonce_buf.len()..]).into(),
            )
            .ok()?;
        ciphertext.extend(tag.as_slice());

        self.maximum_ciphertext_len
            .fetch_max(ciphertext.len(), Ordering::SeqCst);
        Some(ciphertext)
    }

    /// Decrypt `ciphertext` and recover the original message.
    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if ciphertext.len() > self.maximum_ciphertext_len.load(Ordering::SeqCst) {
            return None;
        }

        let (alleged_key_name, ciphertext) = try_split_at(ciphertext, self.key_name.len())?;

        let (nonce_bytes, ciphertext) = try_split_at(ciphertext, 12)?;

        // checking the key_name is the expected one, *and* then putting it into the
        // additionally authenticated data is duplicative.  this check quickly rejects
        // tickets for a different ticketer (see `TicketRotator`), while including it
        // in the AAD ensures it is authenticated independent of that check and that
        // any attempted attack on the integrity such as [^1] must happen for each
        // `key_label`, not over a population of potential keys.  this approach
        // is overall similar to [^2].
        //
        // [^1]: https://eprint.iacr.org/2020/1491.pdf
        // [^2]: "Authenticated Encryption with Key Identification", fig 6
        //       <https://eprint.iacr.org/2022/1680.pdf>
        if ConstantTimeEq::ct_ne(&self.key_name[..], alleged_key_name).into() {
            return None;
        }

        let nonce = nonce_bytes.try_into().ok()?;

        let mut out = Vec::from(ciphertext);
        if out.len() < 16 {
            return None;
        }
        let tag_vec = out.split_off(out.len() - 16);
        let tag = tag_vec.as_slice().try_into().ok()?;

        self.key
            .decrypt_inout_detached(&nonce, alleged_key_name, (&mut out[..]).into(), &tag)
            .ok()?;

        Some(out)
    }
}

impl Debug for AeadTicketer {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // Note: we deliberately omit the key from the debug output.
        f.debug_struct("AeadTicketer").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_pairwise_test() {
        let t = Ticketer::new().unwrap();
        assert!(t.enabled());
        let cipher = t.encrypt(b"hello world").unwrap();
        let plain = t.decrypt(&cipher).unwrap();
        assert_eq!(plain, b"hello world");
    }

    #[test]
    fn refuses_decrypt_before_encrypt() {
        let t = Ticketer::new().unwrap();
        assert_eq!(t.decrypt(b"hello"), None);
    }

    #[test]
    fn refuses_decrypt_larger_than_largest_encryption() {
        let t = Ticketer::new().unwrap();
        let mut cipher = t.encrypt(b"hello world").unwrap();
        assert_eq!(t.decrypt(&cipher), Some(b"hello world".to_vec()));

        // obviously this would never work anyway, but this
        // and `refuses_decrypt_before_encrypt` exercise the
        // first branch in `decrypt()`
        cipher.push(0);
        assert_eq!(t.decrypt(&cipher), None);
    }

    #[test]
    fn aead_ticketer_is_debug() {
        let t = make_ticket_generator().unwrap();
        assert_eq!(alloc::format!("{t:?}"), "AeadTicketer");
        assert!(t.enabled());
        assert_eq!(t.lifetime(), 0);
    }
}
