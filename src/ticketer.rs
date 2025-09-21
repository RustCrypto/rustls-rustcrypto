#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::sync::Arc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt::{Debug, Formatter};
use core::sync::atomic::{AtomicUsize, Ordering};
use core::{fmt, time};

use aead::{AeadInOut, KeyInit};
use elliptic_curve::subtle::ConstantTimeEq;
use rand_core::{OsRng, TryRngCore};
use rustls::crypto::GetRandomFailed;
use rustls::server::ProducesTickets;
use rustls::{Error, ticketer::TicketRotator};

#[cfg(feature = "chacha20poly1305")]
use chacha20poly1305::ChaCha20Poly1305;

fn try_split_at(data: &[u8], at: usize) -> Option<(&[u8], &[u8])> {
    if data.len() < at {
        None
    } else {
        Some(data.split_at(at))
    }
}

/// A concrete, safe ticket creation mechanism.
#[non_exhaustive]
pub struct Ticketer {}

impl Ticketer {
    #[allow(clippy::new_ret_no_self, clippy::missing_errors_doc)]
    pub fn new() -> Result<Arc<dyn ProducesTickets>, Error> {
        Ok(Arc::new(TicketRotator::new(
            #[allow(clippy::cast_possible_truncation)]
            {
                time::Duration::from_secs(6 * 60 * 60).as_secs() as u32
            },
            || Ok(Box::new(AeadTicketProducer::new()?)),
        )?))
    }
}

struct AeadTicketProducer {
    key: ChaCha20Poly1305,
    key_name: [u8; 16],
    maximum_ciphertext_len: AtomicUsize,
}

impl AeadTicketProducer {
    fn new() -> Result<Self, GetRandomFailed> {
        let mut key_bytes = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut key_bytes)
            .map_err(|_| GetRandomFailed)?;

        let key = ChaCha20Poly1305::new_from_slice(&key_bytes).map_err(|_| GetRandomFailed)?;

        let mut key_name = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut key_name)
            .map_err(|_| GetRandomFailed)?;

        Ok(Self {
            key,
            key_name,
            maximum_ciphertext_len: AtomicUsize::new(0),
        })
    }
}

impl ProducesTickets for AeadTicketProducer {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        // this is not used, as this ticketer is only used via a `TicketRotator`
        // that is responsible for defining and managing the lifetime of tickets.
        0
    }

    /// Encrypt `message` and return the ciphertext.
    fn encrypt(&self, message: &[u8]) -> Option<Vec<u8>> {
        // Random nonce, because a counter is a privacy leak.
        let mut nonce_buf = [0u8; 12];
        OsRng.try_fill_bytes(&mut nonce_buf).ok()?;
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
        ciphertext.extend(tag);

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
        let tag_vec = out.split_off(out.len() - 16);
        let tag = tag_vec.try_into().ok()?;

        self.key
            .decrypt_inout_detached(&nonce, alleged_key_name, (&mut out[..]).into(), &tag)
            .ok()?;
        let plain_len = out.len();
        out.truncate(plain_len);

        Some(out)
    }
}

impl Debug for AeadTicketProducer {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // Note: we deliberately omit the key from the debug output.
        f.debug_struct("AeadTicketer").finish()
    }
}
