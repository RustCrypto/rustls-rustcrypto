#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use crypto::{SharedSecret, SupportedKxGroup};
use rustls::crypto::{self, ActiveKeyExchange};
use x25519_dalek::{EphemeralSecret, PublicKey};

#[derive(Debug)]
pub struct X25519;

impl crypto::SupportedKxGroup for X25519 {
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }

    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let priv_key = EphemeralSecret::random();
        let pub_key = PublicKey::from(&priv_key);
        Ok(Box::new(X25519KeyExchange { priv_key, pub_key }))
    }
}

pub struct X25519KeyExchange {
    priv_key: EphemeralSecret,
    pub_key: PublicKey,
}

impl ActiveKeyExchange for X25519KeyExchange {
    fn complete(self: Box<X25519KeyExchange>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer_array: [u8; 32] = peer
            .try_into()
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        Ok(self
            .priv_key
            .diffie_hellman(&peer_array.into())
            .as_ref()
            .into())
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_bytes()
    }

    fn group(&self) -> rustls::NamedGroup {
        X25519.name()
    }
}
