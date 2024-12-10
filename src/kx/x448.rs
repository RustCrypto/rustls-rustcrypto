#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use crrl::x448::{x448, x448_base};
use crypto::{SharedSecret, SupportedKxGroup};
use rand_core::RngCore;
use rustls::crypto::{self, ActiveKeyExchange};

#[derive(Debug)]
pub struct X448;

impl crypto::SupportedKxGroup for X448 {
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X448
    }

    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let priv_key = {
            let mut bytes = [0u8; 56];
            rand_core::OsRng.fill_bytes(&mut bytes);
            bytes
        };
        let pub_key = x448_base(&priv_key);
        Ok(Box::new(X448KeyExchange { priv_key, pub_key }))
    }
}

pub struct X448KeyExchange {
    priv_key: [u8; 56],
    pub_key: [u8; 56],
}

impl ActiveKeyExchange for X448KeyExchange {
    fn complete(self: Box<X448KeyExchange>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer_public: [u8; 56] = peer
            .try_into()
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        Ok(x448(&peer_public, &self.priv_key).as_ref().into())
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_slice()
    }

    fn group(&self) -> rustls::NamedGroup {
        X448.name()
    }
}
