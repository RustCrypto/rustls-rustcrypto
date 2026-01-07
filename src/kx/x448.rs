#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use crypto::{SharedSecret, SupportedKxGroup};
use rand_core::TryRngCore;
use rustls::crypto::{self, ActiveKeyExchange};

#[derive(Debug)]
pub struct X448;

impl crypto::SupportedKxGroup for X448 {
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X448
    }

    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let mut priv_key = [0u8; 56];
        
        getrandom::fill(&mut priv_key)
            .map_err(|_| rustls::Error::FailedToGetRandomBytes)?;
        let priv_key: x448::Secret = priv_key.into();
        let pub_key = x448::PublicKey::from(&priv_key);

        Ok(Box::new(X448KeyExchange { priv_key, pub_key }))
    }
}

pub struct X448KeyExchange {
    priv_key: x448::Secret,
    pub_key: x448::PublicKey,
}

impl ActiveKeyExchange for X448KeyExchange {
    fn complete(self: Box<X448KeyExchange>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        Ok(self
            .priv_key
            .as_diffie_hellman(
                &x448::PublicKey::from_bytes(peer)
                    .ok_or(rustls::PeerMisbehaved::InvalidKeyShare)?,
            )
            .ok_or(rustls::PeerMisbehaved::InvalidKeyShare)?
            .as_bytes()
            .as_ref()
            .into())
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_bytes()
    }

    fn group(&self) -> rustls::NamedGroup {
        X448.name()
    }
}
