#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use crypto::{SharedSecret, SupportedKxGroup};
use rand_core::{RngCore, TryRngCore};
use rustls::crypto::{self, ActiveKeyExchange};

#[derive(Debug)]
pub struct X448;

impl crypto::SupportedKxGroup for X448 {
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X448
    }

    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {

        let priv_key = x448::Secret::from({
            let mut bytes = [0u8; 56];
            rand_core::OsRng.try_fill_bytes(&mut bytes).unwrap();
            bytes
        });
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
        let pub_key = x448::PublicKey::from_bytes(peer).unwrap();

        self.priv_key.as_diffie_hellman(&pub_key).unwrap();

        // let peer_public: x448::PublicKey = peer
        //     .try_into()
        //     .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        Ok(self.priv_key.as_diffie_hellman(&pub_key).unwrap().as_bytes().as_ref().into())
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_bytes()
    }

    fn group(&self) -> rustls::NamedGroup {
        X448.name()
    }
}
