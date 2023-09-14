use alloc::boxed::Box;

use crypto::SupportedKxGroup;
use rustls::crypto;

#[derive(Debug)]
pub struct X25519;

impl crypto::SupportedKxGroup for X25519 {
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }

    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::crypto::GetRandomFailed> {
        let priv_key = x25519_dalek::EphemeralSecret::random_from_rng(rand_core::OsRng);
        let pub_key = (&priv_key).into();
        Ok(Box::new(X25519KeyExchange { priv_key, pub_key }))
    }
}

pub struct X25519KeyExchange {
    priv_key: x25519_dalek::EphemeralSecret,
    pub_key:  x25519_dalek::PublicKey,
}

impl crypto::ActiveKeyExchange for X25519KeyExchange {
    fn complete(
        self: Box<X25519KeyExchange>,
        peer: &[u8],
        sink: &mut dyn crypto::SharedSecretSink,
    ) -> Result<(), rustls::Error> {
        let peer_array: [u8; 32] = peer
            .try_into()
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        let their_pub = x25519_dalek::PublicKey::from(peer_array);
        let shared_secret = self.priv_key.diffie_hellman(&their_pub);
        sink.process_shared_secret(shared_secret.as_bytes());
        Ok(())
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_bytes()
    }

    fn group(&self) -> rustls::NamedGroup {
        X25519.name()
    }
}

#[derive(Debug)]
pub struct SecP256R1;

impl crypto::SupportedKxGroup for SecP256R1 {
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp256r1
    }

    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::crypto::GetRandomFailed> {
        let priv_key = p256::ecdh::EphemeralSecret::random(&mut rand_core::OsRng);
        let pub_key: p256::PublicKey = (&priv_key).into();
        Ok(Box::new(SecP256R1KeyExchange {
            priv_key,
            pub_key: pub_key.to_sec1_bytes(),
        }))
    }
}

pub struct SecP256R1KeyExchange {
    priv_key: p256::ecdh::EphemeralSecret,
    pub_key:  Box<[u8]>,
}

impl crypto::ActiveKeyExchange for SecP256R1KeyExchange {
    fn complete(
        self: Box<SecP256R1KeyExchange>,
        peer: &[u8],
        sink: &mut dyn crypto::SharedSecretSink,
    ) -> Result<(), rustls::Error> {
        let their_pub = p256::PublicKey::from_sec1_bytes(peer)
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        let shared_secret = self.priv_key.diffie_hellman(&their_pub);
        sink.process_shared_secret(shared_secret.raw_secret_bytes());
        Ok(())
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> rustls::NamedGroup {
        SecP256R1.name()
    }
}

#[derive(Debug)]
pub struct SecP384R1;

impl crypto::SupportedKxGroup for SecP384R1 {
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp384r1
    }

    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::crypto::GetRandomFailed> {
        let priv_key = p384::ecdh::EphemeralSecret::random(&mut rand_core::OsRng);
        let pub_key: p384::PublicKey = (&priv_key).into();
        Ok(Box::new(SecP384R1KeyExchange {
            priv_key,
            pub_key: pub_key.to_sec1_bytes(),
        }))
    }
}

pub struct SecP384R1KeyExchange {
    priv_key: p384::ecdh::EphemeralSecret,
    pub_key:  Box<[u8]>,
}

impl crypto::ActiveKeyExchange for SecP384R1KeyExchange {
    fn complete(
        self: Box<SecP384R1KeyExchange>,
        peer: &[u8],
        sink: &mut dyn crypto::SharedSecretSink,
    ) -> Result<(), rustls::Error> {
        let their_pub = p384::PublicKey::from_sec1_bytes(peer)
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        let shared_secret = self.priv_key.diffie_hellman(&their_pub);
        sink.process_shared_secret(shared_secret.raw_secret_bytes());
        Ok(())
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> rustls::NamedGroup {
        SecP384R1.name()
    }
}

pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&X25519, &SecP256R1, &SecP384R1];
