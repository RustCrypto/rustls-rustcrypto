#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use crypto::{SharedSecret, SupportedKxGroup};
use crypto_common::Generate;
use getrandom::rand_core::UnwrapErr;
use paste::paste;
use rustls::crypto;

#[derive(Debug)]
pub struct X25519;

impl crypto::SupportedKxGroup for X25519 {
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }

    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let mut rng = UnwrapErr(getrandom::SysRng);
        let priv_key = x25519_dalek::EphemeralSecret::random_from_rng(&mut rng);
        let pub_key = (&priv_key).into();
        Ok(Box::new(X25519KeyExchange { priv_key, pub_key }))
    }
}

pub struct X25519KeyExchange {
    priv_key: x25519_dalek::EphemeralSecret,
    pub_key: x25519_dalek::PublicKey,
}

impl crypto::ActiveKeyExchange for X25519KeyExchange {
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

#[derive(Debug)]
pub struct X448;

impl crypto::SupportedKxGroup for X448 {
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X448
    }

    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let mut rng = UnwrapErr(getrandom::SysRng);
        let priv_key = x448::EphemeralSecret::try_generate_from_rng(&mut rng)
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        let pub_key = (&priv_key).into();
        Ok(Box::new(X448KeyExchange { priv_key, pub_key }))
    }
}

pub struct X448KeyExchange {
    priv_key: x448::EphemeralSecret,
    pub_key: x448::PublicKey,
}

impl crypto::ActiveKeyExchange for X448KeyExchange {
    fn complete(self: Box<X448KeyExchange>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer = x448::PublicKey::from_bytes(peer)
            .ok_or_else(|| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        Ok(self.priv_key.diffie_hellman(&peer).as_bytes()[..].into())
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_bytes()
    }

    fn group(&self) -> rustls::NamedGroup {
        X448.name()
    }
}

macro_rules! impl_kx {
    ($name:ident, $kx_name:ty, $secret:ty, $public_key:ty) => {
        paste! {

            #[derive(Debug)]
            #[allow(non_camel_case_types)]
            pub struct $name;

            impl crypto::SupportedKxGroup for $name {
                fn name(&self) -> rustls::NamedGroup {
                    $kx_name
                }

                fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
                    let mut rng = UnwrapErr(getrandom::SysRng);
                    let priv_key = <$secret>::try_generate_from_rng(&mut rng).map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
                    let pub_key: $public_key = (&priv_key).into();
                    Ok(Box::new([<$name KeyExchange>] {
                        priv_key,
                        pub_key: pub_key.to_sec1_bytes(),
                    }))
                }
            }

            #[allow(non_camel_case_types)]
            pub struct [<$name KeyExchange>] {
                priv_key: $secret,
                pub_key:  Box<[u8]>,
            }

            impl crypto::ActiveKeyExchange for [<$name KeyExchange>] {
                fn complete(
                    self: Box<[<$name KeyExchange>]>,
                    peer: &[u8],
                ) -> Result<SharedSecret, rustls::Error> {
                    let their_pub = $public_key::from_sec1_bytes(peer)
                        .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
                    Ok(self
                        .priv_key
                        .diffie_hellman(&their_pub)
                        .raw_secret_bytes()
                        .as_slice()
                        .into())
                }

                fn pub_key(&self) -> &[u8] {
                    &self.pub_key
                }

                fn group(&self) -> rustls::NamedGroup {
                    $name.name()
                }
            }
        }
    };
}

impl_kx! {SecP256R1, rustls::NamedGroup::secp256r1, p256::ecdh::EphemeralSecret, p256::PublicKey}
impl_kx! {SecP384R1, rustls::NamedGroup::secp384r1, p384::ecdh::EphemeralSecret, p384::PublicKey}
impl_kx! {SecP521R1, rustls::NamedGroup::secp521r1, p521::ecdh::EphemeralSecret, p521::PublicKey}

pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] =
    &[&X25519, &X448, &SecP256R1, &SecP384R1, &SecP521R1];
