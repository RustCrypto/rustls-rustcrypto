#[cfg(all(feature = "alloc", feature = "kx-nist"))]
use alloc::boxed::Box;

#[cfg(feature = "kx-nist")]
use crypto::{SharedSecret, SupportedKxGroup};

#[cfg(feature = "kx-nist")]
use paste::paste;

#[cfg(feature = "kx-nist")]
use rustls::crypto;

#[cfg(feature = "kx-nist")]
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
                    let priv_key = $secret::random(&mut rand_core::OsRng);
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

#[cfg(feature = "kx-p256")]
impl_kx! {SecP256R1, rustls::NamedGroup::secp256r1, ::p256::ecdh::EphemeralSecret, ::p256::PublicKey}

#[cfg(feature = "kx-p384")]
impl_kx! {SecP384R1, rustls::NamedGroup::secp384r1, ::p384::ecdh::EphemeralSecret, ::p384::PublicKey}

#[cfg(feature = "kx-p521")]
impl_kx! {SecP521R1, rustls::NamedGroup::secp521r1, ::p521::ecdh::EphemeralSecret, ::p521::PublicKey}
