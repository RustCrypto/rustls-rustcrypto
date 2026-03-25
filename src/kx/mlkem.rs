//! Wrap the FIPS203 ML-KEM algorithms as key exchange groups.
//!
//! The existence of this module _does not_ imply that it is a good
//! idea to use these as raw SupportedKxGroups.
//! Instead, using hybrid PQ handshakes is a more conservative choice.

use alloc::boxed::Box;
use crypto::SupportedKxGroup;
use ml_kem::{
    Decapsulate as _, Encapsulate as _, Kem, KeyExport as _, MlKem1024, MlKem768, TryKeyInit as _,
};
use paste::paste;
use rustls::{crypto, NamedGroup};

// From https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
const MLKEM768_ID: u16 = 513;
const MLKEM1024_ID: u16 = 514;

macro_rules! mlkem_exchange {
    { $mlkem:ty } => {
        paste! {

            #[derive(Debug)]
            pub(super) struct [< $mlkem:upper >];

            struct [< $mlkem KeyExchange >] {
                priv_key: <$mlkem as Kem>::DecapsulationKey,
                pub_key: Box<[u8]>,
            }

            impl SupportedKxGroup for [< $mlkem:upper >] {
                fn name(&self) -> rustls::NamedGroup {
                    NamedGroup::from([< $mlkem:upper _ID >])
                }

                fn usable_for_version(&self, _version: rustls::ProtocolVersion) -> bool {
                    // These groups are left disabled and unexposed for now:
                    // Even if they are someday standardized they should probably
                    // not be enabled by default for some while.
                    //
                    // version == rustls::ProtocolVersion::TLSv1_3
                    false
                }

                fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
                    let (priv_key, pub_key) = $mlkem::generate_keypair();
                    let pub_key = (pub_key).to_bytes().into();
                    Ok(Box::new([< $mlkem KeyExchange >] { priv_key, pub_key }))
                }

                fn start_and_complete(
                    &self,
                    peer: &[u8],
                ) -> Result<crypto::CompletedKeyExchange, rustls::Error> {
                    let encapsulation_key = <$mlkem as Kem>::EncapsulationKey::new_from_slice(peer)
                        .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;

                    let (ciphertext, shared_secret) = encapsulation_key.encapsulate();

                    #[cfg(feature = "zeroize")]
                    let shared_secret = zeroize::Zeroizing::new(shared_secret);

                    Ok(crypto::CompletedKeyExchange {
                        group: self.name(),
                        pub_key: ciphertext.to_vec(),
                        secret: shared_secret.as_slice().into(),
                    })
                }
            }

            impl crypto::ActiveKeyExchange for [< $mlkem KeyExchange >] {
                fn group(&self) -> NamedGroup {
                    NamedGroup::from([< $mlkem:upper _ID>])
                }

                fn pub_key(&self) -> &[u8] {
                    &self.pub_key
                }

                fn complete(self: Box<Self>, peer: &[u8]) -> Result<crypto::SharedSecret, rustls::Error> {
                    let shared_secret = self
                        .priv_key
                        .decapsulate_slice(peer)
                        .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;

                    #[cfg(feature = "zeroize")]
                    let shared_secret = zeroize::Zeroizing::new(shared_secret);

                    Ok(shared_secret.as_slice().into())
                }
            }
        }
    }
}

mlkem_exchange! { MlKem768 }
mlkem_exchange! { MlKem1024 }
