use alloc::{boxed::Box, format, sync::Arc};

use paste::paste;
use pkcs8::DecodePrivateKey;
use pki_types::PrivateKeyDer;
use rustls::{
    sign::{Signer, SigningKey},
    SignatureAlgorithm, SignatureScheme,
};
use sec1::DecodeEcPrivateKey;
use signature::{RandomizedSigner, SignatureEncoding};

macro_rules! impl_ecdsa {
    ($name: ident, $scheme: expr, $signing_key: ty, $signature: ty) => {
        paste! {
            pub struct [<EcdsaSigningKey $name>] {
                key:    Arc<$signing_key>,
                scheme: SignatureScheme,
            }

            impl TryFrom<PrivateKeyDer<'_>> for [<EcdsaSigningKey $name>] {
                type Error = rustls::Error;

                fn try_from(value: PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
                    let pkey = match value {
                        PrivateKeyDer::Pkcs8(der) => {
                            $signing_key::from_pkcs8_der(der.secret_pkcs8_der()).map_err(|e| format!("failed to decrypt private key: {e}"))
                        },
                        PrivateKeyDer::Sec1(sec1) => {
                            $signing_key::from_sec1_der(sec1.secret_sec1_der()).map_err(|e| format!("failed to decrypt private key: {e}"))
                        },
                        _ => todo!(),
                    };
                    pkey.map(|kp| {
                        Self {
                            key:    Arc::new(kp),
                            scheme: $scheme,
                        }
                    }).map_err(rustls::Error::General)
                }
            }

            impl SigningKey for [<EcdsaSigningKey $name>] {
                fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
                    if offered.contains(&self.scheme) {
                        Some(Box::new([<EcdsaSigner $name>] {
                            key:     self.key.clone(),
                            scheme:  self.scheme,
                        }))
                    } else {
                        None
                    }
                }

                fn algorithm(&self) -> SignatureAlgorithm {
                    SignatureAlgorithm::ECDSA
                }
            }

            pub struct [<EcdsaSigner $name>] {
                key:     Arc<$signing_key>,
                scheme:  SignatureScheme,
            }

            impl Signer for [<EcdsaSigner $name>] {
                fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
                    self.key
                        .try_sign_with_rng(&mut rand_core::OsRng, message)
                        .map_err(|_| rustls::Error::General("signing failed".into()))
                        .map(|sig: $signature| sig.to_vec())
                }

                fn scheme(&self) -> SignatureScheme {
                    self.scheme
                }
            }
        }
    };
}

impl_ecdsa! {P256, SignatureScheme::ECDSA_NISTP256_SHA256, p256::ecdsa::SigningKey, p256::ecdsa::DerSignature}
impl_ecdsa! {P384, SignatureScheme::ECDSA_NISTP384_SHA384, p384::ecdsa::SigningKey, p384::ecdsa::DerSignature}
