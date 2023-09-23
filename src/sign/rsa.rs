use alloc::{boxed::Box, sync::Arc};

use pkcs8::{self, DecodePrivateKey};
use pki_types::PrivateKeyDer;
use rsa::{pkcs1::DecodeRsaPrivateKey, RsaPrivateKey};
use rustls::{
    sign::{Signer, SigningKey},
    SignatureAlgorithm, SignatureScheme,
};
use sha2::{Sha256, Sha384, Sha512};

const ALL_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

pub struct RsaSigningKey(RsaPrivateKey);

impl TryFrom<PrivateKeyDer<'_>> for RsaSigningKey {
    type Error = rustls::Error;

    fn try_from(value: PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        let pkey = match value {
            PrivateKeyDer::Pkcs8(der) => {
                RsaPrivateKey::from_pkcs8_der(der.secret_pkcs8_der())
                    .map_err(|e| format!("failed to decrypt private key: {e}"))
            }
            PrivateKeyDer::Pkcs1(der) => {
                RsaPrivateKey::from_pkcs1_der(der.secret_pkcs1_der())
                    .map_err(|e| format!("failed to decrypt private key: {e}"))
            }
            _ => todo!(),
        };

        pkey.map(Self).map_err(rustls::Error::General)
    }
}

impl SigningKey for RsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let find = ALL_RSA_SCHEMES
            .iter()
            .find(|scheme| offered.contains(scheme));

        match find {
            Some(scheme) => {
                let pkey = self.0.clone();

                macro_rules! signer {
                    ($key:ty) => {
                        Some(Box::new(super::GenericRandomizedSigner {
                            _marker: Default::default(),
                            key:     Arc::new(<$key>::new(pkey)),
                            scheme:  *scheme,
                        }))
                    };
                }

                match scheme {
                    SignatureScheme::RSA_PSS_SHA512 => signer! {rsa::pss::SigningKey::<Sha512>},
                    SignatureScheme::RSA_PSS_SHA384 => signer! {rsa::pss::SigningKey::<Sha384>},
                    SignatureScheme::RSA_PSS_SHA256 => signer! {rsa::pss::SigningKey::<Sha256>},
                    SignatureScheme::RSA_PKCS1_SHA512 => {
                        signer! {rsa::pkcs1v15::SigningKey::<Sha512>}
                    }
                    SignatureScheme::RSA_PKCS1_SHA384 => {
                        signer! {rsa::pkcs1v15::SigningKey::<Sha384>}
                    }
                    SignatureScheme::RSA_PKCS1_SHA256 => {
                        signer! {rsa::pkcs1v15::SigningKey::<Sha256>}
                    }
                    _ => None,
                }
            }
            None => None,
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}
