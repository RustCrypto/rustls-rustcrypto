use alloc::{boxed::Box, sync::Arc};

use pkcs8::DecodePrivateKey;
use pki_types::PrivateKeyDer;
use rustls::{
    sign::{Signer, SigningKey},
    SignatureAlgorithm, SignatureScheme,
};
use sec1::DecodeEcPrivateKey;

#[derive(Debug)]
pub struct Ed25519SigningKey {
    key:    Arc<ed25519_dalek::SigningKey>,
    scheme: SignatureScheme,
}

impl TryFrom<&PrivateKeyDer<'_>> for Ed25519SigningKey {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                ed25519_dalek::SigningKey::from_pkcs8_der(der.secret_pkcs8_der())
                    .map(|kp| {
                        Self {
                            key:    Arc::new(kp),
                            scheme: SignatureScheme::ED25519,
                        }
                    })
                    .map_err(|_| ())
            }
            PrivateKeyDer::Sec1(der) => {
                ed25519_dalek::SigningKey::from_sec1_der(der.secret_sec1_der())
                    .map(|kp| {
                        Self {
                            key:    Arc::new(kp),
                            scheme: SignatureScheme::ED25519,
                        }
                    })
                    .map_err(|_| ())
            }
            _ => Err(()),
        }
        .map_err(|_| rustls::Error::General("invalid private key".into()))
    }
}

impl SigningKey for Ed25519SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(super::GenericSigner {
                _marker: Default::default(),
                key:     self.key.clone(),
                scheme:  self.scheme,
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}
