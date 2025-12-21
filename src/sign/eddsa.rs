#[cfg(feature = "alloc")]
use alloc::{boxed::Box, format, string::ToString, sync::Arc};
use core::marker::PhantomData;

use der::asn1::ObjectIdentifier;
use pkcs8::DecodePrivateKey;
use pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use sec1::EcPrivateKey;

#[derive(Debug)]
pub struct Ed25519SigningKey {
    key: Arc<ed25519_dalek::SigningKey>,
    scheme: SignatureScheme,
}

impl TryFrom<&PrivateKeyDer<'_>> for Ed25519SigningKey {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        let pkey = match value {
            PrivateKeyDer::Pkcs8(der) => {
                ed25519_dalek::SigningKey::from_pkcs8_der(der.secret_pkcs8_der())
                    .map_err(|e| format!("failed to decrypt private key: {e}"))
            }
            PrivateKeyDer::Sec1(sec1) => {
                // Parse SEC1 ECPrivateKey and extract the raw private key bytes.
                let res = EcPrivateKey::try_from(sec1.secret_sec1_der())
                    .map_err(|e| format!("failed to parse SEC1 private key: {e}"))
                    .and_then(|ec| {
                        // If parameters are present, ensure the named curve OID is id-Ed25519 (1.3.101.112)
                        if let Some(params) = ec.parameters {
                            if let Some(oid) = params.named_curve() {
                                let ed_oid = ObjectIdentifier::new_unwrap("1.3.101.112");
                                if oid != ed_oid {
                                    return Err("not an Ed25519 key".to_string());
                                }
                            }
                        }

                        // Private key must be exactly 32 bytes for Ed25519
                        let sk = ec.private_key;
                        if sk.len() != ed25519_dalek::SECRET_KEY_LENGTH {
                            return Err("invalid Ed25519 secret length".to_string());
                        }

                        // Convert to SigningKey
                        ed25519_dalek::SigningKey::try_from(sk)
                            .map_err(|e| format!("failed to parse Ed25519 secret: {e}"))
                    });
                res
            }
            PrivateKeyDer::Pkcs1(_) => Err("ED25519 does not support PKCS#1 key".to_string()),
            _ => Err("not supported".into()),
        };
        pkey.map(|kp| Self {
            key: Arc::new(kp),
            scheme: SignatureScheme::ED25519,
        })
        .map_err(rustls::Error::General)
    }
}

impl SigningKey for Ed25519SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(super::GenericSigner {
                _marker: PhantomData,
                key: self.key.clone(),
                scheme: self.scheme,
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}
