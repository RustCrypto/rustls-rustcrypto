#[cfg(feature = "alloc")]
use alloc::{boxed::Box, format, string::ToString, sync::Arc};
use core::marker::PhantomData;
use ed25519_dalek::SigningKey;
use rustls::{sign::Signer, SignatureAlgorithm, SignatureScheme};

use pkcs8::DecodePrivateKey;
use pki_types::PrivateKeyDer;
use sec1::DecodeEcPrivateKey;

use crate::sign::GenericSigner;

#[derive(Debug)]
pub struct Ed25519SigningKey(Arc<SigningKey>);

impl TryFrom<&PrivateKeyDer<'_>> for Ed25519SigningKey {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        let pkey = match value {
            PrivateKeyDer::Pkcs8(der) => SigningKey::from_pkcs8_der(der.secret_pkcs8_der())
                .map_err(|e| format!("failed to decrypt private key: {e}")),
            PrivateKeyDer::Sec1(sec1) => SigningKey::from_sec1_der(sec1.secret_sec1_der())
                .map_err(|e| format!("failed to decrypt private key: {e}")),
            PrivateKeyDer::Pkcs1(_) => Err("ED25519 does not support PKCS#1 key".to_string()),
            _ => Err("not supported".into()),
        };
        pkey.map(|kp| Self(Arc::new(kp)))
            .map_err(rustls::Error::General)
    }
}

impl rustls::sign::SigningKey for Ed25519SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        const SCHEME: SignatureScheme = SignatureScheme::ED25519;
        if offered.contains(&SCHEME) {
            Some(Box::new(GenericSigner {
                _marker: PhantomData,
                key: self.0.clone(),
                scheme: SCHEME,
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}
