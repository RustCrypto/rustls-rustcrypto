#[cfg(feature = "alloc")]
use alloc::{boxed::Box, sync::Arc, vec::Vec};
#[cfg(all(feature = "alloc", feature = "der"))]
use alloc::{format, string::ToString};

use ed448_goldilocks::{Signature, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme, sign::Signer};
use signature::{SignatureEncoding, Signer as SignatureSigner};

#[cfg(feature = "der")]
use pki_types::PrivateKeyDer;

// Wrapper for Ed448 signature to implement SignatureEncoding
#[derive(Debug, Clone)]
pub struct Ed448Signature(Signature);

impl SignatureEncoding for Ed448Signature {
    type Repr = [u8; 114]; // Ed448 signature is 114 bytes

    fn to_bytes(&self) -> Self::Repr {
        self.0.to_bytes()
    }

    fn encoded_len(&self) -> usize {
        114
    }
}

impl TryFrom<&[u8]> for Ed448Signature {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Signature::from_slice(bytes)
            .map(Self)
            .map_err(|_| signature::Error::new())
    }
}

impl From<Ed448Signature> for [u8; 114] {
    fn from(sig: Ed448Signature) -> Self {
        sig.0.to_bytes()
    }
}

#[derive(Debug)]
pub struct Ed448SigningKey(Arc<SigningKey>);

#[cfg(feature = "der")]
impl TryFrom<&PrivateKeyDer<'_>> for Ed448SigningKey {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        let pkey = match value {
            #[cfg(feature = "pkcs8")]
            PrivateKeyDer::Pkcs8(der) => {
                use pkcs8::DecodePrivateKey;
                SigningKey::from_pkcs8_der(der.secret_pkcs8_der())
                    .map_err(|e| format!("failed to decrypt private key: {e}"))
            }

            // Per RFC 8410, only PKCS#8 is supported for ED448 keys
            // https://datatracker.ietf.org/doc/html/rfc8410#section-7
            PrivateKeyDer::Sec1(_) => Err("ED448 does not support SEC 1 key".to_string()),
            PrivateKeyDer::Pkcs1(_) => Err("ED448 does not support PKCS#1 key".to_string()),
            _ => Err("not supported".into()),
        };
        pkey.map(|kp| Self(Arc::new(kp)))
            .map_err(rustls::Error::General)
    }
}

impl rustls::sign::SigningKey for Ed448SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        const SCHEME: SignatureScheme = SignatureScheme::ED448;
        if offered.contains(&SCHEME) {
            Some(Box::new(Ed448Signer {
                key: self.0.clone(),
                scheme: SCHEME,
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED448
    }
}

// Custom signer for Ed448
#[derive(Debug)]
pub struct Ed448Signer {
    key: Arc<SigningKey>,
    scheme: SignatureScheme,
}

impl Signer for Ed448Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let sig = self.key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
