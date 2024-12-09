#[cfg(feature = "alloc")]
use alloc::{boxed::Box, format, sync::Arc};

use crate::sign::rand::GenericRandomizedSigner;
use core::marker::PhantomData;
use paste::paste;
use rustls::sign::SigningKey;
use rustls::{SignatureAlgorithm, SignatureScheme};

#[cfg(feature = "der")]
use pki_types::PrivateKeyDer;

macro_rules! impl_ecdsa {
($name: ident, $scheme: expr, $signing_key: ty, $signature: ty) => {
    paste! {
        #[derive(Debug)]
        pub struct [<EcdsaSigningKey $name>] {
            key:    Arc<$signing_key>,
            scheme: SignatureScheme,
        }

        #[cfg(feature = "der")]
        impl TryFrom<&PrivateKeyDer<'_>> for [<EcdsaSigningKey $name>] {
            type Error = rustls::Error;

            fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
                let pkey = match value {
                    #[cfg(feature = "pkcs8")]
                    PrivateKeyDer::Pkcs8(der) => {
                        use pkcs8::DecodePrivateKey;
                        $signing_key::from_pkcs8_der(der.secret_pkcs8_der()).map_err(|e| format!("failed to decrypt private key: {e}"))
                    },
                    #[cfg(feature = "sec1")]
                    PrivateKeyDer::Sec1(sec1) => {
                        use sec1::DecodeEcPrivateKey;
                        $signing_key::from_sec1_der(sec1.secret_sec1_der()).map_err(|e| format!("failed to decrypt private key: {e}"))
                    },
                    PrivateKeyDer::Pkcs1(_) => Err(format!("ECDSA does not support PKCS#1 key")),
                    _ => Err("not supported".into()),
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
                    Some(Box::new(GenericRandomizedSigner::<$signature, _> {
                        _marker: PhantomData,
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
    }
};
}

#[cfg(all(feature = "ecdsa-p256", feature = "hash-sha256"))]
impl_ecdsa! {P256, SignatureScheme::ECDSA_NISTP256_SHA256, ::p256::ecdsa::SigningKey, ::p256::ecdsa::DerSignature}

#[cfg(all(feature = "ecdsa-p384", feature = "hash-sha384"))]
impl_ecdsa! {P384, SignatureScheme::ECDSA_NISTP384_SHA384, ::p384::ecdsa::SigningKey, ::p384::ecdsa::DerSignature}

// #[cfg(all(feature = "ecdsa-p521", feature = "hash-sha512"))]
// impl_ecdsa! {P521, SignatureScheme::ECDSA_NISTP521_SHA512, ::p521::ecdsa::SigningKey, ::p521::ecdsa::DerSignature}
