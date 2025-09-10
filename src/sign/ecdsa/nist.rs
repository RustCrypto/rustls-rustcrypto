#[cfg(feature = "alloc")]
use alloc::{boxed::Box, format, sync::Arc};
use core::fmt::Debug;
use core::marker::PhantomData;

// #[cfg(feature = "sec1")]
// use sec1::DecodeEcPrivateKey;

use crate::sign::rand::GenericRandomizedSigner;
use rustls::sign::SigningKey;
use rustls::{SignatureAlgorithm, SignatureScheme};

#[cfg(feature = "der")]
use ::pki_types::PrivateKeyDer;

trait EcdsaKey: Sized {
    const SCHEME: SignatureScheme;
}

// #[cfg(all(feature = "pkcs8", not(feature = "sec1")))]
// trait DecodePrivateKey: ::pkcs8::DecodePrivateKey {}

// #[cfg(all(feature = "sec1", not(feature = "pkcs8")))]
// trait DecodePrivateKey: ::sec1::DecodeEcPrivateKey {}

// #[cfg(all(feature = "pkcs8", feature = "sec1"))]
// trait DecodePrivateKey: ::pkcs8::DecodePrivateKey + ::sec1::DecodeEcPrivateKey {}

#[cfg(feature = "der")]
impl<SK, SIG> TryFrom<&PrivateKeyDer<'_>> for EcdsaSigningKey<SK, SIG>
where
    SK: EcdsaKey + ::pkcs8::DecodePrivateKey + Send + Sync + 'static,
    SIG: Send + Sync + 'static,
{
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        let pkey = match value {
            #[cfg(feature = "pkcs8")]
            PrivateKeyDer::Pkcs8(der) => SK::from_pkcs8_der(der.secret_pkcs8_der())
                .map_err(|e| format!("failed to decrypt private key: {e}")),
            // #[cfg(feature = "sec1")]
            // PrivateKeyDer::Sec1(sec1) => SK::from_sec1_der(sec1.secret_sec1_der())
            //     .map_err(|e| format!("failed to decrypt private key: {e}")),
            PrivateKeyDer::Pkcs1(_) => Err(format!("ECDSA does not support PKCS#1 key")),
            _ => Err("not supported".into()),
        };
        pkey.map(|kp| Self {
            key: Arc::new(kp),
            scheme: SK::SCHEME,
            _phantom: PhantomData,
        })
        .map_err(rustls::Error::General)
    }
}

#[derive(Debug)]
pub struct EcdsaSigningKey<SK, SIG> {
    key: Arc<SK>,
    scheme: SignatureScheme,
    _phantom: PhantomData<SIG>,
}

impl<SK, SIG> SigningKey for EcdsaSigningKey<SK, SIG>
where
    SK: Send + Sync + 'static + Debug + ecdsa::signature::RandomizedSigner<SIG>,
    SIG: Send + Sync + 'static + Debug + ecdsa::signature::SignatureEncoding,
{
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(GenericRandomizedSigner::<SIG, SK> {
                _marker: PhantomData,
                key: self.key.clone(),
                scheme: self.scheme,
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

#[cfg(feature = "ecdsa-p256")]
pub type EcdsaSigningKeyP256 =
    EcdsaSigningKey<::p256::ecdsa::SigningKey, ::p256::ecdsa::DerSignature>;

#[cfg(all(feature = "ecdsa-p256", feature = "hash-sha256"))]
impl EcdsaKey for ::p256::ecdsa::SigningKey {
    const SCHEME: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;
}

// #[cfg(feature = "ecdsa-p384")]
// impl DecodePrivateKey for ::p384::ecdsa::SigningKey {}

#[cfg(feature = "ecdsa-p384")]
pub type EcdsaSigningKeyP384 =
    EcdsaSigningKey<::p384::ecdsa::SigningKey, ::p384::ecdsa::DerSignature>;

#[cfg(feature = "ecdsa-p521")]
impl EcdsaKey for ::p384::ecdsa::SigningKey {
    const SCHEME: SignatureScheme = SignatureScheme::ECDSA_NISTP384_SHA384;
}

// #[cfg(feature = "ecdsa-p521")]
// impl DecodePrivateKey for ::p521::ecdsa::SigningKey {}

#[cfg(feature = "ecdsa-p521")]
pub type EcdsaSigningKeyP521 =
    EcdsaSigningKey<::p521::ecdsa::SigningKey, ::p521::ecdsa::DerSignature>;

#[cfg(all(feature = "ecdsa-p521", feature = "hash-sha512"))]
impl EcdsaKey for ::p521::ecdsa::SigningKey {
    const SCHEME: SignatureScheme = SignatureScheme::ECDSA_NISTP521_SHA512;
}
