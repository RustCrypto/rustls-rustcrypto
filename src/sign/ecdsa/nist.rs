#[cfg(feature = "alloc")]
use alloc::{boxed::Box, format, sync::Arc};
use core::fmt::Debug;
use core::marker::PhantomData;

use crate::sign::rand::GenericRandomizedSigner;
use rustls::sign::SigningKey;
use rustls::{SignatureAlgorithm, SignatureScheme};

#[cfg(feature = "der")]
use ::pki_types::PrivateKeyDer;

trait EcdsaKey: Sized {
    const SCHEME: SignatureScheme;
}

#[cfg(all(feature = "pkcs8", not(feature = "sec1")))]
trait DecodePrivateKey: ::pkcs8::DecodePrivateKey {}

#[cfg(all(feature = "sec1", not(feature = "pkcs8")))]
trait DecodePrivateKey: ::sec1::DecodeEcPrivateKey {}

#[cfg(all(feature = "pkcs8", feature = "sec1"))]
trait DecodePrivateKey: ::pkcs8::DecodePrivateKey + ::sec1::DecodeEcPrivateKey {}

#[cfg(feature = "der")]
impl<SecretKey, SigningKey, Signature> TryFrom<&PrivateKeyDer<'_>>
    for EcdsaSigningKey<SecretKey, SigningKey, Signature>
where
    SecretKey: Debug + DecodePrivateKey,
    SigningKey: EcdsaKey + Send + Sync + 'static + From<SecretKey>,
    Signature: Send + Sync + 'static,
{
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        let pkey = match value {
            #[cfg(feature = "pkcs8")]
            PrivateKeyDer::Pkcs8(der) => SecretKey::from_pkcs8_der(der.secret_pkcs8_der())
                .map_err(|e| format!("failed to decrypt private key: {e}")),
            #[cfg(feature = "sec1")]
            PrivateKeyDer::Sec1(sec1) => SecretKey::from_sec1_der(sec1.secret_sec1_der())
                .map_err(|e| format!("failed to decrypt private key: {e}")),
            PrivateKeyDer::Pkcs1(_) => Err("ECDSA does not support PKCS#1 key".into()),
            _ => Err("not supported".into()),
        };
        pkey.map(|kp| Self {
            key: Arc::new(kp.into()),
            scheme: SigningKey::SCHEME,
            _phantom: PhantomData,
            _phantom_sk: PhantomData,
        })
        .map_err(rustls::Error::General)
    }
}

#[derive(Debug)]
pub struct EcdsaSigningKey<SecretKey, SK, SIG> {
    key: Arc<SK>,
    scheme: SignatureScheme,
    _phantom: PhantomData<SIG>,
    _phantom_sk: PhantomData<SecretKey>,
}

impl<SecretKey, SK, SIG> SigningKey for EcdsaSigningKey<SecretKey, SK, SIG>
where
    SecretKey: Debug + Send + Sync,
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

macro_rules! impl_ecdsa_curve {
    ($curve:ident, $scheme:expr, $type_name:ident) => {
        pub type $type_name = EcdsaSigningKey<
            ::$curve::SecretKey,
            ::$curve::ecdsa::SigningKey,
            ::$curve::ecdsa::DerSignature,
        >;

        impl EcdsaKey for ::$curve::ecdsa::SigningKey {
            const SCHEME: SignatureScheme = $scheme;
        }

        impl DecodePrivateKey for ::$curve::SecretKey {}
    };
}

#[cfg(all(feature = "ecdsa-p256", feature = "hash-sha256"))]
impl_ecdsa_curve!(
    p256,
    SignatureScheme::ECDSA_NISTP256_SHA256,
    EcdsaSigningKeyP256
);

#[cfg(all(feature = "ecdsa-p384", feature = "hash-sha384"))]
impl_ecdsa_curve!(
    p384,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    EcdsaSigningKeyP384
);

#[cfg(all(feature = "ecdsa-p521", feature = "hash-sha512"))]
impl_ecdsa_curve!(
    p521,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    EcdsaSigningKeyP521
);
