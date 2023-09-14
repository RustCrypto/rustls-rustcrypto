use alloc::{boxed::Box, sync::Arc};
use core::ops::Add;
use ecdsa::{
    elliptic_curve::{
        generic_array::ArrayLength, ops::Invert, pkcs8, pkcs8::DecodePrivateKey, subtle::CtOption,
        CurveArithmetic, FieldBytesSize, Scalar,
    },
    hazmat::{DigestPrimitive, SignPrimitive},
    PrimeCurve, SignatureSize,
};
use pki_types::PrivateKeyDer;
use rustls::{sign::SigningKey, SignatureAlgorithm, SignatureScheme};

pub struct EcdsaSigningKey<C> {
    key: Arc<C>,
    scheme: SignatureScheme,
}

impl TryFrom<PrivateKeyDer<'_>> for EcdsaSigningKey<p256::ecdsa::SigningKey> {
    type Error = pkcs8::Error;

    fn try_from(value: PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                p256::ecdsa::SigningKey::from_pkcs8_der(der.secret_pkcs8_der()).map(|kp| Self {
                    key: Arc::new(kp),
                    scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
                })
            }
            _ => todo!(),
        }
    }
}

impl TryFrom<PrivateKeyDer<'_>> for EcdsaSigningKey<p384::ecdsa::SigningKey> {
    type Error = pkcs8::Error;

    fn try_from(value: PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                p384::ecdsa::SigningKey::from_pkcs8_der(der.secret_pkcs8_der()).map(|kp| Self {
                    key: Arc::new(kp),
                    scheme: SignatureScheme::ECDSA_NISTP384_SHA384,
                })
            }
            _ => todo!(),
        }
    }
}

/* TODO: Curve Arithmetic in WIP for p521
impl TryFrom<PrivateKey> for EcdsaSigningKey<p521::ecdsa::SigningKey> {
    type Error = pkcs8::Error;

    fn try_from(value: PrivateKey) -> Result<Self, Self::Error> {
        p521::ecdsa::SigningKey::from_pkcs8_der(&value.0)
            .map(|kp| Self {
                key: Arc::new(kp),
                scheme: SignatureScheme::ECDSA_NISTP521_SHA512,
            })
    }
}
*/

impl<C> SigningKey for EcdsaSigningKey<ecdsa::SigningKey<C>>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    ecdsa::der::MaxSize<C>: ArrayLength<u8>,
    <FieldBytesSize<C> as Add>::Output: Add<ecdsa::der::MaxOverhead> + ArrayLength<u8>,
{
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(super::GenericRandomizedSigner::<
                ecdsa::der::Signature<C>,
                _,
            > {
                _marker: Default::default(),
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
