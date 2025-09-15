#[cfg(feature = "alloc")]
use alloc::boxed::Box;
use core::fmt::Debug;
use core::marker::PhantomData;

use crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use elliptic_curve::{
    Curve, CurveArithmetic, PublicKey,
    ecdh::EphemeralSecret,
    point::PointCompression,
    sec1::{FromEncodedPoint, ToEncodedPoint},
};
use rand_core::OsRng;
use rustls::{Error, NamedGroup, PeerMisbehaved, crypto};
use sec1::point::ModulusSize;

pub trait NistCurve: Curve + CurveArithmetic + PointCompression {
    const NAMED_GROUP: NamedGroup;
}

#[derive(Debug)]
pub struct NistKxGroup<C>(PhantomData<C>)
where
    C: NistCurve;

impl<C> NistKxGroup<C>
where
    C: NistCurve,
{
    const DEFAULT: Self = Self(PhantomData);
}

impl<C> SupportedKxGroup for NistKxGroup<C>
where
    <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
    <C as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    C: NistCurve,
{
    fn name(&self) -> NamedGroup {
        C::NAMED_GROUP
    }

    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let priv_key = EphemeralSecret::<C>::try_from_rng(&mut OsRng)
            .map_err(|_| Error::General("Failed to generate private key".into()))?;

        Ok(Box::new(NistKeyExchange::<C> {
            pub_key: priv_key.public_key().to_sec1_bytes(),
            priv_key,
        }))
    }
}

#[allow(non_camel_case_types)]
pub struct NistKeyExchange<C>
where
    C: NistCurve,
{
    priv_key: EphemeralSecret<C>,
    pub_key: Box<[u8]>,
}

impl<C> ActiveKeyExchange for NistKeyExchange<C>
where
    <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
    <C as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    C: NistCurve,
{
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let their_pub = PublicKey::<C>::from_sec1_bytes(peer)
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        Ok(self
            .priv_key
            .diffie_hellman(&their_pub)
            .raw_secret_bytes()
            .as_slice()
            .into())
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        C::NAMED_GROUP
    }
}

macro_rules! impl_nist_curve {
    ($ty:ty, $named_group:expr, $const_name:ident) => {
        impl NistCurve for $ty {
            const NAMED_GROUP: NamedGroup = $named_group;
        }

        pub const $const_name: NistKxGroup<$ty> = NistKxGroup::DEFAULT;
    };
}

#[cfg(feature = "kx-p256")]
impl_nist_curve!(::p256::NistP256, NamedGroup::secp256r1, SEC_P256_R1);

#[cfg(feature = "kx-p384")]
impl_nist_curve!(::p384::NistP384, NamedGroup::secp384r1, SEC_P384_R1);

#[cfg(feature = "kx-p521")]
impl_nist_curve!(::p521::NistP521, NamedGroup::secp521r1, SEC_P521_R1);
