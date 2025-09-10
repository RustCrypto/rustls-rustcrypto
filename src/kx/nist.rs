#[cfg(all(feature = "alloc", feature = "kx-nist"))]
use alloc::boxed::Box;

#[cfg(feature = "kx-nist")]
use core::marker::PhantomData;

#[cfg(feature = "kx-nist")]
use rustls::{Error, NamedGroup, PeerMisbehaved, crypto};

#[cfg(feature = "kx-nist")]
use crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};

#[cfg(feature = "kx-nist")]
use elliptic_curve::{
    Curve, CurveArithmetic, PublicKey,
    ecdh::EphemeralSecret,
    point::PointCompression,
    sec1::{FromEncodedPoint, ToEncodedPoint},
};

#[cfg(feature = "kx-nist")]
use rand_core::OsRng;

#[cfg(feature = "kx-nist")]
use sec1::point::ModulusSize;

#[cfg(feature = "kx-nist")]
use core::fmt::Debug;

#[cfg(feature = "kx-nist")]
pub trait NistCurve: Curve + CurveArithmetic + PointCompression {
    const NAMED_GROUP: NamedGroup;
}

#[cfg(all(feature = "kx-nist", feature = "kx-p256"))]
impl NistCurve for ::p256::NistP256 {
    const NAMED_GROUP: NamedGroup = NamedGroup::secp256r1;
}

#[cfg(all(feature = "kx-nist", feature = "kx-p384"))]
impl NistCurve for ::p384::NistP384 {
    const NAMED_GROUP: NamedGroup = NamedGroup::secp384r1;
}

#[cfg(all(feature = "kx-nist", feature = "kx-p521"))]
impl NistCurve for ::p521::NistP521 {
    const NAMED_GROUP: NamedGroup = NamedGroup::secp521r1;
}

#[cfg(feature = "kx-nist")]
#[derive(Debug)]
pub struct NistKxGroup<C>(PhantomData<C>)
where
    C: NistCurve;

#[cfg(feature = "kx-nist")]
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
            pub_key: priv_key.public_key().to_sec1_bytes().into(),
            priv_key,
        }))
    }
}

#[cfg(feature = "kx-nist")]
#[allow(non_camel_case_types)]
pub struct NistKeyExchange<C>
where
    C: NistCurve,
{
    priv_key: EphemeralSecret<C>,
    pub_key: Box<[u8]>,
}

#[cfg(feature = "kx-nist")]
impl<C: NistCurve> ActiveKeyExchange for NistKeyExchange<C>
where
    <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C>,
    <C as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C>,
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

#[cfg(feature = "kx-p256")]
pub const SEC_P256_R1: NistKxGroup<::p256::NistP256> = NistKxGroup(PhantomData);

#[cfg(feature = "kx-p384")]
pub const SEC_P384_R1: NistKxGroup<::p384::NistP384> = NistKxGroup(PhantomData);

#[cfg(feature = "kx-p521")]
pub const SEC_P521_R1: NistKxGroup<::p521::NistP521> = NistKxGroup(PhantomData);
