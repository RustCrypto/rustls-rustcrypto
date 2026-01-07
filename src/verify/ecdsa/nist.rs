use core::marker::PhantomData;

use ::aead::array::ArraySize;
use ::digest::Digest;
use ::ecdsa::EcdsaCurve;
use ::ecdsa::VerifyingKey;
use ::ecdsa::der::{MaxOverhead, MaxSize, Signature};
use ::elliptic_curve::ops::Add;
use ::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use ::elliptic_curve::{Curve, CurveArithmetic, FieldBytesSize};
use ::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id};
use ::sec1::point::ModulusSize;
use ::signature::hazmat::PrehashVerifier;
use core::fmt::Debug;

/// Trait for ECDSA curve algorithm identifiers.
pub trait EcdsaCurveAlgId {
    const PUBLIC_KEY_ALG_ID: AlgorithmIdentifier;
}

/// Trait for ECDSA hash algorithm identifiers.
pub trait EcdsaHashAlgId {
    const SIGNATURE_ALG_ID: AlgorithmIdentifier;
}

/// Trait to simplify generic bounds for ECDSA curve types.
pub trait EcdsaVerifierCurve<H: Digest>: EcdsaCurve + CurveArithmetic + EcdsaCurveAlgId
where
    H: EcdsaHashAlgId,
{
}

impl<H: Digest, C> EcdsaVerifierCurve<H> for C
where
    C: EcdsaCurve + CurveArithmetic + EcdsaCurveAlgId,
    H: EcdsaHashAlgId,
{
}

#[derive(Debug, Default)]
pub struct EcdsaVerifier<C, H>
where
    C: EcdsaVerifierCurve<H>,
    H: Digest + EcdsaHashAlgId,
{
    _curve: PhantomData<C>,
    _hash: PhantomData<H>,
}

impl<C, H> EcdsaVerifier<C, H>
where
    C: EcdsaVerifierCurve<H>,
    H: Digest + EcdsaHashAlgId,
{
    pub const DEFAULT: Self = Self {
        _curve: PhantomData,
        _hash: PhantomData,
    };
}

impl<C, H> EcdsaVerifier<C, H>
where
    C: EcdsaVerifierCurve<H>,
    <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
    <C as Curve>::FieldBytesSize: Debug + ModulusSize,
    MaxSize<C>: ArraySize,
    <FieldBytesSize<C> as Add>::Output: Add<MaxOverhead> + ArraySize,
    H: Digest + EcdsaHashAlgId,
{
    fn verify_inner(
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), crate::verify::Error> {
        use der::Decode;
        let signature = Signature::<C>::from_der(signature)?;
        let verifying_key = VerifyingKey::<C>::from_sec1_bytes(public_key)?;
        let digest = &H::digest(message);
        verifying_key.verify_prehash(digest, &signature)?;
        Ok(())
    }
}
impl<C, H> SignatureVerificationAlgorithm for EcdsaVerifier<C, H>
where
    C: EcdsaVerifierCurve<H>,
    <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
    <C as Curve>::FieldBytesSize: Debug + ModulusSize,
    MaxSize<C>: ArraySize,
    <FieldBytesSize<C> as Add>::Output: Add<MaxOverhead> + ArraySize,
    H: Digest + Debug + Send + Sync + EcdsaHashAlgId,
{
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        C::PUBLIC_KEY_ALG_ID
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        H::SIGNATURE_ALG_ID
    }
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        Self::verify_inner(public_key, message, signature).map_err(|_| InvalidSignature)
    }
}

/// Macro to generate all ECDSA hash impls, curve impls, and constants
macro_rules! ecdsa_setup {
    (
        hashes: $( ($hash_ty:ty, $hash_alg:expr, $hash_feat:literal) ),* $(,)? ;
        curves: $( ($curve_ty:ty, $curve_alg:expr, $curve_feat:literal, $( ($const_name:ident, $hash_for_const:ty, $hash_feat_for_const:literal) ),* $(,)? ) ),* $(,)?
    ) => {
        $(
            #[cfg(feature = $hash_feat)]
            impl EcdsaHashAlgId for $hash_ty {
                const SIGNATURE_ALG_ID: AlgorithmIdentifier = $hash_alg;
            }
        )*

        $(
            #[cfg(feature = $curve_feat)]
            impl EcdsaCurveAlgId for $curve_ty {
                const PUBLIC_KEY_ALG_ID: AlgorithmIdentifier = $curve_alg;
            }

            $(
                #[cfg(all(feature = $curve_feat, feature = $hash_feat_for_const))]
                pub const $const_name: &dyn SignatureVerificationAlgorithm =
                    &EcdsaVerifier::<$curve_ty, $hash_for_const>::DEFAULT;
            )*
        )*
    };
}

ecdsa_setup! {
    hashes:
        (::sha2::Sha256, alg_id::ECDSA_SHA256, "hash-sha256"),
        (::sha2::Sha384, alg_id::ECDSA_SHA384, "hash-sha384"),
        (::sha2::Sha512, alg_id::ECDSA_SHA512, "hash-sha512");

    curves:
        (::p256::NistP256, alg_id::ECDSA_P256, "ecdsa-p256",
            (ECDSA_P256_SHA256, ::sha2::Sha256, "hash-sha256"),
            (ECDSA_P256_SHA384, ::sha2::Sha384, "hash-sha384"),
            (ECDSA_P256_SHA512, ::sha2::Sha512, "hash-sha512")
        ),
        (::p384::NistP384, alg_id::ECDSA_P384, "ecdsa-p384",
            (ECDSA_P384_SHA256, ::sha2::Sha256, "hash-sha256"),
            (ECDSA_P384_SHA384, ::sha2::Sha384, "hash-sha384"),
            (ECDSA_P384_SHA512, ::sha2::Sha512, "hash-sha512")
        ),
        (::p521::NistP521, alg_id::ECDSA_P521, "ecdsa-p521",
            (ECDSA_P521_SHA256, ::sha2::Sha256, "hash-sha256"),
            (ECDSA_P521_SHA384, ::sha2::Sha384, "hash-sha384"),
            (ECDSA_P521_SHA512, ::sha2::Sha512, "hash-sha512")
        )
}
