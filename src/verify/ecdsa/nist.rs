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
use const_default::ConstDefault;
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

#[derive(Debug, ConstDefault)]
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
        let digest = &H::digest(&message);
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

#[cfg(feature = "ecdsa-p256")]
impl EcdsaCurveAlgId for ::p256::NistP256 {
    const PUBLIC_KEY_ALG_ID: AlgorithmIdentifier = alg_id::ECDSA_P256;
}

#[cfg(feature = "ecdsa-p384")]
impl EcdsaCurveAlgId for ::p384::NistP384 {
    const PUBLIC_KEY_ALG_ID: AlgorithmIdentifier = alg_id::ECDSA_P384;
}

#[cfg(feature = "ecdsa-p521")]
impl EcdsaCurveAlgId for ::p521::NistP521 {
    const PUBLIC_KEY_ALG_ID: AlgorithmIdentifier = alg_id::ECDSA_P521;
}

#[cfg(feature = "hash-sha256")]
impl EcdsaHashAlgId for ::sha2::Sha256 {
    const SIGNATURE_ALG_ID: AlgorithmIdentifier = alg_id::ECDSA_SHA256;
}

#[cfg(feature = "hash-sha384")]
impl EcdsaHashAlgId for ::sha2::Sha384 {
    const SIGNATURE_ALG_ID: AlgorithmIdentifier = alg_id::ECDSA_SHA384;
}

#[cfg(feature = "hash-sha512")]
impl EcdsaHashAlgId for ::sha2::Sha512 {
    const SIGNATURE_ALG_ID: AlgorithmIdentifier = alg_id::ECDSA_SHA512;
}

/// Macro to generate ECDSA verifier constants
macro_rules! ecdsa_const {
    ($name:ident, $curve:path, $hash:path, $ecdsa_feat:literal, $hash_feat:literal) => {
        #[cfg(all(feature = $ecdsa_feat, feature = $hash_feat))]
        pub const $name: &dyn SignatureVerificationAlgorithm =
            &EcdsaVerifier::<$curve, $hash>::DEFAULT;
    };
}

// P-256 curve constants
ecdsa_const!(
    ECDSA_P256_SHA256,
    ::p256::NistP256,
    ::sha2::Sha256,
    "ecdsa-p256",
    "hash-sha256"
);
ecdsa_const!(
    ECDSA_P256_SHA384,
    ::p256::NistP256,
    ::sha2::Sha384,
    "ecdsa-p256",
    "hash-sha384"
);
ecdsa_const!(
    ECDSA_P256_SHA512,
    ::p256::NistP256,
    ::sha2::Sha512,
    "ecdsa-p256",
    "hash-sha512"
);

// P-384 curve constants
ecdsa_const!(
    ECDSA_P384_SHA256,
    ::p384::NistP384,
    ::sha2::Sha256,
    "ecdsa-p384",
    "hash-sha256"
);
ecdsa_const!(
    ECDSA_P384_SHA384,
    ::p384::NistP384,
    ::sha2::Sha384,
    "ecdsa-p384",
    "hash-sha384"
);
ecdsa_const!(
    ECDSA_P384_SHA512,
    ::p384::NistP384,
    ::sha2::Sha512,
    "ecdsa-p384",
    "hash-sha512"
);

// P-521 curve constants
ecdsa_const!(
    ECDSA_P521_SHA256,
    ::p521::NistP521,
    ::sha2::Sha256,
    "ecdsa-p521",
    "hash-sha256"
);
ecdsa_const!(
    ECDSA_P521_SHA384,
    ::p521::NistP521,
    ::sha2::Sha384,
    "ecdsa-p521",
    "hash-sha384"
);
ecdsa_const!(
    ECDSA_P521_SHA512,
    ::p521::NistP521,
    ::sha2::Sha512,
    "ecdsa-p521",
    "hash-sha512"
);
