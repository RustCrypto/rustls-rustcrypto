use core::{marker::PhantomData, ops::Add};

use ecdsa::{
    der::{MaxOverhead, MaxSize},
    hazmat::{DigestPrimitive, VerifyPrimitive},
    PrimeCurve, SignatureSize,
};
use elliptic_curve::{
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    AffinePoint, CurveArithmetic, FieldBytesSize,
};
use generic_array::ArrayLength;
use pkcs8::AssociatedOid;
use pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use sha2::{Digest, Sha256, Sha384};
use signature::Verifier;
use webpki::alg_id;

use super::{PublicKeyAlgId, SignatureAlgId};

pub const ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm =
    &EcdsaVerify::<p256::ecdsa::Signature, Sha256>::DEFAULT;
pub const ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm =
    &EcdsaVerify::<p256::ecdsa::Signature, Sha384>::DEFAULT;
pub const ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm =
    &EcdsaVerify::<p384::ecdsa::Signature, Sha256>::DEFAULT;
pub const ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm =
    &EcdsaVerify::<p384::ecdsa::Signature, Sha384>::DEFAULT;

struct EcdsaVerify<C, D>(PhantomData<C>, PhantomData<D>);

impl<C, D> EcdsaVerify<C, D> {
    pub const DEFAULT: Self = Self(PhantomData, PhantomData);
}

impl<Digest> PublicKeyAlgId for EcdsaVerify<p256::ecdsa::Signature, Digest> {
    const PUBLIC_KEY_ALGO_ID: AlgorithmIdentifier = alg_id::ECDSA_P256;
}

impl<Digest> PublicKeyAlgId for EcdsaVerify<p384::ecdsa::Signature, Digest> {
    const PUBLIC_KEY_ALGO_ID: AlgorithmIdentifier = alg_id::ECDSA_P384;
}

impl<Signature> SignatureAlgId for EcdsaVerify<Signature, Sha256> {
    const SIG_ALGO_ID: AlgorithmIdentifier = alg_id::ECDSA_SHA256;
}

impl<Signature> SignatureAlgId for EcdsaVerify<Signature, Sha384> {
    const SIG_ALGO_ID: AlgorithmIdentifier = alg_id::ECDSA_SHA384;
}

impl<Curve, D> SignatureVerificationAlgorithm for EcdsaVerify<ecdsa::Signature<Curve>, D>
where
    Curve: PrimeCurve + CurveArithmetic + DigestPrimitive + Send + Sync,
    D: Digest + AssociatedOid + Send + Sync,
    SignatureSize<Curve>: ArrayLength<u8>,
    MaxSize<Curve>: ArrayLength<u8>,
    AffinePoint<Curve>: VerifyPrimitive<Curve> + FromEncodedPoint<Curve> + ToEncodedPoint<Curve>,
    FieldBytesSize<Curve>: ModulusSize,
    <FieldBytesSize<Curve> as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
    EcdsaVerify<ecdsa::Signature<Curve>, D>: SignatureAlgId + PublicKeyAlgId,
{
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        Self::PUBLIC_KEY_ALGO_ID
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        Self::SIG_ALGO_ID
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let signature =
            ecdsa::Signature::<Curve>::from_der(signature).map_err(|_| InvalidSignature)?;
        ecdsa::VerifyingKey::<Curve>::from_sec1_bytes(public_key)
            .map_err(|_| InvalidSignature)?
            .verify(message, &signature)
            .map_err(|_| InvalidSignature)
    }
}
