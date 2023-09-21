use core::marker::PhantomData;

use pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use signature::Verifier;
use webpki::alg_id;

use super::{PublicKeyAlgId, SignatureAlgId};

pub const ED25519: &dyn SignatureVerificationAlgorithm =
    &EddsaVerify::<ed25519_dalek::Signature>::DEFAULT;

struct EddsaVerify<Signature>(PhantomData<Signature>);

impl<Signature> EddsaVerify<Signature> {
    pub const DEFAULT: Self = Self(PhantomData);
}

impl PublicKeyAlgId for EddsaVerify<ed25519_dalek::Signature> {
    const PUBLIC_KEY_ALGO_ID: AlgorithmIdentifier = alg_id::ED25519;
}

impl SignatureAlgId for EddsaVerify<ed25519_dalek::Signature> {
    const SIG_ALGO_ID: AlgorithmIdentifier = alg_id::ED25519;
}

impl SignatureVerificationAlgorithm for EddsaVerify<ed25519_dalek::Signature> {
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
        let public_key = public_key.try_into().map_err(|_| InvalidSignature)?;
        let signature =
            ed25519_dalek::Signature::from_slice(signature).map_err(|_| InvalidSignature)?;
        ed25519_dalek::VerifyingKey::from_bytes(public_key)
            .map_err(|_| InvalidSignature)?
            .verify(message, &signature)
            .map_err(|_| InvalidSignature)
    }
}
