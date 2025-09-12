use ed448_goldilocks::{Signature, VerifyingKey};
use pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use signature::Verifier;

#[derive(Debug)]
pub struct Ed448Verify;

impl Ed448Verify {
    fn verify_inner(
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), crate::verify::Error> {
        let public_key = public_key.try_into()?;
        let signature = Signature::from_slice(signature)?;
        let verifying_key = VerifyingKey::from_bytes(public_key)?;
        verifying_key.verify(message, &signature)?;
        Ok(())
    }
}

impl SignatureVerificationAlgorithm for Ed448Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        todo!()
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        todo!()
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

pub const ED448: &dyn SignatureVerificationAlgorithm = &Ed448Verify;
