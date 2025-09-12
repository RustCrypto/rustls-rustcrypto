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

// Until https://github.com/rustls/pki-types/pull/87 was released, we need to use this hack
const ED448_IDENTIFIER: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(&[0x06, 0x03, 0x2B, 0x65, 0x71]);

impl SignatureVerificationAlgorithm for Ed448Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        ED448_IDENTIFIER
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        ED448_IDENTIFIER
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
