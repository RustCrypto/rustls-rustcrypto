use core::fmt::Debug;
use core::marker::PhantomData;
use digest::{Digest, FixedOutputReset};
use pkcs1::DecodeRsaPublicKey;
use pkcs8::AssociatedOid;
use pki_types::alg_id;
use pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rsa::RsaPublicKey;
use signature::Verifier;

pub trait RsaHash: Digest + FixedOutputReset + AssociatedOid + Debug + Send + Sync {
    const PKCS1_ALG_ID: AlgorithmIdentifier;
    const PSS_ALG_ID: AlgorithmIdentifier;
}

pub trait RsaScheme {
    type VerifyingKey<H: RsaHash>;
    type Signature: for<'a> TryFrom<&'a [u8], Error = signature::Error>;

    fn signature_alg_id<H: RsaHash>() -> AlgorithmIdentifier;
    fn new_verifying_key<H: RsaHash>(public_key: rsa::RsaPublicKey) -> Self::VerifyingKey<H>;
    /// Verifies the signature.
    ///
    /// # Errors
    /// Returns an error if the signature verification fails.
    fn verify<H: RsaHash>(
        key: &Self::VerifyingKey<H>,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), signature::Error>;
}

#[derive(Debug)]
pub struct Pkcs1;

impl RsaScheme for Pkcs1 {
    type VerifyingKey<H: RsaHash> = rsa::pkcs1v15::VerifyingKey<H>;
    type Signature = rsa::pkcs1v15::Signature;

    fn signature_alg_id<H: RsaHash>() -> AlgorithmIdentifier {
        H::PKCS1_ALG_ID
    }

    fn new_verifying_key<H: RsaHash>(public_key: rsa::RsaPublicKey) -> Self::VerifyingKey<H> {
        rsa::pkcs1v15::VerifyingKey::new(public_key)
    }

    fn verify<H: RsaHash>(
        key: &Self::VerifyingKey<H>,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), signature::Error> {
        key.verify(message, signature)
    }
}

#[derive(Debug)]
pub struct Pss;

impl RsaScheme for Pss {
    type VerifyingKey<H: RsaHash> = rsa::pss::VerifyingKey<H>;
    type Signature = rsa::pss::Signature;

    fn signature_alg_id<H: RsaHash>() -> AlgorithmIdentifier {
        H::PSS_ALG_ID
    }

    fn new_verifying_key<H: RsaHash>(public_key: rsa::RsaPublicKey) -> Self::VerifyingKey<H> {
        rsa::pss::VerifyingKey::new(public_key)
    }

    fn verify<H: RsaHash>(
        key: &Self::VerifyingKey<H>,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), signature::Error> {
        key.verify(message, signature)
    }
}

#[derive(Debug, Default)]
pub struct RsaVerifier<H: RsaHash, S: RsaScheme> {
    _phantom: PhantomData<(H, S)>,
}

impl<H: RsaHash, S: RsaScheme> RsaVerifier<H, S> {
    pub const DEFAULT: Self = Self {
        _phantom: PhantomData,
    };
}

impl<H: RsaHash, S: RsaScheme> RsaVerifier<H, S> {
    fn verify_inner(
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), crate::verify::Error> {
        let public_key = RsaPublicKey::from_pkcs1_der(public_key)?;
        let signature = <S::Signature>::try_from(signature)?;
        let key = S::new_verifying_key::<H>(public_key);
        S::verify::<H>(&key, message, &signature)?;
        Ok(())
    }
}

impl<H: RsaHash, S: RsaScheme + Debug + Send + Sync> SignatureVerificationAlgorithm
    for RsaVerifier<H, S>
{
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        S::signature_alg_id::<H>()
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

/// Macro to generate RSA hash impl and verifier constants
macro_rules! rsa_hash_and_consts {
    (
        $hash:ty,
        $pkcs1_const:ident,
        $pss_const:ident,
        $pkcs1_alg:expr,
        $pss_alg:expr,
        $hash_feat:literal
    ) => {
        #[cfg(feature = $hash_feat)]
        impl RsaHash for $hash {
            const PKCS1_ALG_ID: AlgorithmIdentifier = $pkcs1_alg;
            const PSS_ALG_ID: AlgorithmIdentifier = $pss_alg;
        }

        #[cfg(all(feature = "rsa-pkcs1", feature = $hash_feat))]
        pub const $pkcs1_const: &dyn SignatureVerificationAlgorithm =
            &RsaVerifier::<$hash, Pkcs1>::DEFAULT;

        #[cfg(all(feature = "rsa-pss", feature = $hash_feat))]
        pub const $pss_const: &dyn SignatureVerificationAlgorithm =
            &RsaVerifier::<$hash, Pss>::DEFAULT;
    };
}

rsa_hash_and_consts!(
    sha2::Sha256,
    RSA_PKCS1_SHA256,
    RSA_PSS_SHA256,
    alg_id::RSA_PKCS1_SHA256,
    alg_id::RSA_PSS_SHA256,
    "hash-sha256"
);
rsa_hash_and_consts!(
    sha2::Sha384,
    RSA_PKCS1_SHA384,
    RSA_PSS_SHA384,
    alg_id::RSA_PKCS1_SHA384,
    alg_id::RSA_PSS_SHA384,
    "hash-sha384"
);
rsa_hash_and_consts!(
    sha2::Sha512,
    RSA_PKCS1_SHA512,
    RSA_PSS_SHA512,
    alg_id::RSA_PKCS1_SHA512,
    alg_id::RSA_PSS_SHA512,
    "hash-sha512"
);
