use const_default::ConstDefault;
use core::fmt::Debug;
use core::marker::PhantomData;
use digest::{Digest, FixedOutputReset};
use pkcs1::DecodeRsaPublicKey;
use pkcs8::AssociatedOid;
use pki_types::alg_id;
use pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rsa::RsaPublicKey;
use signature::Verifier;

#[cfg(feature = "hash-sha256")]
use sha2::Sha256;
#[cfg(feature = "hash-sha384")]
use sha2::Sha384;
#[cfg(feature = "hash-sha512")]
use sha2::Sha512;

pub trait RsaHash: Digest + FixedOutputReset + AssociatedOid + Debug + Send + Sync {
    const PKCS1_ALG_ID: AlgorithmIdentifier;
    const PSS_ALG_ID: AlgorithmIdentifier;
}

#[cfg(feature = "hash-sha256")]
impl RsaHash for Sha256 {
    const PKCS1_ALG_ID: AlgorithmIdentifier = alg_id::RSA_PKCS1_SHA256;
    const PSS_ALG_ID: AlgorithmIdentifier = alg_id::RSA_PSS_SHA256;
}

#[cfg(feature = "hash-sha384")]
impl RsaHash for Sha384 {
    const PKCS1_ALG_ID: AlgorithmIdentifier = alg_id::RSA_PKCS1_SHA384;
    const PSS_ALG_ID: AlgorithmIdentifier = alg_id::RSA_PSS_SHA384;
}

#[cfg(feature = "hash-sha512")]
impl RsaHash for Sha512 {
    const PKCS1_ALG_ID: AlgorithmIdentifier = alg_id::RSA_PKCS1_SHA512;
    const PSS_ALG_ID: AlgorithmIdentifier = alg_id::RSA_PSS_SHA512;
}

pub trait RsaScheme {
    type VerifyingKey<H: RsaHash>;
    type Signature: for<'a> TryFrom<&'a [u8], Error = signature::Error>;

    fn signature_alg_id<H: RsaHash>() -> AlgorithmIdentifier;
    fn new_verifying_key<H: RsaHash>(public_key: rsa::RsaPublicKey) -> Self::VerifyingKey<H>;
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

#[derive(Debug, ConstDefault)]
pub struct RsaVerifier<H: RsaHash, S: RsaScheme> {
    _phantom: PhantomData<(H, S)>,
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

/// Macro to generate RSA verifier constants
macro_rules! rsa_const {
    ($name:ident, $hash:ident, $scheme:ident, $rsa_feat:literal, $hash_feat:literal) => {
        #[cfg(all(feature = $rsa_feat, feature = $hash_feat))]
        pub const $name: &dyn SignatureVerificationAlgorithm =
            &RsaVerifier::<$hash, $scheme>::DEFAULT;
    };
}

// PKCS1 constants
rsa_const!(RSA_PKCS1_SHA256, Sha256, Pkcs1, "rsa-pkcs1", "hash-sha256");
rsa_const!(RSA_PKCS1_SHA384, Sha384, Pkcs1, "rsa-pkcs1", "hash-sha384");
rsa_const!(RSA_PKCS1_SHA512, Sha512, Pkcs1, "rsa-pkcs1", "hash-sha512");

// PSS constants
rsa_const!(RSA_PSS_SHA256, Sha256, Pss, "rsa-pss", "hash-sha256");
rsa_const!(RSA_PSS_SHA384, Sha384, Pss, "rsa-pss", "hash-sha384");
rsa_const!(RSA_PSS_SHA512, Sha512, Pss, "rsa-pss", "hash-sha512");
