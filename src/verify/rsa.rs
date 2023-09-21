use core::marker::PhantomData;

use der::Reader;
use pkcs8::AssociatedOid;
use pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rsa::{pkcs1v15, pss, BigUint, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384, Sha512};
use signature::Verifier;
use webpki::alg_id;

use super::{PublicKeyAlgId, SignatureAlgId};

pub const RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm =
    &RsaVerify::<pkcs1v15::Signature, pkcs1v15::VerifyingKey<Sha256>>::DEFAULT;
pub const RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm =
    &RsaVerify::<pkcs1v15::Signature, pkcs1v15::VerifyingKey<Sha384>>::DEFAULT;
pub const RSA_PKCS1_SHA512: &dyn SignatureVerificationAlgorithm =
    &RsaVerify::<pkcs1v15::Signature, pkcs1v15::VerifyingKey<Sha512>>::DEFAULT;
pub const RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm =
    &RsaVerify::<pss::Signature, pss::VerifyingKey<Sha256>>::DEFAULT;
pub const RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm =
    &RsaVerify::<pss::Signature, pss::VerifyingKey<Sha384>>::DEFAULT;
pub const RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm =
    &RsaVerify::<pss::Signature, pss::VerifyingKey<Sha512>>::DEFAULT;

struct RsaVerify<Signature, VerifyingKey>(PhantomData<Signature>, PhantomData<VerifyingKey>);

impl<Signature, VerifyingKey> RsaVerify<Signature, VerifyingKey> {
    pub const DEFAULT: Self = Self(PhantomData, PhantomData);
}

impl<Signature, VerifiyingKey> PublicKeyAlgId for RsaVerify<Signature, VerifiyingKey> {
    const PUBLIC_KEY_ALGO_ID: AlgorithmIdentifier = alg_id::RSA_ENCRYPTION;
}

impl<Signature> SignatureAlgId for RsaVerify<Signature, pkcs1v15::VerifyingKey<Sha256>> {
    const SIG_ALGO_ID: AlgorithmIdentifier = alg_id::RSA_PKCS1_SHA256;
}

impl<Signature> SignatureAlgId for RsaVerify<Signature, pkcs1v15::VerifyingKey<Sha384>> {
    const SIG_ALGO_ID: AlgorithmIdentifier = alg_id::RSA_PKCS1_SHA384;
}

impl<Signature> SignatureAlgId for RsaVerify<Signature, pkcs1v15::VerifyingKey<Sha512>> {
    const SIG_ALGO_ID: AlgorithmIdentifier = alg_id::RSA_PKCS1_SHA512;
}

impl<Signature> SignatureAlgId for RsaVerify<Signature, pss::VerifyingKey<Sha256>> {
    const SIG_ALGO_ID: AlgorithmIdentifier = alg_id::RSA_PSS_SHA256;
}

impl<Signature> SignatureAlgId for RsaVerify<Signature, pss::VerifyingKey<Sha384>> {
    const SIG_ALGO_ID: AlgorithmIdentifier = alg_id::RSA_PSS_SHA384;
}

impl<Signature> SignatureAlgId for RsaVerify<Signature, pss::VerifyingKey<Sha512>> {
    const SIG_ALGO_ID: AlgorithmIdentifier = alg_id::RSA_PSS_SHA512;
}

impl<D> SignatureVerificationAlgorithm for RsaVerify<pkcs1v15::Signature, pkcs1v15::VerifyingKey<D>>
where
    D: Digest + AssociatedOid + Send + Sync,
    RsaVerify<pkcs1v15::Signature, pkcs1v15::VerifyingKey<D>>: SignatureAlgId + PublicKeyAlgId,
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
        let public_key = decode_spki_spk(public_key)?;
        let signature = pkcs1v15::Signature::try_from(signature).map_err(|_| InvalidSignature)?;
        pkcs1v15::VerifyingKey::<D>::new(public_key)
            .verify(message, &signature)
            .map_err(|_| InvalidSignature)
    }
}

impl<D> SignatureVerificationAlgorithm for RsaVerify<rsa::pss::Signature, pss::VerifyingKey<D>>
where
    D: Digest + AssociatedOid + Send + Sync,
    RsaVerify<rsa::pss::Signature, pss::VerifyingKey<D>>: SignatureAlgId + PublicKeyAlgId,
    rsa::pss::VerifyingKey<D>: Verifier<rsa::pss::Signature>,
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
        let public_key = decode_spki_spk(public_key)?;
        let signature = pss::Signature::try_from(signature).map_err(|_| InvalidSignature)?;
        pss::VerifyingKey::<D>::new(public_key)
            .verify(message, &signature)
            .map_err(|_| InvalidSignature)
    }
}

fn decode_spki_spk(spki_spk: &[u8]) -> Result<RsaPublicKey, InvalidSignature> {
    // public_key: unfortunately this is not a whole SPKI, but just the key
    // material. decode the two integers manually.
    let mut reader = der::SliceReader::new(spki_spk).map_err(|_| InvalidSignature)?;
    let ne: [der::asn1::UintRef; 2] = reader.decode().map_err(|_| InvalidSignature)?;

    RsaPublicKey::new(
        BigUint::from_bytes_be(ne[0].as_bytes()),
        BigUint::from_bytes_be(ne[1].as_bytes()),
    )
    .map_err(|_| InvalidSignature)
}
