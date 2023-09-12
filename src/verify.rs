use core::marker::PhantomData;

use pkcs8::AssociatedOid;
use pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rustls::{SignatureScheme, WebPkiSupportedAlgorithms};
use sha2::Digest;
use sha2::Sha256;
use sha2::Sha384;
use sha2::Sha512;
use webpki::alg_id;

use der::Reader;
use rsa::signature::Verifier;
use rsa::BigUint;
use rsa::RsaPublicKey;
use rsa::{pkcs1v15, pss};

pub static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        RSA_PSS_SHA512,
        RSA_PSS_SHA384,
        RSA_PSS_SHA256,
        RSA_PKCS1_SHA512,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA256,
    ],
    mapping: &[
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[RSA_PKCS1_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
    ],
};

static RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm = &RsaPssVerify::<Sha512>::DEFAULT;
static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm = &RsaPssVerify::<Sha384>::DEFAULT;
static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &RsaPssVerify::<Sha256>::DEFAULT;
static RSA_PKCS1_SHA512: &dyn SignatureVerificationAlgorithm = &RsaPkcs1Verify::<Sha512>::DEFAULT;
static RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm = &RsaPkcs1Verify::<Sha384>::DEFAULT;
static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &RsaPkcs1Verify::<Sha256>::DEFAULT;

trait SignatureAlgId {
    const SIG_ALGO_ID: AlgorithmIdentifier;
}

struct RsaPssVerify<D>(PhantomData<D>);

impl<D> RsaPssVerify<D> {
    pub const DEFAULT: Self = Self(PhantomData);
}

impl<D> SignatureVerificationAlgorithm for RsaPssVerify<D>
where
    D: Digest + AssociatedOid + Send + Sync,
    RsaPssVerify<D>: SignatureAlgId,
    rsa::pss::VerifyingKey<D>: Verifier<rsa::pss::Signature>,
{
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        <Self as SignatureAlgId>::SIG_ALGO_ID
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

struct RsaPkcs1Verify<D>(PhantomData<D>);

impl<D> RsaPkcs1Verify<D> {
    pub const DEFAULT: Self = Self(PhantomData);
}

impl<D> SignatureVerificationAlgorithm for RsaPkcs1Verify<D>
where
    D: Digest + AssociatedOid + Send + Sync,
    RsaPkcs1Verify<D>: SignatureAlgId,
{
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        <Self as SignatureAlgId>::SIG_ALGO_ID
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

impl SignatureAlgId for RsaPkcs1Verify<Sha512> {
    const SIG_ALGO_ID: AlgorithmIdentifier = alg_id::RSA_PKCS1_SHA512;
}

impl SignatureAlgId for RsaPkcs1Verify<Sha384> {
    const SIG_ALGO_ID: AlgorithmIdentifier = alg_id::RSA_PKCS1_SHA384;
}

impl SignatureAlgId for RsaPkcs1Verify<Sha256> {
    const SIG_ALGO_ID: AlgorithmIdentifier = alg_id::RSA_PKCS1_SHA256;
}

impl SignatureAlgId for RsaPssVerify<Sha512> {
    const SIG_ALGO_ID: AlgorithmIdentifier = alg_id::RSA_PSS_SHA512;
}

impl SignatureAlgId for RsaPssVerify<Sha384> {
    const SIG_ALGO_ID: AlgorithmIdentifier = alg_id::RSA_PSS_SHA384;
}

impl SignatureAlgId for RsaPssVerify<Sha256> {
    const SIG_ALGO_ID: AlgorithmIdentifier = alg_id::RSA_PSS_SHA256;
}

fn decode_spki_spk(spki_spk: &[u8]) -> Result<RsaPublicKey, InvalidSignature> {
    // public_key: unfortunately this is not a whole SPKI, but just the key material.
    // decode the two integers manually.
    let mut reader = der::SliceReader::new(spki_spk).map_err(|_| InvalidSignature)?;
    let ne: [der::asn1::UintRef; 2] = reader.decode().map_err(|_| InvalidSignature)?;

    RsaPublicKey::new(
        BigUint::from_bytes_be(ne[0].as_bytes()),
        BigUint::from_bytes_be(ne[1].as_bytes()),
    )
    .map_err(|_| InvalidSignature)
}
