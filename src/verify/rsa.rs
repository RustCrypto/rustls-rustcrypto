use paste::paste;
use pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use sha2::{Sha256, Sha384, Sha512};
use signature::Verifier;
use webpki::alg_id;

macro_rules! impl_generic_rsa_verifer {
    (
        $name:ident,
        $public_key_algo:expr,
        $signature_alg_id:expr,
        $verifying_key:ty,
        $signature:ty
    ) => {
        paste! {
            #[allow(non_camel_case_types)]
            #[derive(Debug)]
            pub struct [<RsaVerifier_ $name>];

            impl [<RsaVerifier_ $name>] {
                fn verify_inner(
                    public_key: &[u8],
                    message: &[u8],
                    signature: &[u8],
                ) -> Result<(), crate::verify::Error> {
                    use rsa::RsaPublicKey;
                    use rsa::pkcs1::DecodeRsaPublicKey;

                    let public_key = RsaPublicKey::from_pkcs1_der(public_key)?;
                    let signature = <$signature>::try_from(signature)?;
                    <$verifying_key>::new(public_key).verify(message, &signature)?;
                    Ok(())
                }
            }

            impl SignatureVerificationAlgorithm for [<RsaVerifier_ $name>] {
                fn public_key_alg_id(&self) -> AlgorithmIdentifier {
                    $public_key_algo
                }

                fn signature_alg_id(&self) -> AlgorithmIdentifier {
                    $signature_alg_id
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

            pub const $name: &dyn SignatureVerificationAlgorithm = &[<RsaVerifier_ $name>];
        }
    };
}

#[cfg(feature = "rsa-pkcs1")]
impl_generic_rsa_verifer!(
    RSA_PKCS1_SHA256,
    alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PKCS1_SHA256,
    ::rsa::pkcs1v15::VerifyingKey<Sha256>,
    ::rsa::pkcs1v15::Signature
);

#[cfg(feature = "rsa-pkcs1")]
impl_generic_rsa_verifer!(
    RSA_PKCS1_SHA384,
    alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PKCS1_SHA384,
    ::rsa::pkcs1v15::VerifyingKey<Sha384>,
    ::rsa::pkcs1v15::Signature
);

#[cfg(feature = "rsa-pkcs1")]
impl_generic_rsa_verifer!(
    RSA_PKCS1_SHA512,
    alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PKCS1_SHA512,
    ::rsa::pkcs1v15::VerifyingKey<Sha512>,
    ::rsa::pkcs1v15::Signature
);

#[cfg(feature = "rsa-pss")]
impl_generic_rsa_verifer!(
    RSA_PSS_SHA256,
    alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PSS_SHA256,
    ::rsa::pss::VerifyingKey<Sha256>,
    ::rsa::pss::Signature
);
#[cfg(feature = "rsa-pss")]
impl_generic_rsa_verifer!(
    RSA_PSS_SHA384,
    alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PSS_SHA384,
    ::rsa::pss::VerifyingKey<Sha384>,
    ::rsa::pss::Signature
);
#[cfg(feature = "rsa-pss")]
impl_generic_rsa_verifer!(
    RSA_PSS_SHA512,
    alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PSS_SHA512,
    ::rsa::pss::VerifyingKey<Sha512>,
    ::rsa::pss::Signature
);
