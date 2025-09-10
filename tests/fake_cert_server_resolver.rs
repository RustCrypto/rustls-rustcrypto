use core::time::Duration;
use std::str::FromStr;
use std::sync::Arc;

use itertools::iproduct;
use pki_types::{CertificateDer, PrivateKeyDer};
use rand_core_064::{OsRng, RngCore};
use rsa_098::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rustls::CipherSuite::{
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_rustcrypto::sign::any_supported_type;
use signature_220::{Keypair, Signer};
use x509_cert::builder::{Builder, CertificateBuilder, Profile, RequestBuilder};
use x509_cert::der::{
    Encode,
    asn1::{GeneralizedTime, Ia5String},
};
use x509_cert::ext::pkix::{SubjectAltName, name::GeneralName};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{
    SignatureAlgorithmIdentifier, SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
};
use x509_cert::time::{Time, Validity};

#[derive(Debug)]
pub struct FakeServerCertResolver {
    rsa_cert_key: Arc<CertifiedKey>,
    ecdsa_cert_key: Arc<CertifiedKey>,
    rsa_root_cert: CertificateDer<'static>,
    ecdsa_root_cert: CertificateDer<'static>,
}

impl FakeServerCertResolver {
    pub fn new() -> Self {
        let (rsa_root_cert, rsa_root_key) = Self::generate_root_cert(|| {
            // by running a binary search between 1024 bit and 2048 bit, 1034 bit is the first possible bit size after 1024 bit
            rsa_098::pkcs1v15::SigningKey::<rsa_098::sha2::Sha256>::random(&mut OsRng, 1034)
                .unwrap()
        });
        let (ecdsa_root_cert, ecdsa_root_key) =
            Self::generate_root_cert::<_, p256_0132::ecdsa::DerSignature>(|| {
                p256_0132::ecdsa::SigningKey::random(&mut OsRng)
            });

        let (rsa_cert, rsa_key) = Self::generate_cert(
            || {
                // by running a binary search between 1024 bit and 2048 bit, 1034 bit is the first possible bit size after 1024 bit
                rsa_098::pkcs1v15::SigningKey::<rsa_098::sha2::Sha256>::random(&mut OsRng, 1034)
                    .unwrap()
            },
            rsa_root_key,
        );
        let (ecdsa_cert, ecdsa_key) = Self::generate_cert::<_, _, p256_0132::ecdsa::DerSignature>(
            || p256_0132::ecdsa::SigningKey::random(&mut OsRng),
            ecdsa_root_key,
        );

        Self {
            rsa_root_cert: rsa_root_cert.clone(),
            ecdsa_root_cert: ecdsa_root_cert.clone(),
            rsa_cert_key: Arc::new(CertifiedKey::new(
                vec![rsa_cert],
                any_supported_type(&rsa_key).unwrap(),
            )),
            ecdsa_cert_key: Arc::new(CertifiedKey::new(
                vec![ecdsa_cert],
                any_supported_type(&ecdsa_key).unwrap(),
            )),
        }
    }

    pub fn rsa_root_cert(&self) -> CertificateDer<'static> {
        self.rsa_root_cert.clone()
    }

    pub fn ecdsa_root_cert(&self) -> CertificateDer<'static> {
        self.ecdsa_root_cert.clone()
    }

    fn generate_root_cert<Key, Signature>(
        key_fn: impl Fn() -> Key,
    ) -> (CertificateDer<'static>, Key)
    where
        Key: Signer<Signature> + Keypair + SignatureAlgorithmIdentifier + EncodePrivateKey,
        Signature: SignatureBitStringEncoding,
        <Key as Keypair>::VerifyingKey: EncodePublicKey,
    {
        let signing_key = key_fn();
        (
            CertificateBuilder::new(
                Profile::Root,
                SerialNumber::from(OsRng.next_u64()),
                Validity {
                    not_before: Time::GeneralTime(
                        GeneralizedTime::from_unix_duration(Duration::ZERO).unwrap(),
                    ),
                    not_after: Time::INFINITY,
                },
                Name::from_str("CN=ACME Corporation CA,O=ACME Corporation,C=US").unwrap(),
                SubjectPublicKeyInfoOwned::from_key(signing_key.verifying_key()).unwrap(),
                &signing_key,
            )
            .unwrap()
            .build::<Signature>()
            .unwrap()
            .to_der()
            .unwrap()
            .into(),
            signing_key,
        )
    }
    fn generate_cert<Key, CaKey, Signature>(
        key_fn: impl Fn() -> Key,
        ca_key: CaKey,
    ) -> (CertificateDer<'static>, PrivateKeyDer<'static>)
    where
        Key: Signer<Signature> + Keypair + SignatureAlgorithmIdentifier + EncodePrivateKey,
        CaKey: Signer<Signature> + Keypair + SignatureAlgorithmIdentifier + EncodePrivateKey,
        Signature: SignatureBitStringEncoding,
        <Key as Keypair>::VerifyingKey: EncodePublicKey,
        <CaKey as Keypair>::VerifyingKey: EncodePublicKey,
    {
        let signing_key = key_fn();

        let request = RequestBuilder::new(Name::from_str("CN=acme.com").unwrap(), &signing_key)
            .unwrap()
            .build()
            .unwrap();

        let mut builder = CertificateBuilder::new(
            Profile::Leaf {
                issuer: Name::from_str("CN=ACME Corporation CA,O=ACME Corporation,C=US").unwrap(),
                enable_key_agreement: true,
                enable_key_encipherment: true,
            },
            SerialNumber::from(OsRng.next_u64()),
            Validity {
                not_before: Time::GeneralTime(
                    GeneralizedTime::from_unix_duration(Duration::ZERO).unwrap(),
                ),
                not_after: Time::INFINITY,
            },
            request.info.subject,
            request.info.public_key,
            &ca_key,
        )
        .unwrap();
        builder
            .add_extension(&SubjectAltName(vec![GeneralName::DnsName(
                Ia5String::new(b"acme.com").unwrap(),
            )]))
            .unwrap();
        (
            builder
                .build::<Signature>()
                .unwrap()
                .to_der()
                .unwrap()
                .into(),
            PrivateKeyDer::Pkcs8(
                signing_key
                    .to_pkcs8_der()
                    .unwrap()
                    .as_bytes()
                    .to_vec()
                    .into(),
            ),
        )
    }
}

impl ResolvesServerCert for FakeServerCertResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(
            if iproduct!(
                [
                    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                ],
                hello.cipher_suites()
            )
            .any(|(a, &b)| a == b)
            {
                self.rsa_cert_key.clone()
            } else {
                self.ecdsa_cert_key.clone()
            },
        )
    }
}
