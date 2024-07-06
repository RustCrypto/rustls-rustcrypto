use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SignatureAlgorithm,
};
pub struct TestPki {
    ca_key: KeyPair,
    ca_cert: Certificate,
    algo: &'static SignatureAlgorithm,
}

impl TestPki {
    pub fn ca_key(&self) -> &KeyPair {
        &self.ca_key
    }

    pub fn ca_cert(&self) -> &Certificate {
        &self.ca_cert
    }

    pub fn sign(&self, names: Vec<String>) -> (Certificate, KeyPair) {
        // Create a server end entity cert issued by the CA.
        let mut params = CertificateParams::new(names.clone()).unwrap();
        for name in names {
            params.distinguished_name.push(DnType::CommonName, name);
        }
        params.use_authority_key_identifier_extension = true;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        let key = KeyPair::generate_for(self.algo).unwrap();
        (
            params
                .signed_by(&key, self.ca_cert(), self.ca_key())
                .unwrap(),
            key,
        )
    }

    pub fn new(algo: &'static SignatureAlgorithm) -> Self {
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params
            .distinguished_name
            .push(DnType::OrganizationName, "Rustls Server Acceptor");
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Example CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];

        let ca_key = KeyPair::generate_for(algo).unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        Self {
            ca_cert,
            ca_key,
            algo,
        }
    }
}
