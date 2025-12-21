use pki_types::{PrivateKeyDer, PrivateSec1KeyDer};
use rustls::sign::SigningKey;
use rustls_rustcrypto::sign::eddsa::Ed25519SigningKey;

#[test]
fn parse_ed25519_sec1_der() {
    // Construct a minimal SEC1 ECPrivateKey DER:
    // SEQUENCE { INTEGER 1, OCTET STRING (32 bytes) }
    let sk = [0x11u8; 32];
    let mut der = vec![0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20];
    der.extend_from_slice(&sk);

    let sec1 = PrivateSec1KeyDer::from(der.as_slice());
    let pkey = PrivateKeyDer::Sec1(sec1);

    let skey = Ed25519SigningKey::try_from(&pkey).expect("failed to parse sec1 ed25519 key");
    assert_eq!(skey.algorithm(), rustls::SignatureAlgorithm::ED25519);
}
