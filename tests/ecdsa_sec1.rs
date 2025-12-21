use pki_types::{PrivateKeyDer, PrivateSec1KeyDer};

use rustls_rustcrypto::sign::ecdsa::{EcdsaSigningKeyP256, EcdsaSigningKeyP384};

#[test]
fn parse_p256_sec1_with_oid() {
    // P-256 ECPrivateKey with parameters OID (prime256v1 / 1.2.840.10045.3.1.7)
    let sk = [0x11u8; 32];
    let mut der = vec![
        0x30, 0x31, // SEQUENCE, len=49
        0x02, 0x01, 0x01, // INTEGER 1
        0x04, 0x20,
    ]; // OCTET STRING, len=32
    der.extend_from_slice(&sk);
    // [0] EXPLICIT { OBJECT IDENTIFIER 1.2.840.10045.3.1.7 }
    der.extend_from_slice(&[
        0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    ]);

    let sec1 = PrivateSec1KeyDer::from(der.as_slice());
    let pkey = PrivateKeyDer::Sec1(sec1);

    let _skey = EcdsaSigningKeyP256::try_from(&pkey).expect("failed to parse P-256 SEC1 key");
}

#[test]
fn parse_p384_sec1_without_oid() {
    // P-384 ECPrivateKey without parameters (just the private octets)
    let sk = [0x22u8; 48];
    // sequence length: INTEGER(3) + OCTETSTRING(2+48) = 53 -> 0x35
    let mut der = vec![0x30, 0x35, 0x02, 0x01, 0x01, 0x04, 0x30];
    der.extend_from_slice(&sk);

    let sec1 = PrivateSec1KeyDer::from(der.as_slice());
    let pkey = PrivateKeyDer::Sec1(sec1);

    let _skey = EcdsaSigningKeyP384::try_from(&pkey)
        .expect("failed to parse P-384 SEC1 key without params");
}

#[test]
fn reject_p256_sec1_with_wrong_oid() {
    // P-256 private octets but parameters indicate a different curve (use 1.3.132.0.34)
    let sk = [0x11u8; 32];
    let mut der = vec![0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20];
    der.extend_from_slice(&sk);
    // [0] EXPLICIT { OBJECT IDENTIFIER 1.3.132.0.34 }
    // OBJECT IDENTIFIER encoding: 06 05 2b 81 04 22
    der.extend_from_slice(&[0xa0, 0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x22]);

    let sec1 = PrivateSec1KeyDer::from(der.as_slice());
    let pkey = PrivateKeyDer::Sec1(sec1);

    assert!(EcdsaSigningKeyP256::try_from(&pkey).is_err());
}
