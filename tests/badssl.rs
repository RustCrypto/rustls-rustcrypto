use claim::{assert_err, assert_ok};
use test_case::test_case;

// For the available tests check out here: https://badssl.com/dashboard/

#[cfg(feature = "tls12")]
#[test_case("https://tls-v1-2.badssl.com/"; "test general TLS1.2 verification")]
#[test_case("https://sha256.badssl.com/"; "test SHA-256 hash")]
#[test_case("https://rsa2048.badssl.com/"; "test RSA-2048 verification")]
#[test_case("https://ecc256.badssl.com/"; "test ECC256 verification")]
#[test_case("https://ecc384.badssl.com/"; "test ECC384 verification")]
#[tokio::test]
async fn test_badssl_secure_common_tls12(uri: &str) {
    assert_ok!(client::run_request(uri).await);
}

#[test_case("https://mozilla-modern.badssl.com/"; "test Mozilla modern suites")]
#[tokio::test]
async fn test_badssl_secure_common(uri: &str) {
    assert_ok!(client::run_request(uri).await);
}

#[test_case("https://1000-sans.badssl.com/"; "test 1000-sans")]
#[test_case("https://10000-sans.badssl.com/"; "test 10000-sans")]
#[test_case("https://sha384.badssl.com/"; "test SHA384 verification")]
#[test_case("https://sha512.badssl.com/"; "test SHA512 verification")]
#[test_case("https://rsa8192.badssl.com/"; "test RSA8192 verification")]
#[test_case("https://no-subject.badssl.com/"; "test no subject")]
#[test_case("https://no-common-name.badssl.com/"; "test no common name")]
#[test_case("https://incomplete-chain.badssl.com/"; "test incomplete chain")]
#[tokio::test]
async fn test_badssl_secure_uncommon(uri: &str) {
    assert_err!(client::run_request(uri).await);
}

mod client;
