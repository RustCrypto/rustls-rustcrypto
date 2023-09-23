use claim::{assert_err, assert_ok};
use test_case::test_case;

// For the available tests check out here: https://badssl.com/dashboard/

#[cfg(feature = "tls12")]
#[test_case("https://ecc256.badssl.com/", Ok(()); "test ECC256 verification")]
#[test_case("https://ecc384.badssl.com/", Ok(()); "test ECC384 verification")]
#[test_case("https://rsa2048.badssl.com/", Ok(()); "test RSA-2048 verification")]
#[test_case("https://rsa4096.badssl.com/", Ok(()); "test RSA-4096 verification")]
#[cfg_attr(TODO, test_case("https://rsa8192.badssl.com/", Err(()); "test RSA-8192 verification"))]
#[test_case("https://sha256.badssl.com/", Ok(()); "test SHA-256 hash")]
#[test_case("https://sha384.badssl.com/", Err(()); "test SHA-384 hash (but expired)")]
#[test_case("https://sha512.badssl.com/", Err(()); "test SHA-512 hash (but expired)")]
#[test_case("https://tls-v1-2.badssl.com/", Ok(()); "test general TLS1.2 verification")]
#[test_case("https://mozilla-intermediate.badssl.com/", Ok(()); "test Mozilla intermediate compatibility (TLS 1.2 only)")]
#[test_case("https://long-extended-subdomain-name-containing-many-letters-and-dashes.badssl.com/", Ok(()); "test long name with dashes")]
#[test_case("https://longextendedsubdomainnamewithoutdashesinordertotestwordwrapping.badssl.com/", Ok(()); "test long name")]
#[tokio::test]
async fn test_badssl_tls12(uri: &str, expected: Result<(), ()>) {
    if expected.is_ok() {
        assert_ok!(client::run_request(uri).await);
    } else {
        assert_err!(client::run_request(uri).await);
    }
}

#[test_case("https://hsts.badssl.com/", Ok(()); "test HSTS (TODO)")]
#[test_case("https://mozilla-intermediate.badssl.com/", Ok(()); "test Mozilla intermediate compatibility (TLS 1.3 preferred)")]
#[test_case("https://mozilla-modern.badssl.com/", Ok(()); "test Mozilla modern compatibility (TLS 1.3 required)")]
#[test_case("https://upgrade.badssl.com/", Ok(()); "test upgrade-insecure-requests")]
#[test_case("https://1000-sans.badssl.com/", Err(()); "test 1000-sans")]
#[test_case("https://10000-sans.badssl.com/", Err(()); "test 10000-sans")]
#[test_case("https://expired.badssl.com/", Err(()); "test expired")]
#[test_case("https://incomplete-chain.badssl.com/", Err(()); "test incomplete chain")]
#[test_case("https://no-common-name.badssl.com/", Err(()); "test no common name")]
#[test_case("https://no-subject.badssl.com/", Err(()); "test no subject")]
#[test_case("https://revoked.badssl.com/", Err(()); "test revoked")]
#[test_case("https://self-signed.badssl.com/", Err(()); "test self signed")]
#[test_case("https://untrusted-root.badssl.com/", Err(()); "test untrusted root")]
#[test_case("https://wrong.host.badssl.com/", Err(()); "test wrong host")]
#[cfg_attr(TODO, test_case("https://no-sct.badssl.com/", Err(()); "test Signed Certificate Timestamp"))]
#[cfg_attr(TODO, test_case("https://pinning-test.badssl.com/", Err(()); "test pinning test"))] // NET::ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN
#[tokio::test]
async fn test_badssl(uri: &str, expected: Result<(), ()>) {
    if expected.is_ok() {
        assert_ok!(client::run_request(uri).await);
    } else {
        assert_err!(client::run_request(uri).await);
    }
}

mod client;
