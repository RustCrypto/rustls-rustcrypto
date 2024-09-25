use claim::{assert_err, assert_ok};
use futures::TryFutureExt;
use test_case::test_case;

// For the available tests check out here: https://badssl.com/dashboard/

#[cfg(feature = "tls12")]
#[test_case("https://hsts.badssl.com/", Ok(()); "test HSTS")]
#[test_case("https://upgrade.badssl.com/", Ok(()); "test upgrade-insecure-requests")]
#[test_case("https://ecc256.badssl.com/", Ok(()); "test ECC256 verification")]
#[test_case("https://ecc384.badssl.com/", Ok(()); "test ECC384 verification")]
#[test_case("https://rsa2048.badssl.com/", Ok(()); "test RSA-2048 verification")]
#[test_case("https://rsa4096.badssl.com/", Ok(()); "test RSA-4096 verification")]
#[test_case("https://rsa8192.badssl.com/", Err(()); "test RSA-8192 verification")]
#[test_case("https://sha256.badssl.com/", Ok(()); "test SHA-256 hash")]
#[test_case("https://sha384.badssl.com/", Err(()); "test SHA-384 hash (but expired)")]
#[test_case("https://sha512.badssl.com/", Err(()); "test SHA-512 hash (but expired)")]
#[test_case("https://tls-v1-2.badssl.com/", Ok(()); "test general TLS1.2 verification")]
#[test_case("https://mozilla-intermediate.badssl.com/", Ok(()); "test Mozilla intermediate compatibility (TLS 1.2 only)")]
#[test_case("https://long-extended-subdomain-name-containing-many-letters-and-dashes.badssl.com/", Ok(()); "test long name with dashes")]
#[test_case("https://longextendedsubdomainnamewithoutdashesinordertotestwordwrapping.badssl.com/", Ok(()); "test long name")]
#[tokio::test]
async fn test_badssl_tls12(uri: &str, expected: Result<(), ()>) {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = rustls_rustcrypto::provider().install_default();
    let body = crate::utils::make_client()
        .expect("client cannot be built")
        .get(uri)
        .send()
        .and_then(|x| x.text());

    if expected.is_ok() {
        assert_ok!(body.await);
    } else {
        assert_err!(body.await);
    }
}

// Both Mozilla profile on BadSSL did not match up to the modern standard, hence it is disabled
// See https://github.com/chromium/badssl.com/issues/483 and https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility
#[cfg_attr(TODO, test_case("https://mozilla-intermediate.badssl.com/", Ok(()); "test Mozilla intermediate compatibility (TLS 1.3 preferred)"))]
#[cfg_attr(TODO, test_case("https://mozilla-modern.badssl.com/", Ok(()); "test Mozilla modern compatibility (TLS 1.3 required)"))]
#[test_case("https://1000-sans.badssl.com/", Err(()); "test 1000-sans")]
#[test_case("https://10000-sans.badssl.com/", Err(()); "test 10000-sans")]
#[test_case("https://expired.badssl.com/", Err(()); "test expired")]
#[test_case("https://incomplete-chain.badssl.com/", Err(()); "test incomplete chain")]
#[test_case("https://no-common-name.badssl.com/", Err(()); "test no common name")]
#[test_case("https://no-subject.badssl.com/", Err(()); "test no subject")]
// This one is controversial because on my Edge browser and curl, both of which can make the TLS connection
// With Firefox I got SEC_ERROR_REVOKED_CERTIFICATE, so clearly there is some problem with certificate revocation
// Let's skip this for now, it could be related to webpki-root due to it not refreshing for some revoked CAs
// Also https://github.com/chromium/badssl.com/issues/531
#[cfg_attr(TODO, test_case("https://revoked.badssl.com/", Err(()); "test revoked"))]
#[test_case("https://self-signed.badssl.com/", Err(()); "test self signed")]
#[test_case("https://untrusted-root.badssl.com/", Err(()); "test untrusted root")]
#[test_case("https://wrong.host.badssl.com/", Err(()); "test wrong host")]
// SCT is not implemented in Rustls yet
#[cfg_attr(TODO, test_case("https://no-sct.badssl.com/", Err(()); "test Signed Certificate Timestamp"))] // NET::ERR_CERTIFICATE_TRANSPARENCY_REQUIRED
// TLS Cert Pinning is not implemented in Rustls yet 
#[cfg_attr(TODO, test_case("https://pinning-test.badssl.com/", Err(()); "test pinning test"))] // NET::ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN
#[tokio::test]
async fn test_badssl(uri: &str, expected: Result<(), ()>) {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = rustls_rustcrypto::provider().install_default();
    let body = crate::utils::make_client()
        .expect("client cannot be built")
        .get(uri)
        .send()
        .and_then(|x| x.text());

    if expected.is_ok() {
        assert_ok!(body.await);
    } else {
        assert_err!(body.await);
    }
}
