use claim::{assert_err, assert_ok};
use futures::TryFutureExt;
use test_case::test_case;

// For the available tests check out here: https://badssl.com/dashboard/

#[test_case("https://codeforces.com/", Ok(()))]
#[test_case("https://crates.io/", Ok(()))]
#[test_case("https://doc.rust-lang.org/", Ok(()))]
#[test_case("https://github.com/", Ok(()))]
#[test_case("https://twitter.com/", Ok(()))]
#[test_case("https://wikipedia.org/", Ok(()))]
#[test_case("https://www.facebook.com/", Ok(()))]
#[test_case("https://www.google.com/", Ok(()))]
#[test_case("https://www.hackerrank.com/", Ok(()))]
#[test_case("https://www.instagram.com/", Ok(()))]
#[test_case("https://www.reddit.com/", Ok(()))]
#[test_case("https://stackoverflow.com/", Ok(()))]
#[test_case("https://www.youtube.com/", Ok(()))]
#[test_case("https://leetcode.com/", Ok(()))]
#[cfg_attr(feature = "tls12", test_case("https://www.topcoder.com/", Ok(())))]
#[tokio::test]
async fn test_generic_sites(uri: &str, expected: Result<(), ()>) {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = rustls_rustcrypto::provider().install_default().unwrap();
    let body = reqwest::get(uri).and_then(|x| x.text());

    if expected.is_ok() {
        assert_ok!(body.await);
    } else {
        assert_err!(body.await);
    }
}
