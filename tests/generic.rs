use claim::{assert_err, assert_ok};
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
#[test_case("https://www.youtube.com/", Ok(()))]
#[cfg_attr(feature = "tls12", test_case("https://leetcode.org/", Ok(())))]
#[cfg_attr(feature = "tls12", test_case("https://stackoverflow.com/", Ok(())))]
#[cfg_attr(feature = "tls12", test_case("https://www.topcoder.com/", Ok(())))]
#[tokio::test]
async fn test_generic_sites(uri: &str, expected: Result<(), ()>) {
    if expected.is_ok() {
        assert_ok!(client::run_request(uri).await);
    } else {
        assert_err!(client::run_request(uri).await);
    }
}

mod client;
