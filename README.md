# rustls-rustcrypto

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

[RustCrypto]-based provider implementation for version 0.23 of [rustls], maintained by the RustCrypto organization.

## ⚠️USE THIS AT YOUR OWN RISK! DO NOT USE THIS IN PRODUCTION⚠️

Not only that this is incomplete that only few selected TLS suites implemented (it should be well enough to cover 70% of the usage), but the elephant in the room is that neither did rustls nor RustCrypto packages were formally verified and certified with FIPS compliance.

Note that RustCrypto performance is generally inferior than ring, but in exchange you got a pure Rust implementation that theoretically compiles everywhere Rust was ported to. In our case, we need to have `std` but foundational support for future `no_std` expansion is already here.

## Supported Cipher Suites

Only the recommended ([TLS1.2](https://ciphersuite.info/cs/?security=recommended&singlepage=true&tls=tls12), [TLS1.3](https://ciphersuite.info/cs/?security=recommended&singlepage=true&tls=tls13)) and secure ([TLS1.2](https://ciphersuite.info/cs/?security=secure&singlepage=true&tls=tls12), [TLS1.3](https://ciphersuite.info/cs/?security=secure&singlepage=true&tls=tls13)) suites will be chosen

For TLS 1.3:

- [x] (Recommended) TLS_AES_128_GCM_SHA256
- [x] (Recommended) TLS_AES_256_GCM_SHA384
- [x] (Recommended) TLS_CHACHA20_POLY1305_SHA256
- [x] (Secure) TLS_AES_128_CCM_8_SHA256
- [x] (Secure) TLS_AES_128_CCM_SHA256

For TLS 1.2:

- [ ] (Recommended) TLS_ECCPWD_WITH_AES_128_GCM_SHA256
- [ ] (Recommended) TLS_ECCPWD_WITH_AES_256_GCM_SHA384
- [x] (Recommended) TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- [x] (Recommended) TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- [ ] (Recommended) TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256
- [ ] (Recommended) TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384
- [ ] (Recommended) TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
- [ ] (Recommended) TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
- [x] (Recommended) TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
- [ ] (Recommended) TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256
- [ ] (Recommended) TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384
- [ ] (Recommended) TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
- [ ] (Secure) TLS_ECCPWD_WITH_AES_128_CCM_SHA256
- [ ] (Secure) TLS_ECCPWD_WITH_AES_256_CCM_SHA384
- [x] (Secure) TLS_ECDHE_ECDSA_WITH_AES_128_CCM
- [x] (Secure) TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
- [x] (Secure) TLS_ECDHE_ECDSA_WITH_AES_256_CCM
- [x] (Secure) TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
- [ ] (Secure) TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256
- [ ] (Secure) TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256
- [x] (Secure) TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- [x] (Secure) TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- [ ] (Secure) TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256
- [ ] (Secure) TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384
- [ ] (Secure) TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
- [ ] (Secure) TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
- [x] (Secure) TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256

\* PSK support is currently blocked due to [it not currently being supported in Rustls as of 2024](https://github.com/rustls/rustls/issues/174).
If you want this feature, consider financially supporting the Rustls project by being a funder in [Prossimo](https://www.memorysafety.org/initiative/rustls/)

\* While both [CAMELLIA](https://github.com/RustCrypto/block-ciphers/tree/master/camellia) and [ARIA](https://github.com/RustCrypto/block-ciphers/tree/master/aria) block cipher are in RustCrypto, they are still in 0.1.0 and not currently viable for production use

\* As RustCrypto do not have a [Dragonfly](https://www.ietf.org/proceedings/83/slides/slides-83-cfrg-0.pdf) implementation, nor it is planned yet, [RFC8492](https://datatracker.ietf.org/doc/html/rfc8492) and thus ECCPWD family of cipher suites would be hard to implement for the known future

## License

Licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

Some code authored by [@ctz](https://github.com/ctz) was adapted from upstream rustls. Licensed as above with permission.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # "badges"
[crate-image]: https://img.shields.io/crates/v/rustls-rustcrypto
[crate-link]: https://crates.io/crates/rustls-rustcrypto
[docs-image]: https://docs.rs/rustls-rustcrypto/badge.svg
[docs-link]: https://docs.rs/rustls-rustcrypto/
[build-image]: https://github.com/RustCrypto/rustls-rustcrypto/actions/workflows/rustls-rustcrypto.yml/badge.svg
[build-link]: https://github.com/RustCrypto/rustls-rustcrypto/actions/workflows/rustls-rustcrypto.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.75+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/434751-TLS
[//]: # "links"
[RustCrypto]: https://github.com/RustCrypto/
[rustls]: https://github.com/rustls/rustls/
