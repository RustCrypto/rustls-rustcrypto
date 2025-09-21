# rustls-rustcrypto

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

[RustCrypto]-based provider implementation for version 0.23 of [rustls], maintained by the RustCrypto organization.

## ⚠️CAUTION⚠️

While a basic test suite that tests all available cipher suites and key exchange combinations passes, and it is cross-validated with OpenSSL, and is also running in ESP32 for experimental (but near-production) secure communication, please be reminded that (as of 2024) not all RustCrypto packages are formally verified and optimized for specific architecture, and none of the packages in RustCrypto are certified with FIPS compliance.

Note that RustCrypto performance is generally inferior than ring, but in exchange you got a pure Rust implementation that theoretically compiles everywhere Rust was ported to. In our case, we need to have `std` but foundational support for future `no_std` expansion is already here.

## Supported Cipher Suites

Only the recommended ([TLS1.2](https://ciphersuite.info/cs/?security=recommended&singlepage=true&tls=tls12), [TLS1.3](https://ciphersuite.info/cs/?security=recommended&singlepage=true&tls=tls13)) and secure ([TLS1.2](https://ciphersuite.info/cs/?security=secure&singlepage=true&tls=tls12), [TLS1.3](https://ciphersuite.info/cs/?security=secure&singlepage=true&tls=tls13)) suites will be chosen

### TLS 1.3 Cipher Suites

| Cipher Suite | Status | Required Features |
|-------------|--------|-------------------|
| TLS_AES_128_GCM_SHA256 | ✅ Recommended | `tls13`, `aead-aes-gcm`, `hash-sha256` |
| TLS_AES_256_GCM_SHA384 | ✅ Recommended | `tls13`, `aead-aes-gcm`, `hash-sha384` |
| TLS_CHACHA20_POLY1305_SHA256 | ✅ Recommended | `tls13`, `aead-aes-chacha20poly1305`, `hash-sha256` |
| TLS_AES_128_CCM_8_SHA256 | ✅ Secure | `tls13`, `aead-aes-ccm`, `hash-sha256` |
| TLS_AES_128_CCM_SHA256 | ✅ Secure | `tls13`, `aead-aes-ccm`, `hash-sha256` |

### TLS 1.2 Cipher Suites

| Cipher Suite | Status | Required Features |
|-------------|--------|-------------------|
| TLS_ECCPWD_WITH_AES_128_GCM_SHA256 | ❌ Not supported | N/A (ECCPWD not implemented) |
| TLS_ECCPWD_WITH_AES_256_GCM_SHA384 | ❌ Not supported | N/A (ECCPWD not implemented) |
| TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 | ✅ Recommended | `tls12`, `verify-ecdsa-p256-sha256`, `aead-aes-gcm`, `kx-p256` |
| TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 | ✅ Recommended | `tls12`, `verify-ecdsa-p384-sha384`, `aead-aes-gcm`, `kx-p384` |
| TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 | ❌ Not supported | N/A (ARIA not production-ready) |
| TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 | ❌ Not supported | N/A (ARIA not production-ready) |
| TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 | ❌ Not supported | N/A (CAMELLIA not production-ready) |
| TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 | ❌ Not supported | N/A (CAMELLIA not production-ready) |
| TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 | ✅ Recommended | `tls12`, `verify-ecdsa-p256-sha256`, `aead-chacha20poly1305`, `kx-p256` |
| TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 | ❌ Not supported | N/A (PSK not supported in Rustls) |
| TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 | ❌ Not supported | N/A (PSK not supported in Rustls) |
| TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 | ❌ Not supported | N/A (PSK not supported in Rustls) |
| TLS_ECCPWD_WITH_AES_128_CCM_SHA256 | ❌ Not supported | N/A (ECCPWD not implemented) |
| TLS_ECCPWD_WITH_AES_256_CCM_SHA384 | ❌ Not supported | N/A (ECCPWD not implemented) |
| TLS_ECDHE_ECDSA_WITH_AES_128_CCM | ✅ Secure | `tls12`, `verify-ecdsa-p256-sha256`, `aead-aes-ccm`, `kx-p256` |
| TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 | ✅ Secure | `tls12`, `verify-ecdsa-p256-sha256`, `aead-aes-ccm`, `kx-p256` |
| TLS_ECDHE_ECDSA_WITH_AES_256_CCM | ✅ Secure | `tls12`, `verify-ecdsa-p384-sha384`, `aead-aes-ccm`, `kx-p384` |
| TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 | ✅ Secure | `tls12`, `verify-ecdsa-p384-sha384`, `aead-aes-ccm`, `kx-p384` |
| TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 | ❌ Not supported | N/A (PSK not supported in Rustls) |
| TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 | ❌ Not supported | N/A (PSK not supported in Rustls) |
| TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | ✅ Secure | `tls12`, `verify-rsa-pkcs1-sha256`, `aead-aes-gcm`, `kx-p256` |
| TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | ✅ Secure | `tls12`, `verify-rsa-pkcs1-sha384`, `aead-aes-gcm`, `kx-p384` |
| TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 | ❌ Not supported | N/A (ARIA not production-ready) |
| TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 | ❌ Not supported | N/A (ARIA not production-ready) |
| TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 | ❌ Not supported | N/A (CAMELLIA not production-ready) |
| TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 | ❌ Not supported | N/A (CAMELLIA not production-ready) |
| TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 | ✅ Secure | `tls12`, `verify-rsa-pkcs1-sha256`, `aead-chacha20poly1305`, `kx-p256` |

### Feature Usage Examples

To enable TLS 1.3 with AES-GCM support:
```toml
rustls-rustcrypto = { version = "0.0.2-alpha", features = ["tls13", "gcm", "hash-sha256"] }
```

To enable TLS 1.2 with ECDSA and AES-GCM:
```toml
rustls-rustcrypto = { version = "0.0.2-alpha", features = ["tls12", "verify-ecdsa-p256-sha256", "aead-aes-gcm", "kx-p256"] }
```

To enable TLS 1.2 with RSA and AES-GCM:
```toml
rustls-rustcrypto = { version = "0.0.2-alpha", features = ["tls12", "verify-rsa-pkcs1-sha256", "aead-aes-gcm", "kx-p256"] }
```

To enable both TLS 1.2 and TLS 1.3 with full algorithm support:
```toml
rustls-rustcrypto = { version = "0.0.2-alpha", features = ["full"] }
```

### Simplified Feature Sets

For common use cases, you can use these simplified configurations:

**TLS 1.3 Only (Recommended for new applications):**
```toml
rustls-rustcrypto = { version = "0.0.2-alpha", features = ["tls13", "aead-full", "hash-full"] }
```

**TLS 1.2 + ECDSA (Legacy compatibility):**
```toml
rustls-rustcrypto = { version = "0.0.2-alpha", features = ["tls12", "verify-ecdsa-p256-sha256", "aead-full", "kx-p256"] }
```

**TLS 1.2 + RSA (Maximum compatibility):**
```toml
rustls-rustcrypto = { version = "0.0.2-alpha", features = ["tls12", "verify-rsa-pkcs1-sha256", "aead-full", "kx-p256"] }
```

### Using Compound Features

You can also use compound features that automatically include related dependencies:

**AEAD Compound Features:**
- `aead-aes-gcm` = includes `aead` + `aes-gcm`
- `aead-aes-ccm` = includes `aead` + `aes-ccm`
- `aead-chacha20poly1305` = includes `aead` + `chacha20poly1305`
- `aead-full` = includes all AEAD algorithms

**Signing Compound Features:**
- `sign-ecdsa-p256` = includes `sign-ecdsa-nist` + `ecdsa-p256`
- `sign-rsa-pkcs1` = includes `sign-rsa` + `rsa-pkcs1`
- `sign-full` = includes all signing algorithms

**Example using compound features:**
```toml
# Base features: ["tls12", "verify-ecdsa-p256-sha256", "aead-aes-gcm", "kx-p256"]
# Compound features: ["tls12", "verify-ecdsa-p256-sha256", "aead-aes-gcm", "kx-p256"]
rustls-rustcrypto = { version = "0.0.2-alpha", features = ["tls12", "verify-ecdsa-p256-sha256", "aead-aes-gcm", "kx-p256"] }
```

**Note:** The base features (like `aes-gcm`) are still required for conditional compilation in the source code. Compound features are primarily for convenience and ensuring all dependencies are included.

### Understanding Feature Dependencies

The verification features have hierarchical dependencies that automatically include required components:

- `verify-ecdsa-p256-sha256` automatically includes:
  - `verify-ecdsa-p256` (includes `ecdsa-p256`)
  - `verify-ecdsa-nist`
  - `verify` (includes `webpki`)
  - `hash-sha256`

- `verify-rsa-pkcs1-sha256` automatically includes:
  - `verify-rsa-pkcs1` (includes `rsa-pkcs1`)
  - `verify-rsa`
  - `verify` (includes `webpki`)
  - `hash-sha256`

This hierarchical structure means you only need to specify the highest-level feature for your use case.

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