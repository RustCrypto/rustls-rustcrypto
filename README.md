# rustls-rustcrypto

WIP RustCrypto-based provider implementation for version 0.23 of [rustls](https://github.com/rustls/rustls/pull/1405).

Some code comes directly from one of main rustls contributor, [@ctz](https://github.com/ctz).

Some part of this code is directly derived from his work but modified to use generic instead.

## ⚠️USE THIS AT YOUR OWN RISK! DO NOT USE THIS IN PRODUCTION⚠️

Not only that this is incomplete that only few selected TLS suites implemented (it should be well enough to cover 70% of the usage), but the elephant in the room is that neither did rustls nor RustCrypto packages were formally verified and certified with FIPS compliance.

Note that RustCrypto performance is generally inferior than ring, but in exchange you got a pure Rust implementation that theoretically compiles everywhere Rust was ported to. In our case, we need to have `std` but foundational support for future `no_std` expansion is already here.

This package is still in its very early phase, so until we think the code is okay for general public use, this won't be published to crates.io anytime soon.

Meanwhile you can try it out using git crate installation:

```toml
rustls-rustcrypto = { git = "https://github.com/RustCrypto/rustls-rustcrypto", version = "0.1" }
```

## Supported Cipher Suites

- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
- TLS13_AES_128_GCM_SHA256
- TLS13_AES_256_GCM_SHA384
- TLS13_CHACHA20_POLY1305_SHA256

## QUIC Support

There won't be QUIC support anytime soon until <https://github.com/rustls/rustls/issues/1491> is solved. HTTP/2 however should work out of the box.

## License

Licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
