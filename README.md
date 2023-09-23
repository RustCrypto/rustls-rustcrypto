# rustls-rustcrypto

WIP provider implementations using RustCrypto for the upcoming major patch of [rustls](https://github.com/rustls/rustls/pull/1405).

Some code comes directly from one of main rustls contributor, [@ctz](https://github.com/ctz). Some part of this code is directly derived from his work but modified to use generic instead.

## ⚠️USE THIS AT YOUR OWN RISK! DO NOT USE THIS IN PRODUCTION⚠️

Not only that this is incomplete (only few selected TLS suites implemented), but the elephant in the room is that neither did rustls nor RustCrypto packages were formally verified and certified with FIPS compliance.

This package is still in its very early phase, so until we think the code is okay for general public use, this won't be published to crates.io anytime soon. 

Meanwhile you can try it out using git crate installation:
```
rustls-rustcrypto = { git = "https://github.com/RustCrypto/rustls-rustcrypto", version = "0.1.0" }
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
