# rustls-provider-rustcrypto

WIP provider implementations using RustCrypto for the upcoming major patch of [rustls](https://github.com/rustls/rustls/pull/1405).

Some code comes directly from one of main rustls contributor, [@ctz](https://github.com/ctz). Some part of this code is directly derived from his work but modified to use generic instead.

## ⚠️USE THIS AT YOUR OWN RISK! DO NOT USE THIS IN PRODUCTION⚠️

Not only that this is incomplete (only few selected TLS suites implemented, and some is even buggy like AES), but the elephant in the room is that neither did rustls nor RustCrypto packages were formally verified and certified with FIPS compliance.

The upstream PR is also constantly force pushed, and I do not guarantee I can catch up with the changes rapidly. [We also have a part 4 of this saga](https://github.com/rustls/rustls/pull/1448), so the work done here may also need to refresh.

This package is still in its very early phase, so until the grand part 3 PR is done, this won't be published to crates.io. Meanwhile you can try it out using git crate installation:

```
rustls-provider-rustcrypto = { git = "https://github.com/stevefan1999/rustls-provider-rustcrypto", version = "0.0.1" }
```