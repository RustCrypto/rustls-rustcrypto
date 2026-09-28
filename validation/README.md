# rustls-rustcrypto Validation

These are collection of crates that can be used to validate integration
between rustls and rustcrypto-rustcrypto provider under different targets.

| Crate            | Description                                      |
| :---             | :---                                             |
| consumer-no_std  | Basic consumer library aiming no_std environment |
| local_ping_pong_openssl | Local tests against OpenSSL reference     |

These live in the workspace due to different dependency requirements between
tests where development-deps may pollute the integration under test.

This is aimed for internal validation without requiring further upstream
dependencies which are may or may not be in lock-step with current version of
rustls the provider targets in any given time.
