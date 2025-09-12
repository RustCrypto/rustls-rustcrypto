# rustls-rustcrypto Validation

This directory contains a collection of validation crates designed to thoroughly test the integration between [rustls](https://github.com/rustls/rustls) and the [rustcrypto-rustcrypto](https://github.com/RustCrypto/rustls-rustcrypto) provider across different environments and targets.

## Purpose

These validation crates serve multiple critical purposes:

- **Integration Testing**: Ensure seamless compatibility between rustls and the RustCrypto provider
- **Cross-Platform Validation**: Test functionality across different architectures and environments (e.g., ESP32, no_std)
- **Reference Implementation Comparison**: Validate against established TLS implementations like OpenSSL
- **Real-World Scenarios**: Test with actual network sockets and certificates
- **Build Verification**: Confirm builds work in constrained environments (no_std)

## Validation Crates

| Crate                    | Description                                      | Target Environment |
| :---                     | :---                                             | :---               |
| consumer-no_std          | Basic consumer library for no_std environments   | no_std             |
| local_ping_pong_openssl  | Local tests against OpenSSL reference            | Standard Rust      |
| esp32-test               | Test for ESP32 microcontroller target using real sockets | ESP32           |
| rustls-real-socket-test  | Test using real sockets for TLS integration      | Standard Rust      |

### Detailed Crate Descriptions

#### consumer-no_std
A minimal self-testing crate that validates the no_std build capability of rustls-rustcrypto. This crate ensures that the provider can be compiled and used in environments without the standard library, which is crucial for embedded systems and constrained environments.

**Key Features:**
- Validates no_std compilation
- Minimal dependencies
- Self-contained testing

#### local_ping_pong_openssl
This crate performs comprehensive compatibility testing between rustls-rustcrypto and OpenSSL. It includes tests with OpenSSL-generated certificates and keys to ensure interoperability and correct TLS handshake behavior.

**Key Features:**
- OpenSSL compatibility testing
- Certificate and key validation
- TLS handshake verification
- Cross-implementation validation

#### esp32-test
A specialized test crate for the ESP32 microcontroller platform. It performs end-to-end TLS testing using real network sockets, validating the rustcrypto provider's functionality in an embedded environment.

**Key Features:**
- ESP32-specific testing
- Real socket communication
- TLS client/server implementation
- Embedded target validation

#### rustls-real-socket-test
Similar to esp32-test but designed for standard Rust environments. This crate tests TLS functionality using actual network sockets, providing realistic validation of the provider's capabilities.

**Key Features:**
- Real socket testing
- TLS client/server implementation
- Network communication validation
- Standard Rust environment testing

## Installation and Setup

### Prerequisites

- Rust 1.88.0 or later
- Cargo package manager
- For ESP32 testing: ESP-IDF development environment
- For OpenSSL testing: OpenSSL development libraries

### Building All Crates

```bash
# From the workspace root
cargo build --workspace
```

### Building Individual Crates

```bash
# consumer-no_std
cargo build -p consumer-no_std --no-default-features

# local_ping_pong_openssl
cargo build -p local_ping_pong_openssl

# rustls-real-socket-test
cargo build -p rustls-real-socket-test

# esp32-test (requires ESP32 toolchain)
cargo build -p esp32-test
```

## Usage Examples

### Running consumer-no_std Tests

```bash
cargo test -p consumer-no_std --no-default-features
```

### Running OpenSSL Compatibility Tests

```bash
# Generate test certificates (if needed)
cd validation/local_ping_pong_openssl/certs
make

# Run the tests
cargo run -p local_ping_pong_openssl
```

### Running Real Socket Tests

```bash
# Standard Rust
cargo run -p rustls-real-socket-test

# ESP32 (requires appropriate hardware/toolchain)
cargo run -p esp32-test
```

## Dependencies

### Common Dependencies
- `rustls` 0.23.x
- `rustls-rustcrypto` (workspace)
- `anyhow` for error handling
- `log` for logging

### ESP32-Specific
- `esp-idf-svc` for ESP32 services
- `esp-idf-hal` for hardware abstraction

### OpenSSL-Specific
- OpenSSL development libraries
- Custom certificate generation tools

## Configuration

### Feature Flags

Most crates support various feature flags to customize the build:

```toml
[dependencies.rustls-rustcrypto]
version = "0.0.2-alpha"
path = "../.."
default-features = false
features = [
    "aead-chacha20poly1305",
    "alloc",
    "der",
    "ecdsa-p256",
    "fast",
    "kx-p256",
    "pkcs8",
    "sign-ecdsa-p256",
    "tls12",
    "verify-ecdsa-p256",
    "verify-ecdsa-p256-sha256"
]
```

### Environment Variables

- `RUST_LOG`: Set logging level (e.g., `RUST_LOG=trace`)
- ESP32-specific: Various ESP-IDF environment variables for toolchain setup

## Architecture and Design

These validation crates are designed with the following principles:

1. **Isolation**: Each crate has its own Cargo.toml to avoid dependency pollution
2. **Minimalism**: Focused on specific validation scenarios
3. **Realism**: Use actual network communication where possible
4. **Cross-Platform**: Support multiple target architectures
5. **Extensibility**: Easy to add new test scenarios

## Troubleshooting

### Common Issues

#### ESP32 Build Failures
- Ensure ESP-IDF is properly installed and configured
- Check that the correct Rust toolchain is selected
- Verify ESP32 hardware connections if running on device

#### OpenSSL Compatibility Issues
- Ensure OpenSSL development libraries are installed
- Check certificate generation scripts in `certs/` directory
- Verify OpenSSL version compatibility

#### no_std Compilation Errors
- Use `--no-default-features` flag
- Ensure all dependencies support no_std
- Check for std-specific code in dependencies

#### Network Socket Issues
- Ensure no firewall blocking local connections
- Check that ports are available (tests use random ports)
- Verify network interface configuration

### Debugging

Enable detailed logging:

```bash
RUST_LOG=trace cargo run -p <crate_name>
```

For ESP32, use ESP-IDF logging facilities.

## Contributing

When adding new validation crates:

1. Create a new directory under `validation/`
2. Add a dedicated `Cargo.toml` with minimal dependencies
3. Include a `README.md` with crate-specific documentation
4. Update this main README.md
5. Add appropriate CI/CD configuration if needed

## License

These validation crates follow the same license as the main rustls-rustcrypto project: Apache-2.0 or MIT.

---

These live in the workspace due to different dependency requirements between tests where development-deps may pollute the integration under test.

This is aimed for internal validation without requiring further upstream dependencies which may or may not be in lock-step with current version of rustls the provider targets in any given time.
