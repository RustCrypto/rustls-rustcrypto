# ESP32 TLS Test

A comprehensive test suite for validating TLS functionality on ESP32 microcontrollers using the rustls-rustcrypto provider. This crate performs end-to-end TLS testing with real network sockets, ensuring secure communication works correctly in embedded environments.

## Overview

This test crate demonstrates and validates:

- TLS 1.2 and TLS 1.3 handshake completion
- Secure communication over real TCP sockets
- Certificate-based authentication
- Client-server TLS communication
- RustCrypto provider integration with ESP32
- Embedded system TLS capabilities

## Architecture

The test implements a complete TLS client-server architecture:

1. **TLS Server**: Runs on ESP32, accepts connections, performs TLS handshake
2. **TLS Client**: Also runs on ESP32, connects to server, sends test messages
3. **Real Sockets**: Uses actual TCP sockets (not mock implementations)
4. **Embedded Certificates**: Includes test certificates compiled into the binary

## Features

- ✅ TLS 1.2 and TLS 1.3 support
- ✅ ECDSA certificate authentication
- ✅ AES-GCM and ChaCha20-Poly1305 ciphers
- ✅ Real network socket communication
- ✅ Embedded certificate validation
- ✅ ESP32-specific optimizations
- ✅ Comprehensive logging

## Prerequisites

### Hardware Requirements
- ESP32 microcontroller (ESP32, ESP32-S2, ESP32-S3, etc.)
- USB connection for flashing and monitoring

### Software Requirements
- Rust 1.88.0 or later
- ESP-IDF development environment
- ESP32 Rust toolchain
- OpenSSL (for certificate generation if needed)

### ESP-IDF Setup

1. Install ESP-IDF:
```bash
# Using espup (recommended)
cargo install espup
espup install

# Or manual installation following ESP-IDF docs
```

2. Set up the environment:
```bash
# Add to your shell profile
. $HOME/export-esp.sh
```

3. Install ESP32 Rust toolchain:
```bash
rustup target add riscv32imc-esp-espidf
# or for ESP32-S2/S3
rustup target add xtensa-esp32-espidf
```

## Installation

### Clone and Setup
```bash
# From the rustls-rustcrypto workspace root
cd validation/esp32-test

# Build for ESP32
cargo build --release
```

### Dependencies

The crate uses the following key dependencies:

- `rustls` 0.23.x - TLS library
- `rustls-rustcrypto` - RustCrypto provider (workspace)
- `esp-idf-svc` - ESP32 services
- `esp-idf-hal` - ESP32 hardware abstraction
- `anyhow` - Error handling
- `log` - Logging framework

## Configuration

### Feature Flags

Configure the build with appropriate feature flags:

```toml
[dependencies.rustls-rustcrypto]
version = "0.0.2-alpha"
path = "../../"
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

### Build Profiles

The crate includes optimized profiles for ESP32:

```toml
[profile.release]
opt-level = "s"  # Optimize for size
debug = false

[profile.dev]
debug = true     # Symbols for debugging
opt-level = "z"  # Optimize for size in debug
```

## Usage

### Running the Test

1. **Flash to ESP32**:
```bash
cargo run --release
```

2. **Monitor Output**:
```bash
# In another terminal
espmonitor /dev/ttyUSB0  # Adjust port as needed
```

### Expected Output

The test will show:
```
ESP32 Rustls Real Socket TLS Test Starting...
Rustcrypto provider initialized
TLS client config created successfully
TLS server config created successfully
TLS server listening on 127.0.0.1:xxxxx
Accepted connection from 127.0.0.1:xxxxx
TLS handshake completed successfully
Server received: Hello from ESP32 TLS client!
Client received: Echo: Hello from ESP32 TLS client!
TLS client shutting down
TLS server shutting down
ESP32 Rustls Real Socket TLS Test completed!
```

## Test Details

### TLS Handshake Process

1. **Server Setup**: Creates TLS config with embedded certificate
2. **Client Setup**: Creates TLS config with custom certificate verifier
3. **Connection**: Client connects to server using TCP
4. **Handshake**: Mutual TLS handshake with certificate validation
5. **Data Exchange**: Client sends message, server echoes response
6. **Cleanup**: Both connections close gracefully

### Certificates

The test uses embedded certificates:
- **Server Certificate**: `cert.der` - ECDSA P-256 certificate
- **Private Key**: `key.der` - PKCS#8 encoded private key
- **Certificate Verification**: Custom verifier (accepts all for testing)

### Security Notes

⚠️ **WARNING**: This test uses a dummy certificate verifier that accepts all certificates. This is for testing purposes only and should NEVER be used in production code.

## Troubleshooting

### Common Issues

#### Build Failures
- Ensure ESP-IDF is properly installed and sourced
- Check Rust toolchain version compatibility
- Verify target architecture matches your ESP32 variant

#### Flashing Issues
- Check USB port permissions
- Ensure no other processes are using the serial port
- Try different USB cables or ports

#### Runtime Errors
- Verify network connectivity if using WiFi
- Check ESP32 power supply stability
- Monitor serial output for detailed error messages

#### TLS Handshake Failures
- Ensure certificates are properly embedded
- Check cipher suite compatibility
- Verify TLS version support

### Debugging

Enable detailed logging:
```bash
# Set log level
espmonitor /dev/ttyUSB0 -e "RUST_LOG=trace"
```

Common debug commands:
```bash
# Check ESP32 connection
ls /dev/ttyUSB*

# Monitor with specific baud rate
espmonitor /dev/ttyUSB0 --baud 115200

# Flash with verbose output
cargo espflash flash --release --verbose
```

## Performance Considerations

### Memory Usage
- Optimized for ESP32's limited RAM
- Uses static allocations where possible
- Minimal heap allocation during runtime

### CPU Usage
- ECC operations are computationally intensive
- Consider using hardware acceleration if available
- Profile with ESP-IDF tools for optimization

## Extending the Test

### Adding New Cipher Suites
```rust
// In main.rs, modify the provider features
let provider = rustcrypto_provider();
// Add additional cipher suites as needed
```

### Custom Certificate Verification
```rust
// Replace NoCertificateVerification with custom implementation
impl ServerCertVerifier for MyVerifier {
    // Implement verification logic
}
```

### Network Configuration
```rust
// Modify connection parameters
let server_addr = "192.168.1.100:8443"; // Custom IP/port
```

## Integration with CI/CD

This test can be integrated into automated testing pipelines:

```yaml
# Example GitHub Actions workflow
name: ESP32 TLS Test
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: esp-rs/xtensa-toolchain@v1
      - run: cargo build --release -p esp32-test
```

## Contributing

When contributing to this test crate:

1. Maintain compatibility with ESP32 variants
2. Keep memory usage optimized
3. Add comprehensive logging
4. Update documentation for any changes
5. Test on physical hardware when possible

## License

Licensed under the same terms as the rustls-rustcrypto project: Apache-2.0 or MIT.

## Related Documentation

- [ESP-IDF Programming Guide](https://docs.espressif.com/projects/esp-idf/)
- [Rust on ESP32](https://esp-rs.github.io/book/)
- [rustls Documentation](https://docs.rs/rustls/)
- [RustCrypto Documentation](https://docs.rs/rustcrypto/)