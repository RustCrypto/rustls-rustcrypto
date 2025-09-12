# Rustls Real Socket Test

A comprehensive test suite for validating TLS functionality using real network sockets with the rustls-rustcrypto provider. This crate performs end-to-end TLS testing in standard Rust environments, ensuring secure communication works correctly across different platforms.

## Overview

This test crate demonstrates and validates:

- TLS 1.2 and TLS 1.3 handshake completion
- Secure communication over real TCP sockets
- Certificate-based authentication
- Client-server TLS communication
- RustCrypto provider integration
- Cross-platform TLS capabilities

## Architecture

The test implements a complete TLS client-server architecture:

1. **TLS Server**: Runs locally, accepts connections, performs TLS handshake
2. **TLS Client**: Also runs locally, connects to server, sends test messages
3. **Real Sockets**: Uses actual TCP sockets (not mock implementations)
4. **Embedded Certificates**: Includes test certificates compiled into the binary

## Features

- ✅ TLS 1.2 and TLS 1.3 support
- ✅ ECDSA certificate authentication
- ✅ AES-GCM and ChaCha20-Poly1305 ciphers
- ✅ Real network socket communication
- ✅ Embedded certificate validation
- ✅ Cross-platform compatibility
- ✅ Comprehensive logging
- ✅ Environment variable configuration

## Prerequisites

### Software Requirements
- Rust 1.88.0 or later
- Cargo package manager
- OpenSSL (for certificate generation if needed)

### System Requirements
- Linux, macOS, or Windows
- Network interface available
- No firewall blocking local connections

## Installation

### Clone and Setup
```bash
# From the rustls-rustcrypto workspace root
cd validation/rustls-real-socket-test

# Build the test
cargo build --release
```

### Dependencies

The crate uses the following key dependencies:

- `rustls` 0.23.x - TLS library
- `rustls-rustcrypto` - RustCrypto provider (workspace)
- `anyhow` - Error handling
- `log` - Logging framework
- `env_logger` - Environment-based logging

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
    "der",
    "fast",
    "kx-p256",
    "pkcs8",
    "sign-ecdsa-p256",
    "std",
    "tls12",
    "verify-ecdsa-p256-sha256"
]
```

### Environment Variables

Configure runtime behavior:

```bash
# Set log level
export RUST_LOG=trace

# Custom server address (optional)
export TLS_TEST_SERVER_ADDR=127.0.0.1:8443

# Enable debug output
export RUST_BACKTRACE=1
```

## Usage

### Running the Test

1. **Execute the test**:
```bash
cargo run --release
```

2. **With custom logging**:
```bash
RUST_LOG=debug cargo run
```

3. **With full trace logging**:
```bash
RUST_LOG=trace cargo run
```

### Expected Output

The test will show:
```
Rustls Real Socket TLS Test Starting...
Rustcrypto provider initialized
TLS client config created successfully
TLS server config created successfully
TLS server listening on 127.0.0.1:xxxxx
Accepted connection from 127.0.0.1:xxxxx
TLS handshake completed successfully
Server received: Hello from Rustls client!
Client received: Echo: Hello from Rustls client!
TLS client shutting down
TLS server shutting down
Rustls Real Socket TLS Test completed!
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

#### Network Connection Failures
- Ensure no firewall is blocking local connections
- Check that the port range is available (test uses random ports)
- Verify network interface is up and configured

#### TLS Handshake Failures
- Ensure certificates are properly embedded
- Check cipher suite compatibility
- Verify TLS version support
- Confirm RustCrypto provider is correctly initialized

#### Build Issues
- Verify Rust version meets minimum requirements
- Check that all dependencies are available
- Ensure workspace path is correct for rustls-rustcrypto

#### Runtime Errors
- Check available system resources (memory, file descriptors)
- Verify no other processes are using the test ports
- Monitor system logs for additional error information

### Debugging

Enable detailed logging:
```bash
# Debug level
RUST_LOG=debug cargo run

# Trace level (very verbose)
RUST_LOG=trace cargo run

# Specific module logging
RUST_LOG=rustls=debug,rustls_rustcrypto=trace cargo run
```

Common debug commands:
```bash
# Check network connectivity
ping 127.0.0.1

# Check port availability
netstat -an | grep LISTEN

# Monitor with system tools
strace cargo run  # Linux
dtruss cargo run  # macOS
```

## Performance Considerations

### Memory Usage
- Minimal heap allocation
- Static certificate data
- Efficient buffer management

### CPU Usage
- ECC operations are computationally intensive
- Consider CPU architecture optimizations
- Profile with cargo flamegraph for bottlenecks

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

### Multi-threading
```rust
// Add thread pools for concurrent testing
use std::thread;
use std::sync::mpsc;

// Implement concurrent client connections
```

## Integration with CI/CD

This test can be integrated into automated testing pipelines:

```yaml
# Example GitHub Actions workflow
name: Real Socket TLS Test
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo build --release -p rustls-real-socket-test
      - run: cargo run -p rustls-real-socket-test
```

### Cross-Platform Testing

Test on multiple platforms:
```yaml
jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    steps:
      - uses: actions/checkout@v3
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test -p rustls-real-socket-test
```

## Testing Strategy

### Unit Tests
```bash
cargo test -p rustls-real-socket-test
```

### Integration Tests
```bash
cargo test --test integration
```

### Benchmarking
```bash
cargo bench -p rustls-real-socket-test
```

## Contributing

When contributing to this test crate:

1. Maintain cross-platform compatibility
2. Add comprehensive error handling
3. Include detailed logging for debugging
4. Update documentation for any changes
5. Test on multiple platforms when possible
6. Follow Rust best practices and idioms

## License

Licensed under the same terms as the rustls-rustcrypto project: Apache-2.0 or MIT.

## Related Documentation

- [Rust Documentation](https://doc.rust-lang.org/)
- [rustls Documentation](https://docs.rs/rustls/)
- [RustCrypto Documentation](https://docs.rs/rustcrypto/)
- [Cargo Documentation](https://doc.rust-lang.org/cargo/)