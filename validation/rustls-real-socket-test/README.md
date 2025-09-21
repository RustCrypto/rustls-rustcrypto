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
- Most operating system where Rust works
- Loopback interface available

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
