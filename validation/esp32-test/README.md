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

## License

Licensed under the same terms as the rustls-rustcrypto project: Apache-2.0 or MIT.
