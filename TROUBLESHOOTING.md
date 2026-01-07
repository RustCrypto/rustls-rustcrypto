## Troubleshooting (for ESP32 integration test)

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