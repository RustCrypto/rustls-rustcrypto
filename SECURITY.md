### Certificates

The two tests (real socket test and ESP32 test) uses embedded certificates (for now):
- **Server Certificate**: `cert.der` - ECDSA P-256 certificate
- **Private Key**: `key.der` - PKCS#8 encoded private key
- **Certificate Verification**: Custom verifier (accepts all for testing)

### Security Notes

⚠️ **WARNING**: The tests uses a dummy certificate verifier that accepts all certificates. This is for testing purposes only and should NEVER be used in production code.

## Performance Considerations for embedded

### Memory Usage
- Optimized for ESP32's limited RAM
- Uses static allocations where possible
- Minimal heap allocation during runtime

### CPU Usage
- ECC operations are computationally intensive
- Consider using hardware acceleration if available
- Profile with ESP-IDF tools for optimization