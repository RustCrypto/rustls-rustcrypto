## Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

## Tips
When contributing to this test crate:

1. Maintain compatibility with ESP32 variants
2. Keep memory usage optimized
3. Add comprehensive logging
4. Update documentation for any changes
5. Test on physical hardware when possible

## Related Documentation

- [ESP-IDF Programming Guide](https://docs.espressif.com/projects/esp-idf/)
- [Rust on ESP32](https://esp-rs.github.io/book/)
- [rustls Documentation](https://docs.rs/rustls/)
- [RustCrypto Documentation](https://docs.rs/rustcrypto/)
- [RustCrypto GitHub organization](https://github.com/RustCrypto)

## Testing Strategy

### Unit Tests
```bash
cargo test -p rustls-real-socket-test
```

### Integration Tests
```bash
cargo test --test integration
```
