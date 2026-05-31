# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Double Ratchet implementation (`init_double_ratchet/4`, `dr_encrypt_message/2`, `dr_decrypt_message/2`) backed by `dr_init/4`, `dr_encrypt/2`, `dr_decrypt/2` NIF functions.
- MKSKIPPED cache for out-of-order DR delivery. Bounded LRU (32 slots) keyed by `(dh_pub, message_number)`; `MAX_SKIP = 32` per receive to bound DOS.
- Test suites: `crypto_properties_SUITE`, `crypto_adversarial_SUITE`, `double_ratchet_SUITE`, `double_ratchet_reorder_SUITE`.

### Changed

- **Breaking**: `signal_nif:generate_curve25519_keypair/0` now returns `{ok, {Pub, Priv}}` (was `{ok, {Priv, Pub}}`).
- **Breaking**: `libsignal_protocol_nif:init_double_ratchet/3` → `/4` — added an explicit `IsAlice` flag and split the `RemoteIdentityPub` / `SelfIdentityPriv` arguments. The prior 3-arg form never produced a working bidirectional channel.
- **Breaking**: DR NIF binding names: `get_cache_stats` → `dr_init`, `reset_cache_stats` → `dr_encrypt`, `set_cache_size` → `dr_decrypt`. The Erlang aliases `init_double_ratchet`, `dr_encrypt_message`, `dr_decrypt_message` are unchanged, so public callers are unaffected.
- **Breaking**: DR session binary grew from ~200 B to ~2.6 KB (MKSKIPPED storage). Sessions persisted across the upgrade will fail with `invalid_session_size`.
- `libsignal_protocol_nif:load_nif/0` now fails closed (`{error, _}` from `-on_load`) when the C NIF can't be found; previously it printed a warning and returned `ok`, leaving the module loaded with stubs.
- macOS NIF builds now emit `.so` (was `.dylib`) to match what BEAM looks for.
- Unit test profile no longer pinned to `signal_crypto_SUITE`; `make test-unit` runs every suite under `test/erl/unit/`.

### Fixed

- DR receive ratchet now derives the recv chain key before the new send chain (per Signal DR spec §3.5). Previous version only did the send-side KDF, leaving Bob unable to decrypt Alice's messages after his first reply.

### Removed

- `libsignal_protocol_nif_v2` NIF (623 C + 64 Erlang lines) — no callers, no tests, no documented purpose.
- ~360 lines of unbound C functions in `libsignal_protocol_nif.c` (older DR encrypt/decrypt pair, helper that was never exported).
- 8 dead test suites referencing non-existent modules (`nif`, `signal_crypto`, `signal_session`, `protocol`) plus the dead `test_cache_management` function in `signal_protocol_test_SUITE`.
- Plaintext-passthrough fallback functions in `libsignal_protocol_nif.erl` and the deleted `_v2.erl`. They were never reachable (public functions already fired `nif_error`), but the dead code was a trap: any future wiring would have silently downgraded sessions to plaintext.

### Security

- Removed plaintext-passthrough fallback trap (see Removed above) and made `load_nif/0` fail closed — a NIF load failure now refuses to load the module rather than leaving it loaded with stubs.

### CI

- Bumped `aquasecurity/trivy-action` from `0.16.1` (missing) to `v0.36.0`.
- `rebar3 format` applied to all test suites.
- Fixed Erlang hex literal (`16#FFFFFFFF`) misused in the Elixir wrapper test (`0xFFFFFFFF`).

## [0.1.1] - 2024-07-07

### Added

- Improved README badges with clear language labels
- Comprehensive security documentation (SECURITY.md)
- Quick start guide (IMMEDIATE_ACTIONS.md)
- This changelog file
- Separate Gleam wrapper CI workflow for isolated testing
- Manual trigger capability for Gleam tests with workflow_dispatch

### Changed

- Cleaned up project root (removed crash dump files)
- Improved documentation structure and references
- Upgraded Gleam CI from v1.7.0 to v1.11.0 for compatibility
- Updated gleam_stdlib from 0.38.0 to 0.60.0
- Updated gleeunit from 0.8.0 to 1.6.0
- Separated Gleam wrapper testing from main CI pipeline for faster builds

### Fixed

- Trimmed trailing whitespace in VERSION file
- Fixed Gleam wrapper CI compatibility issues with version matrix
- Resolved gleeunit API changes (should.fail() → panic())
- Fixed type mismatches in Gleam test files (String → BitArray)
- Corrected unused variable warnings in test code
- Resolved dependency resolution conflicts between Gleam versions

### Technical Improvements

- **CI Performance**: Main CI now runs faster without Gleam compilation
- **Isolated Testing**: Gleam issues no longer block main pipeline
- **Version Compatibility**: All dependencies now properly aligned
- **Test Reliability**: Fixed compilation errors in Gleam test suite

## [0.1.0] - 2024-07-06

### Added

- Complete cryptographic implementation using libsodium
- Curve25519 key pair generation (X25519 ECDH)
- Ed25519 key pair generation and digital signatures
- SHA-256 and SHA-512 hashing functions
- HMAC-SHA256 authentication
- AES-GCM encryption/decryption with authenticated encryption
- Comprehensive test suite for all cryptographic operations
- Multi-language support with Erlang, Elixir, and Gleam wrappers
- Cross-platform build system (Linux, macOS, Windows)
- Nix-based development environment
- Docker support for containerized builds
- Comprehensive documentation including:
  - API reference documentation
  - Architecture and implementation details
  - Cross-language comparison guide
  - Contributing guidelines
- Memory-safe implementation with proper cleanup
- Error handling and input validation
- Performance optimizations

### Security

- Secure memory management with `sodium_memzero()`
- Constant-time cryptographic operations via libsodium
- Proper key validation and error handling
- No sensitive data logging or exposure

### Technical Details

- **Erlang NIF**: High-performance native implementation
- **libsodium**: Industry-standard cryptographic library
- **CMake**: Cross-platform build system
- **rebar3**: Erlang build tool and package manager
- **Hex.pm**: Package distribution for all BEAM languages

## [0.0.1] - Initial Development

### Added

- Initial project structure
- Basic NIF scaffolding
- Build system setup
- Development environment configuration

---

## Release Notes

### Version 0.1.1 - "CI Stability & Compatibility"

This release focuses on improving the CI/CD pipeline stability and fixing compatibility issues across all language wrappers. The main CI pipeline is now faster and more reliable, while Gleam wrapper testing has been isolated for better development workflow.

**Key Improvements:**

- ✅ **CI Performance**: Main pipeline runs 40% faster without Gleam compilation
- ✅ **Version Compatibility**: All Gleam dependencies properly aligned
- ✅ **Isolated Testing**: Gleam issues no longer block other language tests
- ✅ **Manual Control**: Gleam tests can be run on-demand when needed
- ✅ **Fixed Compilation**: All test files now compile without errors

**Technical Changes:**

- **Gleam**: Upgraded from 1.7.0 → 1.11.0
- **gleam_stdlib**: Upgraded from 0.38.0 → 0.60.0  
- **gleeunit**: Upgraded from 0.8.0 → 1.6.0
- **CI Structure**: Separated into main + dedicated Gleam workflows

**Breaking Changes:**

- None - this is a patch release with only CI improvements

### Version 0.1.0 - "Crypto Complete"

This is the first stable release of libsignal-protocol-nif, featuring a complete implementation of Signal Protocol cryptographic primitives. The library provides high-performance, memory-safe cryptographic operations for Erlang, Elixir, and Gleam applications.

**Key Features:**

- ✅ All major cryptographic primitives implemented
- ✅ Comprehensive test coverage
- ✅ Multi-language wrapper support
- ✅ Production-ready security measures
- ✅ Cross-platform compatibility

**Performance:**

- Optimized for high-throughput applications
- Memory-efficient with proper cleanup
- Minimal overhead NIFs

**Security:**

- Based on audited libsodium library
- Constant-time operations
- Secure memory management
- Comprehensive input validation

### Migration Guide

This is the initial release, so no migration is needed. For future releases, migration guides will be provided here.

### Known Issues

- None currently identified

### Supported Platforms

- **Linux**: x86_64, ARM64
- **macOS**: Intel, Apple Silicon
- **Windows**: x86_64 (experimental)

### Dependencies

- **Erlang/OTP**: 24.0 or later
- **libsodium**: 1.0.18 or later
- **CMake**: 3.15 or later
- **rebar3**: 3.20 or later

### Contributors

- [@hydepwns](https://github.com/hydepwns) - Initial implementation and maintenance

---

## Future Roadmap

### Planned Features

- [ ] Additional Signal Protocol features (if needed)
- [ ] Performance benchmarking suite
- [ ] Windows native support improvements
- [ ] Additional language wrappers (Rust, Go, etc.)
- [ ] Hardware security module (HSM) support
- [ ] Formal security audit

### Long-term Goals

- Become the reference implementation for Signal Protocol cryptography in BEAM languages
- Maintain compatibility with Signal Protocol specification updates
- Provide the highest performance cryptographic operations for Erlang ecosystem
