# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-06-03

The Signal Protocol primitives are rewritten against the on-the-wire spec: X3DH, the Double Ratchet, header encryption (DR-HE), and PreKeySignalMessage are all implemented and tested across 10 CT suites. The 0.1 line shipped an HMAC-based bundle signature forgeable from any published bundle; that's fixed with real Ed25519 identities. Numerous breaking changes -- DR session blobs, bundle binaries, and DR wire messages from any 0.1.x release will not interoperate.

### Security

- **CRITICAL FIX**: Identity keys are now Ed25519 and signed pre-keys are signed with `crypto_sign_detached`. The 0.1 line used HMAC-SHA-512-256 with the identity *public* key as the MAC "secret" -- since the identity pub is published in bundles, any attacker who saw a bundle could forge a valid "signature" on any signed prekey. A network MITM could swap a victim's bundle for the attacker's signed prekey and `process_pre_key_bundle` would still accept it. With Ed25519, only the holder of the identity priv can produce a verifying signature.
- New `x3dh_forgery_SUITE` reproduces the pre-fix HMAC-based forgery and asserts it is now rejected with `signature_verification_failed`.
- `libsignal_protocol_nif:load_nif/0` now fails closed (`{error, _}` from `-on_load`) when the C NIF can't be found; previously it printed a warning and returned `ok`, leaving the module loaded with stubs.
- Plaintext-passthrough fallback functions are removed from `libsignal_protocol_nif.erl` -- they were never reachable, but were a trap that would have silently downgraded sessions to plaintext if wired in. The Elixir wrapper's matching `rescue UndefinedFunctionError -> mock` blocks (which *were* reachable) are also gone.
- The DR cipher's HMAC is verified before AES-CBC decrypt using `CRYPTO_memcmp`, closing the padding-oracle channel.

### Added

- **Double Ratchet** -- `dr_init/5`, `dr_encrypt/2`, `dr_decrypt/2` NIF entry points with Erlang aliases `init_double_ratchet`, `dr_encrypt_message`, `dr_decrypt_message`. MKSKIPPED cache for out-of-order delivery: 32-slot bounded LRU keyed by `(header_key, message_number)`; `MAX_SKIP = 32` per receive to bound DOS.
- **Double Ratchet with header encryption (DR-HE)** -- inner header protobuf is AES-256-CBC'd under a separate header key so an on-path observer can't see `(ratchet_key, counter, previous_counter)`. Receive path trial-decrypts the encrypted header against the current header key, the next header key, and each MKSKIPPED entry's stored header key.
- **PreKeySignalMessage envelope** -- Alice's first message wraps the inner DR message in a Signal-spec PKSM protobuf so the receiver can identify which stored pre-keys to consume:
  - Wire shape: `version_byte(0x33) || protobuf{ registration_id=1, base_key=2, identity_key=3, pre_key_id=4 (optional), signed_pre_key_id=5, message=6 }`.
  - `identity_key` is sent in X25519 (DJB) form -- Alice's Ed25519 identity pub converted via `crypto_sign_ed25519_pk_to_curve25519`. Wire-spec compatible with libsignal.
  - New NIF entry points: `dr_encrypt_prekey/3` (encode) and `pksm_decode/1` (pure decode; returns a 6-tuple with `undefined` for an absent OPK id).
- `process_pre_key_bundle_bob/5` -- Bob's side of X3DH. Returns the same 96-byte shared secret Alice derived. Inputs: Bob's identity priv (Ed25519, 64B), SPK priv (X25519, 32B), OPK priv (X25519, 32B or `<<>>`), Alice's identity pub (Ed25519, 32B), Alice's ephemeral pub (X25519, 32B).
- `signal_nif:ed25519_sk_to_curve25519/1` and `ed25519_pk_to_curve25519/1` -- exposed so Erlang code can reconstruct Bob's X3DH via `crypto:compute_key(ecdh, _, _, x25519)`. Wrap `crypto_sign_ed25519_{sk,pk}_to_curve25519`.
- **Pre-built NIF binaries shipped from GitHub Releases.** A new `.github/workflows/release.yml` builds the NIF on `v*.*.*` tag push for four platforms (`aarch64-apple-darwin`, `x86_64-apple-darwin`, `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`) and attaches the resulting `libsignal_protocol_nif-<triplet>-<version>.tar.gz` files plus a `CHECKSUMS.txt` to the GitHub Release. The Hex package ships `c_src/build_nif.sh`, which runs at consumer `rebar3 compile` time, detects the platform via `uname`, downloads the matching tarball, and extracts the `.so`/`.dylib` into `priv/`. Source-build fallback via cmake kicks in for unsupported platforms or download failures. `LIBSIGNAL_NIF_BUILD_FROM_SOURCE=1` opts out of the download path entirely. Checksum verification of downloaded tarballs is deferred to 0.2.1 -- 0.2.0 trusts HTTPS to GitHub Releases.
- Wrappers expose the Double Ratchet + X3DH + PKSM surface:
  - Elixir: `SignalProtocol.init_double_ratchet/5`, `dr_encrypt_message/2`, `dr_decrypt_message/2`, `dr_encrypt_prekey/3`, `pksm_decode/1`, `process_pre_key_bundle/2`, `process_pre_key_bundle_bob/5`.
  - Gleam: `signal_protocol.init_double_ratchet`, `dr_encrypt_message`, `dr_decrypt_message`, `dr_encrypt_prekey`, `pksm_decode`, `process_pre_key_bundle`, `process_pre_key_bundle_bob`, plus typed `DrSession`, `DrRole.Alice|Bob`, and `PreKeyInfo` records.
  - Gleam adds `libsignal_protocol_gleam_ffi` to translate Gleam's `Option(Int)` to the NIF's `Int | undefined` for the optional pre-key id field.
- New CT suites under `test/erl/unit/{crypto,protocol}/`: `crypto_properties_SUITE`, `crypto_adversarial_SUITE`, `double_ratchet_SUITE`, `double_ratchet_reorder_SUITE`, `dr_he_bootstrap_SUITE`, `dr_he_cross_decrypt_SUITE`, `dr_he_envelope_SUITE`, `pksm_SUITE`, `x3dh_dr_compose_SUITE` (full Alice ↔ Bob flow including an Erlang-side cross-check that Bob's X3DH reconstruction matches Alice's NIF output), `x3dh_forgery_SUITE`.

### Changed -- DR protocol (breaking, wire-incompatible with 0.1.x)

- **DR chain advance** -- HMAC-SHA-256 (was HMAC-SHA-512-256 via `crypto_auth`). Constants flipped to spec: chain key uses `0x02`, message key uses `0x01` (was reversed).
- **KDF throughout** -- HKDF-SHA-256 (RFC 5869), replacing BLAKE2b. Info strings: `"DR-RK"` for the DR root chain, `"X3DH-Signal"` for X3DH, `"WhisperMessageKeys"` for the per-message KDF, `"WhisperHeader"` for DR-HE header keys.
- **DH output** -- raw X25519 (`crypto_scalarmult`), replacing `crypto_box_beforenm` (which applied HSalsa20 on top of X25519). Brings the DH primitive in line with Signal spec and makes Bob-side X3DH reconstruction implementable in Erlang.
- **DR wire format** -- serialized protobuf `DrMessage { ratchet_key=1, counter=2, previous_counter=3, ciphertext=4 }` matching the Signal `SignalMessage` shape. Hand-rolled varint + length-delimited encoder/decoder in `c_src/dr_proto.c`. Malformed wire input returns `malformed_message`.
- **DR AEAD** -- AES-256-CBC + HMAC-SHA-256(8), Signal-spec:
  - 32-byte `messageKey` → `HKDF-SHA-256(salt=zeros, IKM=messageKey, info="WhisperMessageKeys", L=80)` → `cipher_key(32) || mac_key(32) || iv(16)`. No random nonce; the IV is HKDF-derived per message.
  - Body: `AES-256-CBC(cipher_key, iv, plaintext)` with PKCS#7 padding.
  - MAC: `HMAC-SHA-256(mac_key, sender_id_pub(32) || receiver_id_pub(32) || version(1) || serialized_DrMessage)` truncated to 8 bytes, verified before decrypt via `CRYPTO_memcmp`.
  - Wire envelope (without DR-HE): `version_byte(0x33) || serialized_DrMessage || mac(8)`.
- **DR-HE wire format** -- inner header protobuf is AES-256-CBC'd. Final envelope: `version_byte(0x33) || protobuf{ enc_header=1, ciphertext=2 } || mac(8)`, where `enc_header = iv(16) || AES-256-CBC(header_cipher_key, iv, inner_header_protobuf)`. `header_cipher_key = HKDF-SHA-256(salt=zeros, IKM=header_key, info="WhisperHeader", L=32)`. Outer MAC scope now covers the encrypted header.
- **DR state size** -- grew from ~200 B (0.1.x) to ~2.6 KB. MKSKIPPED + DR-HE header keys (`header_key_send`, `header_key_recv`, `next_header_key_send`, `next_header_key_recv`) account for the bulk. MKSKIPPED entries are keyed by `(header_key, message_number)` instead of `(dh_pub, message_number)`. Sessions persisted across the upgrade fail with `invalid_session_size`.
- **OpenSSL is now a build dependency.** AES-256-CBC isn't in libsodium. CMake does `find_package(OpenSSL REQUIRED)`; on macOS the build auto-discovers Homebrew's keg-only `openssl@3`.

### Changed -- API surface (breaking)

- `init_double_ratchet/3` → `/5`. Two arity bumps: `/3 → /4` added the explicit `IsAlice` flag and split `RemoteIdentityPub` / `SelfIdentityPriv` so a bidirectional channel actually works. `/4 → /5` added `LocalIdentityPub` so both identity pubs are folded into the Signal-spec MAC scope. New signature: `init_double_ratchet(SharedSecret, LocalIdentityPub, RemoteIdentityPub, SelfIdentityPriv, IsAlice)`.
- `process_pre_key_bundle/2` and `process_pre_key_bundle_bob/5` return a 96-byte shared secret (was 64 bytes). The first 64 bytes are the original X3DH SK (bit-identical, extended via HKDF-Expand by one more output block); the trailing 32 bytes are a shared header-key seed for DR-HE. `init_double_ratchet/5`'s `SharedSecret` argument requires exactly 96 bytes; the old 64-byte SK is rejected with `invalid_shared_secret_size`.
- DR NIF binding renames: `get_cache_stats` → `dr_init`, `reset_cache_stats` → `dr_encrypt`, `set_cache_size` → `dr_decrypt`. The Erlang aliases (`init_double_ratchet`, `dr_encrypt_message`, `dr_decrypt_message`) are unchanged, so public callers are unaffected.

### Changed -- Ed25519 identity (breaking)

- `libsignal_protocol_nif:generate_identity_key_pair/0` returns a 32-byte Ed25519 public key + **64-byte** Ed25519 private key (was 32-byte X25519 pub + 32-byte X25519 priv).
- `libsignal_protocol_nif:generate_signed_pre_key(IdentityPriv, KeyId)` takes a 64-byte Ed25519 priv and returns a **64-byte** Ed25519 signature (was 32-byte HMAC).
- Bundle binary format grew: `id_pub(32) ++ spk_pub(32) ++ signature(64) ++ [opk(32)]` (signature was 32B, now 64B). Minimum bundle size: 128 bytes.
- `init_double_ratchet/5` expects Ed25519 identity keys on both sides; conversion to X25519 for DH happens inside the NIF.
- Gleam `IdentityKeyPair` field renamed: `signature` → `private_key` (the field always held the private key; the old name was actively dangerous).

### Changed -- `signal_nif` Ed25519 representation (breaking)

- `signal_nif:generate_ed25519_keypair/0` returns the full 64-byte libsodium SK (`seed || derived pub`) instead of the 32-byte seed. Matches `libsignal_protocol_nif:generate_identity_key_pair/0` so callers can hand keys between the two NIFs without binary-part juggling.
- `signal_nif:sign_data/2` accepts a 64-byte SK (was 32-byte seed). The internal `crypto_sign_seed_keypair` regeneration is gone -- the SK is passed straight to `crypto_sign_detached`. Side effect: signing throughput roughly 2x faster (~34us → ~17us p50 on Apple Silicon).
- `signal_nif:ed25519_sk_to_curve25519/1` was already 64-byte; unchanged.

### Changed -- crypto wrapper API surface (breaking)

- Removed `SignalProtocol.create_session/2`, `encrypt_message/2`, `decrypt_message/2` from the Elixir wrapper. They had `is_reference(session)` guards that never matched the binary the NIF returns -- unreachable. The NIF still exports them for direct Erlang callers; wrapper users should use the DR flow: `process_pre_key_bundle` → `init_double_ratchet` → `dr_encrypt_message`.
- Removed `signal_protocol.{create_session, create_session_with_keys, encrypt_message, decrypt_message, create_and_process_bundle, send_message, receive_message}` plus the `Session` type from the Gleam wrapper. Same rationale.
- Removed `SignalProtocol.Session` module (`wrappers/elixir/lib/session.ex`) -- pure passthrough with a fixed pattern bug; no longer needed.
- Removed `SignalProtocol.start_link/1` and its GenServer -- the `handle_call` passthroughs added nothing over direct module calls.

### Changed -- runtime

- macOS NIF builds emit `.so` (was `.dylib`) to match what BEAM looks for.
- Unit test profile no longer pinned to `signal_crypto_SUITE`; `make test-unit` runs every suite under `test/erl/unit/`.

### Fixed

- DR receive ratchet now derives the recv chain key before the new send chain (per Signal DR spec §3.5). Prior code only did the send-side KDF, leaving Bob unable to decrypt Alice's messages after his first reply.

### Removed

- `libsignal_protocol_nif_v2` NIF (623 C + 64 Erlang lines) -- no callers, no tests, no documented purpose.
- ~360 lines of unbound C in `libsignal_protocol_nif.c` (older DR encrypt/decrypt pair, helpers never exported).
- `c_src/{protocol,crypto,session,keys,cache,utils}/`, `c_src/nif.c`, `c_src/types.h`, `c_src/constants.h` -- 3379 LOC of dead C never referenced by `CMakeLists.txt`.
- **Breaking**: `:libsignal_protocol_nif.create_session/1` -- semantically broken (hash of a public key + 32 random bytes; no actual key agreement). `create_session/2` (proper Curve25519 DH) is unchanged.
- 12 dead test suites total across the cleanup passes: `nif_cache_SUITE`, `coverage_test_SUITE`, `nif_functions_SUITE`, `crypto_wrapper_SUITE`, `session_SUITE`, `protocol_SUITE`, `session_management_SUITE`, `signal_session_SUITE`, `integration_SUITE`, `signal_protocol_test_SUITE`, `smoke/debug_module_SUITE`, `smoke/simple_module_test_SUITE`. All referenced non-existent `:nif` / `signal_crypto` modules.
- Stale duplicate test trees `test/elixir/*.exs` and `test/gleam/*.gleam` -- never run, drifted from the wrapper-local trees.
- `wrappers/gleam/src/session.gleam` + `wrappers/gleam/test/session_test.gleam` -- every function passed a session ref where the NIF expects a 32-byte identity priv. Mismatch was structural.

### Refactored

- C side split per concern: `signal_nif.c`, `libsignal_protocol_nif.c`, `dr.c`, `dr_chain.c`, `dr_crypto.c`, `dr_proto.c`, `pksm.c`, `session.c`, `keys.c`. The CMake target list is the source of truth for what gets built.
- `LibsignalProtocol` (Elixir wrapper) -- 113 → 36 LOC. Removed try/rescue/catch boilerplate; mirrors NIF return atoms verbatim (no rename, no wrap).
- `signal_protocol.gleam` -- `case` chains replaced with `result.try` / `use`. Real bundle serializer (`to_binary/1`) matches the C NIF's expected layout.
- Wrapper tests rewritten: `wrappers/elixir/test/signal_protocol_test.exs` was 118 LOC of calls to functions that don't exist; replaced with 23 LOC against the real API. `wrappers/elixir/test/pre_key_bundle_test.exs` was 340 LOC with a CompileError plus 35 references to a non-existent `:nif` module; replaced with 51 LOC covering `create/5` ↔ `parse/1` round-trip and `verify_signature/1`.
- Documentation consolidated: top-level README, wrapper READMEs, `CONTRIBUTING.md`, `docs/API.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/CROSS_LANGUAGE_COMPARISON.md` all rewritten against the real 0.2.0 API. Removed `docs/IMMEDIATE_ACTIONS.md`, `docs/IMPLEMENTATION.md`, `docs/DOCUMENTATION_PLAN.md` (redundant / aspirational).
- `Makefile`: cleaned dead `CFLAGS` / `LDFLAGS` / `ERLANG_PATH` / `ERL_INTERFACE_PATH` / `SHARED_EXT` block (cmake handles flags). Removed `perf-monitor`, `monitor-memory`, `monitor-cache` -- they called stub functions. Added `perf-quick` and `perf-baseline`. Fixed `-pa` paths so `perf-test` actually finds the compiled beams.
- `performance_test.erl` rebuilt -- 322 LOC of real benchmarks against the 0.2 API, replacing 368 LOC of broken / stub code. Reports min / p50 / p95 / p99 / throughput, compares against a checked-in `baseline.term`, tags regressions over 20%.

### CI

- Bumped `aquasecurity/trivy-action` from `0.16.1` (missing) to `v0.36.0`.
- Bumped `actions/checkout` v4.1.1 → v5, `actions/cache` v4 → v5, `erlef/setup-beam` v1.18.0 → v1.24.0, `docker/setup-buildx-action` v3 → v4, `docker/login-action` v3 → v4. Clears the Node.js 20 deprecation deadline (2026-06-16).
- Removed the codecov upload step (was failing every run, masked by `continue-on-error: true`).
- Tightened the Elixir wrapper test step: no more `mix test || { ... }` swallowing failures.
- `rebar3 format` applied to all test suites; `rebar3 format --verify` runs in CI.
- Fixed Erlang hex literal misuse (`16#FFFFFFFF` instead of `0xFFFFFFFF`) in an Elixir test.

## [0.1.1] - 2024-07-07

### Added

- Improved README badges with clear language labels
- Comprehensive security documentation (SECURITY.md)
- Quick start guide (later folded into the top-level README)
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

- Trimmed trailing whitespace in VERSION file.
- Resolved gleeunit API changes (`should.fail()` -> `panic()`).
- Fixed type mismatches in Gleam test files (`String` -> `BitArray`).
- Resolved dependency resolution conflicts between Gleam versions.
- Corrected unused-variable warnings in test code.

## [0.1.0] - 2024-07-06

### Added

- Curve25519 (X25519 ECDH) and Ed25519 keygen, sign/verify, all via libsodium.
- SHA-256, SHA-512, HMAC-SHA-256.
- AES-GCM encrypt/decrypt with configurable tag length and AAD.
- Erlang, Elixir, and Gleam wrappers.
- CMake build, Nix dev shell, Docker image, CI for Linux and macOS.
- CT suites covering each primitive.

### Security

- `sodium_memzero` on sensitive scratch buffers.
- Constant-time primitives via libsodium.
- Input validation on all NIF entry points.

## [0.0.1] - Initial Development

- Initial project structure, NIF scaffolding, build system.
