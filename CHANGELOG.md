# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- NIF Hex packaging now reads its source-file allowlist from the application's `.app.src` metadata, as required by rebar3_hex. Includes `VERSION` so consumers can attempt the matching prebuilt download; excludes CMake caches and native build output without requiring a clean checkout. Release version updates now target the same application metadata.
- Linux prebuilt selection now requires positive glibc detection. Alpine/musl and unavailable or unsupported libc probes fall back directly to source builds instead of attempting incompatible GNU/Linux binaries.
- Gleam packaging and publishing now use `gleam export hex-tarball` / `gleam publish`, preserving the NIF dependency and generated Erlang modules. Removed the competing rebar3 configuration and hand-written application metadata. Release CI publishes the Gleam package and exercises it from a separate consumer project.

## [0.3.0] - 2026-09-14

Security release. Closes a remotely reachable pre-authentication stack overflow in the Double Ratchet receive path (also fixed in 0.2.1), then authenticates the DR-HE header, separates header keys per direction, tags the session blob, and makes the documented API usable end to end -- the responder side could not previously be driven from the published functions at all.

**Wire and state formats both change.** 0.2.x peers cannot interoperate and persisted session blobs are rejected with `invalid_session_size`: `enc_header` grows 64 -> 80 bytes, the PreKeySignalMessage `identity_key` field changes encoding, and the DR state blob grows 2836 -> 7740 bytes behind a version tag. Re-run X3DH to establish fresh sessions.

### Security

- **Breaking (wire + session blob) -- authenticated DR-HE headers.** The encrypted header now carries a 16-byte HMAC-SHA-256 tag over `iv || ct`, keyed by a MAC key derived alongside the header cipher key (`HKDF(header_key, "WhisperHeader", L=64)`), and the receiver verifies it in constant time *before* any CBC decryption or protobuf parsing. Previously the header was bare CBC and every candidate header key was tried by decrypt-unpad-parse, so a forged header could drive up to `MAX_SKIP` chain derivations plus a DH ratchet before the outer MAC rejected it (a work-amplification and parse-oracle channel; state was never committed, so no key or plaintext exposure). `enc_header` grows from 64 to 80 bytes; 0.2.x peers cannot interoperate.
- **Breaking (session blob) -- per-direction header keys.** `next_header_key_send` and `next_header_key_recv` were both seeded from `shared_secret[64..96)`, so after the first ratchet each side's sending and receiving header keys coincided and a message reflected to its sender passed the header trial-decrypt. The X3DH output is now consumed as `root(32) || seed_a(32) || seed_b(32)` with the two seeds assigned mirror-wise by role (Signal's `shared_hka` / `shared_nhkb`); `shared_secret[32..64)` was previously unused. New `dr_he_envelope_SUITE:reflected_message_rejected` pins that a reflected message stops at `bad_mac` without ratchet work (pre-fix it surfaced `too_many_skipped`).
- **Breaking (session blob) -- MKSKIPPED grows to `3 * MAX_SKIP`.** A single receive that crosses a DH ratchet can bank up to `2 * MAX_SKIP` = 64 message keys, but the cache held only 32, so one legitimate ratchet message silently evicted every key still in flight from earlier receives and those messages became permanent `bad_mac`s. The cache is now 96 slots -- one budget above the worst single receive -- while `MAX_SKIP` stays a per-chain bound as the Signal spec defines it. (A shared per-receive budget was tried during development and reverted: it rejected ordinary reorders that 0.2 accepted, e.g. 29 skipped on the old chain plus 10 on the new.) New `double_ratchet_reorder_SUITE:skip_budget_is_per_chain` and `previous_receive_keys_survive_ratchet_skip`. Eviction beyond the new bound is still silent and still possible across three worst-case receives; see `docs/SECURITY.md`.
- **Breaking (session blob) -- tagged session blobs.** The blob now opens with an 8-byte `magic || version || size` tag checked on every load, and all four crossings of the NIF boundary go through a single `dr_state_load`/`dr_state_store` pair in `dr.c`. A blob from another release, or any buffer of the right length that is not one of ours, is rejected with `invalid_session` instead of being reinterpreted as root/chain/ratchet key material; a length mismatch still yields `invalid_session_size`. The loader also normalises the `bool` fields (`initialized`, `dh_recv_initialized`, every `mkskipped[i].occupied`), which previously held caller-supplied bytes and were read as `bool` -- undefined behaviour for any value other than 0 or 1. New `dr_he_bootstrap_SUITE:untagged_session_blob_rejected`, `wrong_size_session_blob_rejected`, and `corrupt_blob_never_crashes` (every byte position set to 0xFF must still yield a term, never a VM crash).
- **Breaking (API + PKSM wire) -- the responder side is usable from the documented API.** `generate_pre_key/1` now returns `{KeyId, Pub, Priv}` and `generate_signed_pre_key/2` returns `{KeyId, Pub, Priv, Signature}`; both previously zeroed and discarded the private half, so nothing the published API produced could later be passed to `process_pre_key_bundle_bob/5` -- every test and both wrapper READMEs routed around them with `signal_nif:generate_curve25519_keypair/0` + `sign_data/2`. Relatedly, the PreKeySignalMessage `identity_key` field now carries Alice's **Ed25519** identity pub instead of its X25519 form: `dr_init/5` and `process_pre_key_bundle_bob/5` both require Ed25519 and X25519 -> Ed25519 is not uniquely invertible, so Bob previously could not bootstrap from the envelope and had to obtain Alice's identity key out of band. `pksm_decode/1` now rejects a `base_key` or `identity_key` that is not exactly 32 bytes. The DR state carries the extra 32-byte Ed25519 pub (blob grows by 32 bytes). `pksm_SUITE` drives Bob entirely from `pksm_decode/1` output; new `decode_rejects_bad_key_lengths`.
- **Breaking (API removal) -- the static-key "simple session" is gone.** `create_session/2`, `encrypt_message/2` and `decrypt_message/2` are removed from the NIF, the Erlang module, and `LibsignalProtocol` (the Gleam wrapper never exposed them). They derived one ChaCha20-Poly1305 key used identically in both directions, with no AAD, no counter, and a 12-byte random nonce: a ciphertext one side produced also decrypted on that same side, messages replayed freely, and the nonce had a birthday bound near 2^32 messages per key. The `key`/`nonce` stack copies were also never zeroed and `create_session/2` allocated its output binary before the DH could fail. None of it was reachable from a correct Signal flow -- use `process_pre_key_bundle` -> `dr_init` -> `dr_encrypt`. With it go the `invalid_key_sizes`, `key_agreement_failed`, `invalid_session`(simple-session sense), and `invalid_message` atoms from that path.
- **Fixed before release (pre-release adversarial review).** `dr_encrypt_prekey/3` sized the PreKeySignalMessage buffer for "typical" key ids: the real worst case is 92 bytes of protobuf overhead (three uint32 ids at a 5-byte varint each), so Alice's very first message failed with `pksm_encode_failed` once a deployment's id space grew past small values. Sized from a new `PKSM_MAX_OVERHEAD`; covered by `pksm_SUITE:handshake_with_maximal_ids`.
- **Fixed before release.** `process_pre_key_bundle/2` inferred one-time-pre-key presence from `size >= 160`, so a padded bundle had trailing bytes read as a key and a 129..159-byte bundle silently dropped them. The length is now pinned to exactly 128 or 160 (`x3dh_forgery_SUITE:bundle_length_is_pinned`). Stripping the OPK from a real bundle still yields a valid 128-byte bundle -- that downgrade defeats the documented PKSM-replay mitigation and is now called out in `docs/SECURITY.md` as the embedder's to detect.
- **Fixed before release.** The MKSKIPPED trial loop called the header KDF once per occupied slot, repeating the same `HKDF(hk, "WhisperHeader")` up to 32 times per chain -- about 264 HMAC invocations of pure waste for a garbage packet. It now tries each distinct header key once. Slots whose header key is all-zero are skipped entirely, and `skip_message_keys` refuses to derive from a chain whose receive header key is still zero: such keys are publicly computable, so caching under one would let a third party forge a message that passes both MACs.
- **Fixed before release.** `dr_encrypt`, `dr_encrypt_prekey`, `dr_decrypt` and the `signal_nif` hashing/HMAC/AES-GCM entry points are marked `ERL_NIF_DIRTY_JOB_CPU_BOUND`. All do O(n) work over a caller- or peer-supplied binary with no size cap, which can hold a normal scheduler well past its 1 ms budget.
- **Fixed before release.** `dr_decrypt`'s plaintext buffer now honours OpenSSL's `inl + block_size` output contract (documented on `dr_aes_cbc_decrypt`) and is zeroed on the `decryption_failed` path too, where it already holds real plaintext. `dr_serialize_header` takes an output capacity and fails closed; `mkskipped_find` uses `sodium_memcmp`; a `_Static_assert` catches the session blob outgrowing its `uint16_t` size tag.
- **Breaking (wrappers) -- the Elixir and Gleam surfaces now match the NIF.** `SignalProtocol.PreKeyBundle` emitted a wrapper-local layout (`version || registration_id || key ids || keys...`) that `process_pre_key_bundle/2` always rejected, and its `verify_signature/1` only checked that the signature was 64 bytes long. It is replaced by a struct plus `encode/1`, `decode/1` and a real `verify_signature/1` over the NIF layout (`identity_key(32) || signed_pre_key(32) || signature(64) [|| one_time_pre_key(32)]`); the Gleam equivalents are `signal_protocol.encode_bundle` / `decode_bundle` with a `PreKeyBundle` record of the same shape, and the `pre_key_bundle` and `utils` modules (which FFI'd into the Elixir one) are deleted. The `LibsignalProtocol` module is gone -- `init/0` and `generate_identity_key_pair/0` live on `SignalProtocol`. The Gleam package no longer ships an OTP application callback and supervisor that supervised nothing.
- **Gleam errors are actually strings now.** Every Gleam external binds to `libsignal_protocol_gleam_ffi`, which converts the NIF's `{error, Atom}` to `{error, Binary}`. The declared `Result(_, String)` was previously a lie for every call bound straight to the NIF: `Error("bad_mac")` could not match and any `string` function applied to the error crashed.
- Both wrapper packages declare `{:libsignal_protocol_nif, "~> 0.3"}` / `libsignal_protocol_nif = ">= 0.3.0 and < 0.4.0"` as a dependency. Previously neither did, and a Hex consumer got `UndefinedFunctionError` -- the wrapper tests only worked because they walked the filesystem to the parent repo's `_build`. Those test hooks now use `add_patha` + purge so the working tree's NIF still takes precedence over the dependency copy during local development.
- **CRITICAL FIX**: `dr_decrypt` trial-decrypted the DR-HE `enc_header` into a fixed 64-byte stack buffer with no upper bound on the header length taken from the (not yet authenticated) outer envelope. A remote peer could send an oversized header and overwrite the receiver's stack before any MAC check. `dr_try_decrypt_header` now rejects any `enc_header` that is not exactly `DR_ENC_HEADER_LEN` -- the single length a legitimate sender can produce, 64 bytes when this was fixed in 0.2.1 and 80 after the header gained its MAC tag -- and additionally checks the caller's output capacity; `dr_decrypt` rejects the length once, before any header key is touched, with `{error, malformed_message}`. The sender enforces the same length and a `_Static_assert` ties it to the inner-header size bounds. New `dr_he_envelope_SUITE:wrong_size_enc_header_rejected` covers 0 B through 64 KiB headers, aligned and not.
- **Breaking** for callers that used keys longer than 32 bytes: `signal_nif:hmac_sha256/2` called libsodium's fixed-key `crypto_auth`, which always reads 32 key bytes: shorter keys caused an out-of-bounds read and longer keys were silently truncated to their first 32 bytes. It now uses `crypto_auth_hmacsha256_{init,update,final}` with the caller's actual key length, so output matches RFC 2104 / OTP `crypto:mac/4` for every key size. MACs computed by <= 0.2.0 with a key longer than 32 bytes will not verify against the corrected output (keys of exactly 32 bytes are unaffected; shorter keys previously produced undefined results). `crypto_adversarial_SUITE:adv_hmac_key_lengths_rfc4231` pins RFC 4231 known answers plus empty/32/64-byte keys (it replaces `adv_hmac_empty_key`, which had documented the over-read as accepted behaviour).
- `dr_aes_cbc_{encrypt,decrypt}` reject inputs larger than `INT_MAX` before the `int` cast into OpenSSL EVP; `signal_nif:aes_gcm_decrypt/6` compares `ExpectedPlaintextLen` against the ciphertext size as `size_t` after rejecting negatives.
- `libsignal_protocol_nif`'s `on_load` now calls `sodium_init()` and fails the module load if it returns an error. Previously only `signal_nif` initialised libsodium, so any deployment that loaded the main NIF alone (the Elixir wrapper never loads `signal_nif`) ran `randombytes_buf`/`crypto_box_keypair` against an uninitialised library, relying on libsodium's unlocked lazy first-use init across schedulers. The leftover `srand(time(NULL))` (nothing used `rand()`) is removed. `init/0` is unchanged in shape but is now documented as an optional no-op probe; the never-emitted `libsodium_init_failed` atom is dropped from `docs/API.md`.

### Changed

- **NIF loading.** Both stub modules now delegate to a single `src/libsignal_nif_loader.erl`: `code:priv_dir(libsignal_protocol_nif)` first, then `priv/` relative to CWD. Replaces two divergent loaders (one tried eight paths including a directory walk-up and was silent on failure; the other printed to stdout on every successful load). On failure `-on_load` returns `{error, {nif_not_found, Lib, [{Path, Reason}]}}` and the code server reports it; nothing is printed on success.
- **Build.** The `_build/*/lib/nif/priv` copy fan-out (Makefile targets and the `scripts/copy_nifs.sh` rebar3 post-compile hook) is removed -- nothing ever read those directories; rebar3 symlinks each profile's `priv` to the app's `priv/`. `make build`/`make ci-build` now fail if either `.so` is missing instead of hiding `cp` errors behind `|| true`. `c_src/CMakeLists.txt` fails configure with a clear message when `erl` cannot be run or `erl_nif.h` is not found. `c_src/build_nif.sh` is now included in the Hex tarball (the post-compile hook already referenced it; it was missing from the `files` list).
- **DR MAC via libsodium.** `dr_compute_mac` uses `crypto_auth_hmacsha256_{init,update,final}` instead of the OpenSSL `EVP_MAC` API, dropping a provider fetch + context allocation per message (and per trial-decrypt candidate on receive). Output is byte-identical. `dr.c` uses `sodium_memcmp` for the tag compare; OpenSSL is now used only for AES-256-CBC.
- `signal_nif:test_function/0` and `test_crypto/0` (bare `ok`/`crypto_ok` probes) and the public `load_nif/0` export are removed. Test suites gate on `code:ensure_loaded/1` via `dr_test_helpers:nif_or_skip/2`, which surfaces the real on_load error.
- `test/erl/unit/crypto/` is renamed to `test/erl/unit/primitives/`. As an `extra_src_dirs` entry, a code-path directory named `crypto` made `code:priv_dir(crypto)` resolve to it and OTP's `crypto` NIF failed to load inside every CT run.
- `session.c` and `signal_nif.c` use `enif_alloc`/`enif_free` instead of `malloc`/`free`; the protobuf varint codec is shared from `dr_proto.h` instead of being duplicated in `pksm.c`.
- Dead scripts removed: `scripts/{aggregate_coverage,monitor,test-build,test-ci-fixes,test_coverage_improvements,test_docker_build}.sh` and `config/build.config` (referenced deleted suites, nonexistent make targets, or a `priv/nif.dylib` that was never produced).
- `make docker-test`/`docker-perf` pass `-f docker/docker-compose.yml`; the compose file anchors build contexts and bind mounts at the repo root. CI's `elixir-version` matches `.tool-versions` (1.16.3).

### Documentation

- `docs/API.md`'s error table is generated from the atoms the C code actually emits, grouped by origin, and every documented return shape is exercised against the built NIF. The previously documented `mac_verification_failed`, `max_skip_exceeded`, `invalid_bundle`, `bundle_too_short` and `libsodium_init_failed` never existed; the real atoms are `bad_mac`, `too_many_skipped`, `invalid_bundle_size`, and so on. AES-GCM is documented as AES-256 / 12-byte IV / 16-byte tag only (what `signal_nif` enforces), and `signal_nif:verify_signature/3` is documented as answering with the bare atoms `ok` / `invalid_signature` rather than tuples.
- `docs/SECURITY.md` and `docs/ARCHITECTURE.md` describe the receive path as it ships: structural length checks, then a constant-time header-tag verify per candidate key, then the ratchet on a stack copy, then the outer MAC, then the body -- with nothing committed until the body decrypts. The remaining listed deviation from the Signal spec is Bob's initial ratchet key (his identity key rather than the signed pre-key), plus the encrypt-then-MAC header construction and the Ed25519 PKSM `identity_key` encoding. The session blob is described as a raw, unauthenticated, ABI-specific struct copy behind a version tag rather than a "sealed binary"; PKSM replay, one-time-pre-key deletion, OPK-stripping and responder identity pinning are called out.
- `docs/CROSS_LANGUAGE_COMPARISON.md` documents the bundle struct/record both wrappers serialize, and that Gleam errors are real `String`s now that every external routes through the FFI.
- Stale references removed: `.dylib` outputs, `erl_src/`, `session.ex`, `performance_test:run_benchmarks/0`, Erlang-level `init_double_ratchet` aliases, and the `.claude/TODO.md` pointer. `shell.nix` includes `openssl` (required by CMake) plus `elixir`/`gleam`. C comments describing the pre-DR-HE `DrMessage.payload` field and the pre-0.3 X3DH slot map are corrected; the dead `payload` fields are removed from `dr_message_t`.

## [0.2.0] - 2026-06-03

The Signal Protocol primitives are rewritten against the on-the-wire spec: X3DH, the Double Ratchet, header encryption (DR-HE), and PreKeySignalMessage are all implemented and tested across 10 CT suites. The 0.1 line shipped an HMAC-based bundle signature forgeable from any published bundle; that's fixed with real Ed25519 identities. Numerous breaking changes -- DR session blobs, bundle binaries, and DR wire messages from any 0.1.x release will not interoperate.

### Security

- **CRITICAL FIX**: Identity keys are now Ed25519 and signed pre-keys are signed with `crypto_sign_detached`. The 0.1 line used HMAC-SHA-512-256 with the identity *public* key as the MAC "secret" -- since the identity pub is published in bundles, any attacker who saw a bundle could forge a valid "signature" on any signed prekey. A network MITM could swap a victim's bundle for the attacker's signed prekey and `process_pre_key_bundle` would still accept it. With Ed25519, only the holder of the identity priv can produce a verifying signature.
- New `x3dh_forgery_SUITE` reproduces the pre-fix HMAC-based forgery and asserts it is now rejected with `signature_verification_failed`.
- `libsignal_protocol_nif:load_nif/0` now fails closed (`{error, _}` from `-on_load`) when the C NIF can't be found; previously it printed a warning and returned `ok`, leaving the module loaded with stubs.
- Plaintext-passthrough fallback functions are removed from `libsignal_protocol_nif.erl` -- they were never reachable, but were a trap that would have silently downgraded sessions to plaintext if wired in. The Elixir wrapper's matching `rescue UndefinedFunctionError -> mock` blocks (which *were* reachable) are also gone.
- The DR cipher's HMAC is verified before AES-CBC decrypt using `CRYPTO_memcmp`, closing the padding-oracle channel.

### Added

- **Double Ratchet** -- `dr_init/5`, `dr_encrypt/2`, `dr_decrypt/2` NIF entry points (the Elixir and Gleam wrappers expose them as `init_double_ratchet`, `dr_encrypt_message`, `dr_decrypt_message`; the Erlang module has no aliases). MKSKIPPED cache for out-of-order delivery: 32-slot bounded LRU keyed by `(header_key, message_number)`; `MAX_SKIP = 32` per receive to bound DOS.
- **Double Ratchet with header encryption (DR-HE)** -- inner header protobuf is AES-256-CBC'd under a separate header key so an on-path observer can't see `(ratchet_key, counter, previous_counter)`. Receive path trial-decrypts the encrypted header against the current header key, the next header key, and each MKSKIPPED entry's stored header key.
- **PreKeySignalMessage envelope** -- Alice's first message wraps the inner DR message in a Signal-spec PKSM protobuf so the receiver can identify which stored pre-keys to consume:
  - Wire shape: `version_byte(0x33) || protobuf{ registration_id=1, base_key=2, identity_key=3, pre_key_id=4 (optional), signed_pre_key_id=5, message=6 }`.
  - `identity_key` is sent in X25519 (DJB) form -- Alice's Ed25519 identity pub converted via `crypto_sign_ed25519_pk_to_curve25519`. Wire-spec compatible with libsignal.
  - New NIF entry points: `dr_encrypt_prekey/3` (encode) and `pksm_decode/1` (pure decode; returns a 6-tuple with `undefined` for an absent OPK id).
- `process_pre_key_bundle_bob/5` -- Bob's side of X3DH. Returns the same 96-byte shared secret Alice derived. Inputs: Bob's identity priv (Ed25519, 64B), SPK priv (X25519, 32B), OPK priv (X25519, 32B or `<<>>`), Alice's identity pub (Ed25519, 32B), Alice's ephemeral pub (X25519, 32B).
- `signal_nif:ed25519_sk_to_curve25519/1` and `ed25519_pk_to_curve25519/1` -- exposed so Erlang code can reconstruct Bob's X3DH via `crypto:compute_key(ecdh, _, _, x25519)`. Wrap `crypto_sign_ed25519_{sk,pk}_to_curve25519`.
- **Pre-built NIF binaries shipped from GitHub Releases.** A new `.github/workflows/release.yml` builds the NIF on `v*.*.*` tag push for three platforms (`aarch64-apple-darwin`, `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`) and attaches the resulting `libsignal_protocol_nif-<triplet>-<version>.tar.gz` files plus a `CHECKSUMS.txt` to the GitHub Release. The Hex package ships `c_src/build_nif.sh`, which runs at consumer `rebar3 compile` time, detects the platform via `uname`, downloads the matching tarball, and extracts the `.so` into `priv/`. Source-build fallback via cmake kicks in for unsupported platforms (including Intel Mac -- the free-tier macos-13 runner pool was too oversubscribed at release time to build x86_64-apple-darwin reliably) or download failures. `LIBSIGNAL_NIF_BUILD_FROM_SOURCE=1` opts out of the download path entirely. Checksum verification of downloaded tarballs is deferred to 0.2.1 -- 0.2.0 trusts HTTPS to GitHub Releases.
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
- DR NIF binding renames: `get_cache_stats` → `dr_init`, `reset_cache_stats` → `dr_encrypt`, `set_cache_size` → `dr_decrypt`. The wrapper-level names (`init_double_ratchet`, `dr_encrypt_message`, `dr_decrypt_message`) are unchanged, so Elixir and Gleam callers are unaffected.

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
