# Security notes

What this library protects, what it doesn't, and what's still aspirational.

## Status

Not externally audited. No third-party security review has been done on the NIF, the protocol composition, or the wrappers. libsodium (the crypto primitives underneath) and OpenSSL (the AES-256-CBC implementation for the DR cipher) are audited, widely deployed libraries -- but how we compose them has only been reviewed in-house.

If you're considering this for production, treat it as pre-audit and pin a specific version.

## What's implemented

- **X3DH** key agreement (RFC-style; Signal info string variation noted below).
- **Double Ratchet with header encryption (DR-HE)** matching the Signal wire format: AES-256-CBC + HMAC-SHA-256 truncated to 8 bytes, AES-CBC IV derived per message via HKDF, encrypted protobuf header, version byte `0x33`.
- **PreKeySignalMessage** envelope for Alice's first message (carries pre-key ids + ephemeral pub so Bob can identify which of his stored keys to consume).
- **MKSKIPPED** cache for out-of-order delivery -- bounded 32-slot LRU, `MAX_SKIP=32` per receive.
- **Constant-time MAC verify** (`CRYPTO_memcmp`) before AES-CBC decrypt, so a padding-oracle channel can't open.
- **`sodium_memzero`** on sensitive scratch buffers.
- **Fail-closed NIF load** -- a load failure raises `UndefinedFunctionError` at the call site rather than leaving stubs in place.
- **Ed25519 identity keys** with `crypto_sign_detached` signatures over signed pre-keys. The 0.1 line used HMAC-SHA-512-256 keyed by the identity pub, which is forgeable from any published bundle; that's fixed in 0.2.

## What's deliberately out of scope

- Long-term key storage. The library returns keys as binaries and expects the embedder to store and look them up. Nothing in the repo is a `SignalProtocolStore` analog.
- Identity verification (the "safety number" comparison). That's a UX concern outside the protocol.
- Endpoint compromise, physical access, kernel-level attackers, malicious peer devices.
- Side-channel resistance beyond what libsodium/OpenSSL provide -- no per-target SCA hardening, no constant-time guarantees outside the primitives.
- Group messaging / Sender Keys.

## Primitives

| Operation                | Implementation                                                                                                                                              |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Identity keys            | Ed25519 via libsodium `crypto_sign_*`                                                                                                                       |
| Signed pre-keys          | `crypto_sign_detached` over the pre-key pub                                                                                                                 |
| DH                       | Raw X25519 via `crypto_scalarmult` (not `crypto_box_beforenm`, which adds HSalsa20)                                                                         |
| KDF                      | HKDF-SHA-256 throughout (`info="DR-RK"` for root chain, `"X3DH-Signal"` for X3DH, `"WhisperMessageKeys"` / `"WhisperHeader"` for DR cipher and header keys) |
| Chain advance            | HMAC-SHA-256; constants 0x02 for chain, 0x01 for message (Signal spec)                                                                                      |
| DR cipher                | AES-256-CBC + HMAC-SHA-256 truncated to 8B, MAC checked before decrypt                                                                                      |
| Simple session AEAD      | ChaCha20-Poly1305 (libsodium IETF variant)                                                                                                                  |
| AES-GCM in `signal_nif`  | libsodium `crypto_aead_aes256gcm_*`                                                                                                                         |
| SHA-256 / SHA-512 / HMAC | libsodium                                                                                                                                                   |
| CSPRNG                   | libsodium `randombytes_buf`                                                                                                                                 |

The Signal-spec items are clearly labelled in `CHANGELOG.md` under the 0.2 release notes.

## Known deviations from Signal spec

Documented in `.claude/TODO.md` under "Non-Signal-spec but consistent within this library". The short version:

- HKDF info strings for the DR root KDF (`"DR-RK"`) and X3DH KDF (`"X3DH-Signal"`) differ from Signal's `"WhisperRatchet"` / `"WhisperText"`. The structure of the HKDF call is identical; only the info bytes differ. The per-message AEAD KDF uses the canonical `"WhisperMessageKeys"`.
- The PreKeySignalMessage version byte is `0x33` matching `(3<<4)|3`, the Signal Protocol convention.
- X3DH F-prefix, chain-key constants, MAC truncation length all match the Signal spec.

These differences mean DR sessions are not on-the-wire compatible with a stock libsignal client out of the box -- they're compatible at the structural level, but a peer would need to know the alternate info strings.

## Threat model

**In scope.** A passive on-path attacker who reads ciphertexts; a network attacker who can drop, reorder, or modify messages; bundle-substitution attempts (the Ed25519 signature on the signed pre-key blocks the published-bundle forgery that bit the 0.1 line).

**Out of scope.** A peer who logs plaintext after decrypt; a compromised device; an attacker with arbitrary memory read on the host process; an attacker who can replace the loaded `.so`; side-channel attacks on the host CPU.

## Reporting a vulnerability

Open a private security advisory on GitHub: <https://github.com/Hydepwns/libsignal-protocol-nif/security/advisories/new>. Include a minimal reproducer if you have one.

Don't file security issues in the public issue tracker.

## Operational guidance

- **Pin a version.** Both the NIF wire format and the DR session blob layout have changed multiple times in 0.x. Persisted session blobs from a prior 0.x release will not decrypt under a newer one.
- **Persist what the spec requires you to persist:** identity priv, signed pre-key priv (rotated), unused one-time pre-keys, current DR session blob. The session blob is opaque -- treat it as a sealed binary.
- **Don't reuse one-time pre-keys.** Delete them on first use. The library does not enforce this for you.
- **Don't log keys or plaintext.** The wrapper return shapes (`{:ok, binary}`) make it easy to accidentally inspect-then-log.
- **Rotate the signed pre-key on the cadence your application requires.** The library does not impose one.
