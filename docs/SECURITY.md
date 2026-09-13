# Security notes

What this library protects, what it doesn't, and what's still aspirational.

## Status

Not externally audited. No third-party security review has been done on the NIF, the protocol composition, or the wrappers. libsodium (the crypto primitives underneath) and OpenSSL (the AES-256-CBC implementation for the DR cipher) are audited, widely deployed libraries -- but how we compose them has only been reviewed in-house.

If you're considering this for production, treat it as pre-audit and pin a specific version.

## What's implemented

- **X3DH** key agreement (RFC-style; Signal info string variation noted below).
- **Double Ratchet with header encryption (DR-HE)** matching the Signal wire format: AES-256-CBC + HMAC-SHA-256 truncated to 8 bytes, body IV derived per message via HKDF, encrypted protobuf header (random 16-byte IV, shipped in the clear), version byte `0x33`.
- **PreKeySignalMessage** envelope for Alice's first message (carries pre-key ids + ephemeral pub so Bob can identify which of his stored keys to consume).
- **MKSKIPPED** cache for out-of-order delivery -- bounded 32-slot LRU, `MAX_SKIP=32` per receive.
- **Constant-time MAC verify** (`sodium_memcmp`) on the outer MAC before the message *body* is AES-CBC decrypted, so a padding oracle on the body can't open. See "Receive-path ordering" below for what happens *before* that MAC check.
- **Structural bounds before crypto.** The encrypted header is pinned to exactly 64 bytes on the wire and rejected before any key is touched; the body ciphertext must be a non-zero multiple of 16. Both checks run before any decryption.
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
| DR cipher                | AES-256-CBC + HMAC-SHA-256 truncated to 8B; outer MAC checked before the body is decrypted (header is trial-decrypted first, see below)             |
| Simple session AEAD      | ChaCha20-Poly1305 (libsodium IETF variant)                                                                                                                  |
| AES-GCM in `signal_nif`  | libsodium `crypto_aead_aes256gcm_*`                                                                                                                         |
| SHA-256 / SHA-512 / HMAC | libsodium                                                                                                                                                   |
| CSPRNG                   | libsodium `randombytes_buf`                                                                                                                                 |

The Signal-spec items are clearly labelled in `CHANGELOG.md` under the 0.2 release notes.

## Receive-path ordering

`dr_decrypt` does, in order: (1) structural checks on the outer envelope and header/body lengths; (2) trial-decrypt of the 64-byte `enc_header` under the current receive header key, the next one, and each occupied MKSKIPPED slot -- AES-CBC decrypt, PKCS#7 unpad, and a strict inner-protobuf parse (exactly three fields, 32-byte ratchet key) act as the "does this key fit" oracle; (3) chain/ratchet advance and message-key derivation on a *copy* of the state; (4) outer MAC verification with `sodium_memcmp`; (5) body decrypt; (6) commit of the new state. Nothing is persisted before step 6, so a message that fails at any step leaves the session untouched.

Step 2 is unauthenticated: the header has no MAC of its own (the Signal DR-HE spec uses an AEAD for `HENCRYPT`; this implementation uses bare CBC). A network attacker can therefore observe, via timing and the returned error atom, whether a forged header decrypts to something parseable under one of Bob's header keys, and can make Bob do up to `MAX_SKIP` chain derivations plus one DH before the MAC rejects the message. This is not a plaintext or key-recovery channel -- the ratchet state is never committed and CBC tampering scrambles the preceding block -- but it is a spec deviation and a work-amplification vector. Authenticating the header is planned for 0.3.

## Known deviations from Signal spec

- HKDF info strings for the DR root KDF (`"DR-RK"`) and X3DH KDF (`"X3DH-Signal"`) differ from Signal's `"WhisperRatchet"` / `"WhisperText"`. The structure of the HKDF call is identical; only the info bytes differ. The per-message AEAD KDF uses the canonical `"WhisperMessageKeys"`.
- **Bob's initial ratchet key is his identity key**, not his signed pre-key: `dr_init/5` converts Bob's Ed25519 identity secret to X25519 and uses it as `dh_send_private`; Alice uses Bob's converted identity pub as her first `dh_recv_public`. The spec uses `SPK_B` so that SPK rotation gives forward secrecy for the first receiving chain and keeps the long-term key out of the ratchet. Here the first DH ratchet step on Bob's side is `DH(IK_B, EK_A')`. The root key still comes from the full X3DH, so this does not weaken the session's confidentiality against a passive observer; it does mean compromise of `IK_B` alone exposes the first chain's DH contribution.
- **Header keys are not separated per direction.** Both `next_header_key_send` and `next_header_key_recv` are seeded from the same 32 bytes (`shared_secret[64..96)`) on both parties, so after the first ratchet Bob's sending and receiving header keys coincide and a message reflected back to its sender will pass the header trial-decrypt (it still fails the identity-bound outer MAC). The spec derives distinct `shared_hka` / `shared_nhkb`; `shared_secret[32..64)` is computed by X3DH but currently unused.
- **The DR-HE header is CBC without a MAC** (see "Receive-path ordering").
- The PreKeySignalMessage version byte is `0x33` matching `(3<<4)|3`, the Signal Protocol convention.
- X3DH F-prefix, chain-key constants, MAC truncation length all match the Signal spec.

These differences mean DR sessions are not on-the-wire compatible with a stock libsignal client -- they're compatible at the structural level, but a peer would need to match the info strings and the ratchet-key choice.

## Threat model

**In scope.** A passive on-path attacker who reads ciphertexts; a network attacker who can drop, reorder, or modify messages; bundle-substitution attempts (the Ed25519 signature on the signed pre-key blocks the published-bundle forgery that bit the 0.1 line, provided the embedder verifies the identity key out of band -- the bundle is self-describing and X3DH does not pin identities for you).

**Partially in scope.** Replay: the Double Ratchet rejects a repeated message once its key has been consumed (`bad_mac`), but a `PreKeySignalMessage` can be replayed to re-derive the initial session unless the one-time pre-key it consumed has been deleted. The simple session API has no replay or direction binding at all (see `API.md`).

**Out of scope.** A peer who logs plaintext after decrypt; a compromised device; an attacker with arbitrary memory read on the host process; an attacker who can replace the loaded `.so`; side-channel attacks on the host CPU.

## Reporting a vulnerability

Open a private security advisory on GitHub: <https://github.com/Hydepwns/libsignal-protocol-nif/security/advisories/new>. Include a minimal reproducer if you have one.

Don't file security issues in the public issue tracker.

## Operational guidance

- **Pin a version.** Both the NIF wire format and the DR session blob layout have changed multiple times in 0.x. Persisted session blobs from a prior 0.x release will not decrypt under a newer one.
- **Persist what the spec requires you to persist:** identity priv, signed pre-key priv (rotated), unused one-time pre-keys, current DR session blob. The session blob is a raw copy of the C `double_ratchet_state_t` struct: it contains the root key, both chain keys, the ratchet private key, header keys, and every cached skipped message key in plaintext; it is not encrypted, not authenticated, and its layout is compiler/ABI-specific. Store it with the same care as the identity private key, never accept one from an untrusted source, and expect `invalid_session_size` after any toolchain or struct change.
- **Returned binaries cannot be wiped.** Every `dr_encrypt`/`dr_decrypt` returns a new session binary; the superseded one lives on the BEAM heap until garbage-collected and can be copied by message passing, crash dumps, or `observer`. Keep session terms in as few processes as possible and don't log them.
- **Don't reuse one-time pre-keys.** Delete them on first use. The library does not enforce this for you.
- **Don't log keys or plaintext.** The wrapper return shapes (`{:ok, binary}`) make it easy to accidentally inspect-then-log.
- **Rotate the signed pre-key on the cadence your application requires.** The library does not impose one.
