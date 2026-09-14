# Security notes

What this library protects, what it doesn't, and what's still aspirational.

## Status

Not externally audited. No third-party security review has been done on the NIF, the protocol composition, or the wrappers. libsodium (the crypto primitives underneath) and OpenSSL (the AES-256-CBC implementation for the DR cipher) are audited, widely deployed libraries -- but how we compose them has only been reviewed in-house.

If you're considering this for production, treat it as pre-audit and pin a specific version.

## What's implemented

- **X3DH** key agreement (RFC-style; Signal info string variation noted below).
- **Double Ratchet with header encryption (DR-HE)** matching the Signal wire format: AES-256-CBC + HMAC-SHA-256 truncated to 8 bytes, body IV derived per message via HKDF, encrypted protobuf header (random 16-byte IV, shipped in the clear), version byte `0x33`.
- **PreKeySignalMessage** envelope for Alice's first message (carries pre-key ids + ephemeral pub so Bob can identify which of his stored keys to consume).
- **MKSKIPPED** cache for out-of-order delivery -- 96 slots (`3 * MAX_SKIP`). `MAX_SKIP = 32` bounds each chain, so one receive that crosses a DH ratchet banks at most 64 keys and always leaves a chain's worth of earlier keys resident. Past that, insertion evicts the least recently inserted slot and the dropped message becomes an unrecoverable `bad_mac` -- three consecutive worst-case receives can still evict in-flight keys, and the library gives the application no way to tell eviction from forgery.
- **Authenticated header encryption.** Each DR-HE header carries a 16-byte HMAC-SHA-256 tag (key derived with the header cipher key from the header key) that is verified in constant time before the header is CBC-decrypted or parsed. Header keys are seeded per direction from distinct halves of the X3DH output, so a message reflected to its sender authenticates under none of the sender's receive keys.
- **Constant-time MAC verify** (`sodium_memcmp`) on both MACs: the header tag before the header is decrypted, the outer MAC before the body is decrypted. No padding oracle is reachable on either.
- **Structural bounds before crypto.** The encrypted header is pinned to exactly 80 bytes on the wire and rejected before any key is touched; the body ciphertext must be a non-zero multiple of 16. Both checks run before any MAC or decryption.
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
| DR cipher                | AES-256-CBC + HMAC-SHA-256 truncated to 8B; MAC checked before the body is decrypted                                                              |
| DR-HE header             | AES-256-CBC + HMAC-SHA-256 truncated to 16B over `iv \|\| ct`; keys from HKDF(header_key, "WhisperHeader", L=64); tag checked before decrypt   |
| AES-GCM in `signal_nif`  | libsodium `crypto_aead_aes256gcm_*`                                                                                                                         |
| SHA-256 / SHA-512 / HMAC | libsodium                                                                                                                                                   |
| CSPRNG                   | libsodium `randombytes_buf`                                                                                                                                 |

The Signal-spec items are clearly labelled in `CHANGELOG.md` under the 0.2 release notes.

## Receive-path ordering

`dr_decrypt` does, in order: (1) structural checks on the outer envelope and header/body lengths; (2) for each candidate header key (current receive key, next one, each occupied MKSKIPPED slot): derive the header cipher/MAC keys, verify the 16-byte header tag with `sodium_memcmp`, and only on success CBC-decrypt, unpad and parse the inner header; (3) chain/ratchet advance and message-key derivation on a *copy* of the state, bounded by the shared `MAX_SKIP` budget; (4) outer MAC verification with `sodium_memcmp`; (5) body decrypt; (6) commit of the new state. Nothing is persisted before step 6, so a message that fails at any step leaves the session untouched.

A forged or reflected header therefore costs the receiver one HKDF and one HMAC per candidate key (at most 2 + occupied MKSKIPPED slots) and reaches neither the cipher nor the ratchet. The remaining pre-MAC work for a message whose header *does* authenticate -- up to `MAX_SKIP` chain derivations plus one DH -- can only be driven by a party holding the current header key, i.e. the peer.

## Known deviations from Signal spec

- HKDF info strings for the DR root KDF (`"DR-RK"`) and X3DH KDF (`"X3DH-Signal"`) differ from Signal's `"WhisperRatchet"` / `"WhisperText"`. The structure of the HKDF call is identical; only the info bytes differ. The per-message AEAD KDF uses the canonical `"WhisperMessageKeys"`.
- **Bob's initial ratchet key is his identity key**, not his signed pre-key: `dr_init/5` converts Bob's Ed25519 identity secret to X25519 and uses it as `dh_send_private`; Alice uses Bob's converted identity pub as her first `dh_recv_public`. The spec uses `SPK_B` so that SPK rotation gives forward secrecy for the first receiving chain and keeps the long-term key out of the ratchet. Here the first DH ratchet step on Bob's side is `DH(IK_B, EK_A')`. The root key still comes from the full X3DH, so this does not weaken the session's confidentiality against a passive observer; it does mean compromise of `IK_B` alone exposes the first chain's DH contribution.
- The DR-HE header MAC is HMAC-SHA-256 truncated to 16 bytes over `iv || ct` (encrypt-then-MAC with a separately derived key) rather than a single AEAD primitive; the security argument is the same as for the body.
- The PreKeySignalMessage `identity_key` field carries the sender's **Ed25519** identity pub. libsignal puts the X25519 (DJB) form there, but that form cannot be converted back, and both `process_pre_key_bundle_bob/5` and `dr_init/5` need Ed25519 -- with the X25519 form the recipient could not bootstrap from the envelope at all. Changed in 0.3.
- The PreKeySignalMessage version byte is `0x33` matching `(3<<4)|3`, the Signal Protocol convention.
- X3DH F-prefix, chain-key constants, MAC truncation length all match the Signal spec.

These differences mean DR sessions are not on-the-wire compatible with a stock libsignal client -- they're compatible at the structural level, but a peer would need to match the info strings, the ratchet-key choice, the authenticated header format, and the PKSM identity-key encoding.

## Threat model

**In scope.** A passive on-path attacker who reads ciphertexts; a network attacker who can drop, reorder, or modify messages; bundle-substitution attempts (the Ed25519 signature on the signed pre-key blocks the published-bundle forgery that bit the 0.1 line, provided the embedder verifies the identity key out of band -- the bundle is self-describing and X3DH does not pin identities for you).

**Partially in scope.** Replay: the Double Ratchet rejects a repeated message once its key has been consumed (`bad_mac`), but a `PreKeySignalMessage` can be replayed to re-derive the initial session unless the one-time pre-key it consumed has been deleted.

**Embedder's responsibility.** Two downgrades the library cannot detect for you:

- **One-time pre-key stripping.** Only the signed pre-key is covered by the bundle signature, so an active attacker or a malicious key server can serve a 128-byte bundle where you published a 160-byte one. X3DH still succeeds on the 3-DH path, no OPK is consumed or deleted, and PKSM replay is silently back. The NIF pins bundles to exactly 128 or 160 bytes and rejects everything else, but it cannot know which one you published -- pin OPK presence out of band if you rely on it.
- **Responder identity.** `pksm_decode/1` returns the `identity_key` the sender put on the wire. Binding a session to it unverified is trust-on-first-use: a forged envelope yields a different DH and dies at `bad_mac`, so nothing is decrypted under the wrong identity, but the session you create is bound to whatever the first packet asserted. Compare it against a pinned identity before calling `process_pre_key_bundle_bob/5`.

**Out of scope.** A peer who logs plaintext after decrypt; a compromised device; an attacker with arbitrary memory read on the host process; an attacker who can replace the loaded `.so`; side-channel attacks on the host CPU.

## Reporting a vulnerability

Open a private security advisory on GitHub: <https://github.com/Hydepwns/libsignal-protocol-nif/security/advisories/new>. Include a minimal reproducer if you have one.

Don't file security issues in the public issue tracker.

## Operational guidance

- **Pin a version.** Both the NIF wire format and the DR session blob layout have changed multiple times in 0.x. Persisted session blobs from a prior 0.x release will not decrypt under a newer one.
- **Persist what the spec requires you to persist:** identity priv, signed pre-key priv (rotated), unused one-time pre-keys, current DR session blob. The session blob is a raw copy of the C `double_ratchet_state_t` struct behind an 8-byte `magic || version || size` tag: it contains the root key, both chain keys, the ratchet private key, header keys, and every cached skipped message key in plaintext; it is not encrypted and not authenticated, and its layout is compiler/ABI-specific. The tag means a blob from another release or a corrupted buffer is rejected with `invalid_session` (or `invalid_session_size`) rather than reinterpreted as key material -- it is a safety check, not an integrity guarantee: an attacker who can write your storage can still substitute a validly-tagged blob of their own. Store it with the same care as the identity private key and never accept one from an untrusted source.
- **Don't reuse one-time pre-keys.** Delete them on first use. The library does not enforce this for you.
- **Don't log keys or plaintext.** The wrapper return shapes (`{:ok, binary}`) make it easy to accidentally inspect-then-log.
- **Rotate the signed pre-key on the cadence your application requires.** The library does not impose one.
