# Architecture

What the layers are, why they look the way they do, and what's in the DR envelope.

For build steps and the file tree, see [CLAUDE.md](../CLAUDE.md). For the call-level NIF surface, see [API.md](API.md). For the crypto choices, see [SECURITY.md](SECURITY.md).

## Layers

```
Erlang / Elixir / Gleam application
            |
   *.erl NIF stub modules                src/{signal_nif,libsignal_protocol_nif}.erl
            |  on_load: search priv/, _build/.../priv/
   C NIF entry + dispatch                c_src/{signal_nif,libsignal_protocol_nif}.c
            |
   protocol pieces                       c_src/{dr,dr_chain,dr_crypto,dr_proto,pksm,
                                                session,keys}.c
            |
   libsodium  (+ OpenSSL EVP for AES-CBC)
```

Two NIFs ship because they have different audiences. `signal_nif` is stateless crypto -- callable from anywhere, no init. `libsignal_protocol_nif` is the full Signal Protocol module: identity keys, X3DH, the Double Ratchet, the PreKeySignalMessage envelope, plus a simple ChaCha20-Poly1305 session API for callers who already have a static shared key.

The `.erl` stubs use `-on_load(load_nif/0)` with a fallback path list. A failed load fails closed: the calling process gets `UndefinedFunctionError` rather than a silently-stubbed module.

## Protocol surface

### Identity and pre-keys

Identity keys are Ed25519 (32B pub, 64B secret-key encoding). The 0.1 line used X25519 with an HMAC-based "signature" that anyone with a published bundle could forge. 0.2 switched to real Ed25519 with `crypto_sign_detached`.

Pre-keys are X25519. Signed pre-keys are signed under the identity key. The published bundle is wire bytes:

```
id_pub(32) || spk_pub(32) || signature(64) [|| opk_pub(32)]
```

The wrappers serialize a higher-level versioned bundle for storage. The NIF only sees this raw form.

### X3DH

Standard Signal X3DH with one variation: the KDF uses `info="X3DH-Signal"` rather than Signal's `"WhisperText"`. Structure of the HKDF call is identical, only the info bytes differ.

The output widened in 0.2 from 64 to 96 bytes. The first 64 are the X3DH SK (bit-identical to the old output -- the new bytes come from extending HKDF-Expand by one block). The trailing 32 are a shared header-key seed for DR-HE.

Bob's side reconstructs the same 96 bytes from his stored privs plus values from Alice's first message. `x3dh_dr_compose_SUITE` asserts the two halves match by computing Bob's X3DH in plain Erlang via `crypto:compute_key(ecdh, _, _, x25519)`.

### Double Ratchet with header encryption

The DR session struct (`double_ratchet_state_t` in `dr.h`) carries the root key, send/receive chain keys, four DR-HE header keys (current and next, per direction), the local and remote identity pubs in X25519 form, and a 32-slot MKSKIPPED LRU cache. Serialized blob is roughly 2.6 KB.

Wire envelope:

```
version_byte(0x33)
  || protobuf { enc_header=1: bytes(iv16 || AES-256-CBC(header_key, header_pb)),
                ciphertext=2: bytes(AES-256-CBC(message_key, plaintext)) }
  || mac(8)
```

- `header_key` is derived per direction from the DR state.
- `header_pb` is `DrMessage { ratchet_key=1, counter=2, previous_counter=3 }`. Encrypting it hides those fields from on-path observers.
- `message_key -> HKDF(info="WhisperMessageKeys", L=80) -> cipher_key(32) || mac_key(32) || iv(16)`. No random nonce; the IV is HKDF-derived.
- `mac = HMAC-SHA-256(mac_key, sender_id || receiver_id || version || outer_protobuf)` truncated to 8 bytes. Verified before AES-CBC decrypt with `CRYPTO_memcmp` to close the padding-oracle channel.

Receive trial-decrypts `enc_header` under the current receive header key, then the next, then each MKSKIPPED entry's header key. PKCS#7 unpad + inner protobuf parse is the success oracle. MKSKIPPED entries are keyed by `(header_key, message_number)` -- the unencrypted ratchet key is no longer available at lookup time.

`MAX_SKIP = 32` per receive bounds DOS. Anything beyond returns `max_skip_exceeded`.

### PreKeySignalMessage envelope

Alice's first message has to tell Bob which of his stored pre-keys to consume. Wire shape is the Signal `PreKeySignalMessage`:

```
version_byte(0x33)
  || protobuf { registration_id=1, base_key=2, identity_key=3,
                pre_key_id=4 (optional), signed_pre_key_id=5, message=6 }
```

`identity_key` is in X25519 (DJB) form. The DR MAC scope already uses X25519 identity pubs (converted at `dr_init`), so the envelope is wire-spec compatible with libsignal. `pre_key_id` is optional -- absent means no OPK was consumed.

The `message` field carries the full inner DR `SignalMessage` (version byte + outer protobuf + MAC). `dr_encrypt_prekey/3` and `dr_encrypt/2` share the same `dr_encrypt_core` helper for the cipher + MAC + envelope path.

## Design choices

**NIF, not port driver.** Signal's keygen and AEAD ops are small and frequent. The synchronous in-process call beats message-passing latency. Cost: a C-side crash takes the VM down, so each entry validates its inputs.

**libsodium + OpenSSL 3.** libsodium covers Curve25519, Ed25519, ChaCha20-Poly1305, SHA-2, HKDF, HMAC. AES-256-CBC for the DR cipher comes from OpenSSL's `EVP_CIPHER` -- libsodium has no CBC. AES-256-GCM in `signal_nif` is libsodium's `crypto_aead_aes256gcm_*`. The OpenSSL dep showed up in 0.2 with the move to Signal-spec DR AEAD.

**Atom error vocabulary.** Every NIF returns `{ok, _} | {error, atom}`. Atoms are stable, cheap to pattern-match, and the Elixir wrapper mirrors them verbatim. The Gleam wrapper surfaces them as `Result(_, String)` because Gleam errors are strings.

**No global state.** Both NIFs are stateless across calls. `init/0` on `libsignal_protocol_nif` only seeds libsodium's randomness pool. Idempotent.

**Fail closed on load.** A failed `load_nif/0` returns `{error, _}` from `-on_load` so the module refuses to load. Prior to 0.2 a load failure printed a warning and returned `ok`, leaving stubs in place that would silently no-op cryptographic work. Removed.

## Memory

`sodium_memzero` runs on every sensitive scratch buffer before free. `enif_alloc`/`enif_free` for heap; stack for small fixed-size buffers.

Erlang-side: the caller owns the returned binary. Sensitive keys returned to Erlang live in the BEAM heap until GC. There is no facility to wipe them from Erlang -- callers that need that should not hold the private key as a long-lived term.
