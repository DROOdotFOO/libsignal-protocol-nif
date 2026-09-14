# Architecture

What the layers are, why they look the way they do, and what's in the DR envelope.

For build steps and the file tree, see [CLAUDE.md](../CLAUDE.md). For the call-level NIF surface, see [API.md](API.md). For the crypto choices, see [SECURITY.md](SECURITY.md).

## Layers

```
Erlang / Elixir / Gleam application
            |
   *.erl NIF stub modules                src/{signal_nif,libsignal_protocol_nif}.erl
            |  on_load: libsignal_nif_loader -> code:priv_dir/1, then priv/
   C NIF entry + dispatch                c_src/{signal_nif,libsignal_protocol_nif}.c
            |
   protocol pieces                       c_src/{dr,dr_chain,dr_crypto,dr_proto,pksm,
                                                session,keys}.c
            |
   libsodium  (+ OpenSSL EVP for AES-CBC)
```

Two NIFs ship because they have different audiences. `signal_nif` is stateless crypto -- callable from anywhere, no init. `libsignal_protocol_nif` is the full Signal Protocol module: identity keys, X3DH, the Double Ratchet, and the PreKeySignalMessage envelope.

Both `.erl` stubs use `-on_load(load_nif/0)` and delegate path resolution to `src/libsignal_nif_loader.erl`. A failed load fails closed: the module refuses to load and the calling process gets `UndefinedFunctionError` rather than silently-stubbed crypto.

## Protocol surface

### Identity and pre-keys

Identity keys are Ed25519 (32B pub, 64B secret-key encoding). The 0.1 line used X25519 with an HMAC-based "signature" that anyone with a published bundle could forge. 0.2 switched to real Ed25519 with `crypto_sign_detached`.

Pre-keys are X25519. Signed pre-keys are signed under the identity key. The published bundle is wire bytes:

```
id_pub(32) || spk_pub(32) || signature(64) [|| opk_pub(32)]
```

Both generators hand back the private half; the publisher keeps it to complete X3DH when someone consumes the bundle. The Elixir and Gleam wrappers model the bundle as a struct/record and serialize it to exactly these bytes -- there is no second, wrapper-level format.

### X3DH

Standard Signal X3DH with one variation: the KDF uses `info="X3DH-Signal"` rather than Signal's `"WhisperText"`. Structure of the HKDF call is identical, only the info bytes differ.

The output widened in 0.2 from 64 to 96 bytes and is laid out as `root(32) || seed_a(32) || seed_b(32)`. The first 32 bytes seed the DR root key; the two trailing seeds become the initial next-header-keys, assigned mirror-wise by role so Alice's sending header key equals Bob's receiving one and vice versa (Signal's `shared_hka` / `shared_nhkb`).

Bob's side reconstructs the same 96 bytes from his stored privs plus values from Alice's first message. `x3dh_dr_compose_SUITE` asserts the two halves match by computing Bob's X3DH in plain Erlang via `crypto:compute_key(ecdh, _, _, x25519)`.

### Double Ratchet with header encryption

The DR session struct (`double_ratchet_state_t` in `dr.h`) carries an 8-byte `magic || version || size` tag, the root key, send/receive chain keys, four DR-HE header keys (current and next, per direction), the local and remote identity pubs in X25519 form, the local identity pub in Ed25519 form for the PKSM envelope, and a 96-slot MKSKIPPED LRU cache. Serialized blob is roughly 7.6 KB. The struct layout *is* the persistence format; `dr_state_load`/`dr_state_store` in `dr.c` are the only places it crosses the NIF boundary, and load validates the tag and normalises every `bool` byte before anything reads them.

Wire envelope:

```
version_byte(0x33)
  || protobuf { enc_header=1: bytes(iv(16) || AES-256-CBC(hk_cipher, header_pb) || tag(16)),
                ciphertext=2: bytes(AES-256-CBC(message_key, plaintext)) }
  || mac(8)
```

- `header_key` comes from the DR state (`header_key_send` / `header_key_recv`, rotated from the pre-derived `next_*` at each DH step). `HKDF(header_key, info="WhisperHeader", L=64)` yields `hk_cipher(32) || hk_mac(32)`.
- `header_pb` is `DrMessage { ratchet_key=1, counter=2, previous_counter=3 }` (38..46 bytes, always padded to 48). Encrypting it hides those fields from on-path observers. The header IV is 16 random bytes shipped in the clear; `tag = HMAC-SHA-256(hk_mac, iv || ct)[0..16)`.
- `message_key -> HKDF(info="WhisperMessageKeys", L=80) -> cipher_key(32) || mac_key(32) || iv(16)`. The body IV is HKDF-derived, not random.
- `mac = HMAC-SHA-256(mac_key, sender_id || receiver_id || version || outer_protobuf)` truncated to 8 bytes. Verified with `sodium_memcmp` before the body is AES-CBC decrypted.

Receive first pins `enc_header` to exactly 80 bytes and the body to a non-zero multiple of 16, then trial-opens `enc_header` under the current receive header key, the next, and each MKSKIPPED entry's header key: the header tag is verified in constant time and only a header that authenticates is CBC-decrypted and parsed. MKSKIPPED entries are keyed by `(header_key, message_number)` -- the unencrypted ratchet key is not available at lookup time. State is mutated on a stack copy and committed only after the body decrypts, so a failing message never changes the session.

`MAX_SKIP = 32` bounds each chain (Signal spec), so a receive that crosses a DH ratchet may skip up to 32 on the old chain and 32 on the new one; anything beyond returns `too_many_skipped`. MKSKIPPED holds `3 * MAX_SKIP` entries, one budget above that worst case, so a full two-chain receive still leaves a chain's worth of earlier keys resident.

### PreKeySignalMessage envelope

Alice's first message has to tell Bob which of his stored pre-keys to consume. Wire shape is the Signal `PreKeySignalMessage`:

```
version_byte(0x33)
  || protobuf { registration_id=1, base_key=2, identity_key=3,
                pre_key_id=4 (optional), signed_pre_key_id=5, message=6 }
```

`identity_key` is Alice's Ed25519 identity pub, the form `process_pre_key_bundle_bob/5` and `dr_init/5` both take, so Bob can bootstrap from the envelope alone. (Through 0.2 it was sent in X25519 (DJB) form, matching libsignal's wire spec, but X25519 -> Ed25519 is not uniquely invertible so the field was unusable here; the DR MAC scope still uses the X25519 forms internally.) Both `identity_key` and `base_key` are rejected unless exactly 32 bytes. `pre_key_id` is optional -- absent means no OPK was consumed.

The `message` field carries the full inner DR `SignalMessage` (version byte + outer protobuf + MAC). `dr_encrypt_prekey/3` and `dr_encrypt/2` share the same `dr_encrypt_core` helper for the cipher + MAC + envelope path.

## Design choices

**NIF, not port driver.** Signal's keygen and AEAD ops are small and frequent. The synchronous in-process call beats message-passing latency. Cost: a C-side crash takes the VM down, so each entry validates its inputs.

**libsodium + OpenSSL 3.** libsodium covers Curve25519, Ed25519, SHA-2, HKDF, HMAC. AES-256-CBC for the DR cipher comes from OpenSSL's `EVP_CIPHER` -- libsodium has no CBC. AES-256-GCM in `signal_nif` is libsodium's `crypto_aead_aes256gcm_*`. The OpenSSL dep showed up in 0.2 with the move to Signal-spec DR AEAD.

**Atom error vocabulary.** Every NIF returns `{ok, _} | {error, atom}`. Atoms are stable, cheap to pattern-match, and the Elixir wrapper mirrors them verbatim. The Gleam wrapper surfaces them as `Result(_, String)` because Gleam errors are strings.

**No global state.** Both NIFs are stateless across calls. Each library calls `sodium_init()` in its own `on_load` -- they load independently, so neither may assume the other ran first. `init/0` on `libsignal_protocol_nif` is a no-op probe that returns `ok`; idempotent.

**Fail closed on load.** A failed `load_nif/0` returns `{error, _}` from `-on_load` so the module refuses to load. Prior to 0.2 a load failure printed a warning and returned `ok`, leaving stubs in place that would silently no-op cryptographic work. Removed.

## Memory

`sodium_memzero` runs on every sensitive scratch buffer before free. `enif_alloc`/`enif_free` for heap; stack for small fixed-size buffers.

Erlang-side: the caller owns the returned binary. Sensitive keys returned to Erlang live in the BEAM heap until GC. There is no facility to wipe them from Erlang -- callers that need that should not hold the private key as a long-lived term.
