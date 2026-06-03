# API reference

Two Erlang NIF modules ship in this repo. `signal_nif` is lower-level crypto primitives. `libsignal_protocol_nif` is the Signal Protocol surface: identity keys, X3DH, the Double Ratchet, and the PreKeySignalMessage envelope.

All NIF calls return `{ok, Term} | {error, Atom}` unless noted. Sensitive scratch buffers are wiped with `sodium_memzero`. A failed `load_nif/0` fails closed -- the module refuses to load, the calling process gets `UndefinedFunctionError`.

Sizes match the 0.2.0 wire format: Ed25519 identities (32-byte pub, 64-byte priv), X25519 for DH (32B), 96-byte X3DH shared secret (64B SK || 32B header-key seed for DR-HE).

## signal_nif

Lower-level primitives. Stateless, no init required.

### Key generation

```erlang
{ok, {Pub, Priv}} = signal_nif:generate_curve25519_keypair().
%% Pub, Priv: 32 bytes each.

{ok, {Pub, Priv}} = signal_nif:generate_ed25519_keypair().
%% Pub: 32 bytes. Priv: 64 bytes (libsodium secret-key encoding: seed || derived pub).

{ok, X25519Priv} = signal_nif:ed25519_sk_to_curve25519(Ed25519Priv).
{ok, X25519Pub}  = signal_nif:ed25519_pk_to_curve25519(Ed25519Pub).
%% Conversion helpers for Bob-side X3DH reconstruction in Erlang.
```

### Signatures

```erlang
{ok, Sig} = signal_nif:sign_data(Ed25519Priv, Message).
%% Sig: 64 bytes.

ok = signal_nif:verify_signature(Ed25519Pub, Message, Sig).
%% Returns ok on success, {error, invalid_signature} otherwise.
```

### Hashes and MACs

```erlang
{ok, Hash}   = signal_nif:sha256(Data).      %% 32 bytes
{ok, Hash}   = signal_nif:sha512(Data).      %% 64 bytes
{ok, Mac}    = signal_nif:hmac_sha256(Key, Data). %% 32 bytes, key any length
```

### AES-GCM

```erlang
{ok, Ct, Tag} = signal_nif:aes_gcm_encrypt(Key, IV, Plaintext, AAD, TagLen).
{ok, Pt}      = signal_nif:aes_gcm_decrypt(Key, IV, Ct, AAD, Tag, PlaintextLen).
```

- `Key`: 16, 24, or 32 bytes (AES-128/192/256).
- `IV`: 12 bytes.
- `AAD`: any length, may be `<<>>`.
- `TagLen`: 12-16. Decrypt requires the exact tag.
- Decrypt failure returns `{error, decryption_failed}` -- includes failed tag verification.

## libsignal_protocol_nif

Signal Protocol module. Call `init/0` once per VM before using anything else.

### Lifecycle

```erlang
ok = libsignal_protocol_nif:init().
%% Initializes libsodium. Returns {error, libsodium_init_failed} on failure.
```

### Identity and pre-keys

```erlang
{ok, {IdPub, IdPriv}} = libsignal_protocol_nif:generate_identity_key_pair().
%% IdPub: 32B Ed25519 pub. IdPriv: 64B Ed25519 secret-key encoding.

{ok, {KeyId, PreKeyPub}} = libsignal_protocol_nif:generate_pre_key(KeyId).
%% PreKeyPub: 32B X25519.

{ok, {KeyId, SpkPub, Sig}} =
    libsignal_protocol_nif:generate_signed_pre_key(IdPriv, KeyId).
%% SpkPub: 32B X25519. Sig: 64B Ed25519 over SpkPub.
```

### Simple session (ChaCha20-Poly1305)

A static-key AEAD session. Real Signal flows should use the Double Ratchet below; this is here for callers who already have a DH-derived shared key and want a one-shot encrypted channel. Not exposed in the Elixir or Gleam wrappers.

```erlang
{ok, Session} =
    libsignal_protocol_nif:create_session(LocalPriv32, RemotePub32).
%% Session: binary containing the derived 32B key (first 32 bytes are the key).

{ok, Envelope}  = libsignal_protocol_nif:encrypt_message(Session, Plaintext).
%% Envelope: nonce(12) || ChaCha20-Poly1305(plaintext) || tag(16).

{ok, Plaintext} = libsignal_protocol_nif:decrypt_message(Session, Envelope).
```

Errors: `invalid_session` (less than 32 bytes), `invalid_message` (envelope too short), `encryption_failed`, `decryption_failed`.

### X3DH

Alice's side. The `Bundle` is the wire form Bob publishes:

```
id_pub(32) || spk_pub(32) || signature(64) [|| opk_pub(32)]
```

`signature` is Ed25519 over `spk_pub` under Bob's identity key. The trailing OPK is optional.

```erlang
{ok, {SharedSecret96, AliceEphPub32}} =
    libsignal_protocol_nif:process_pre_key_bundle(AliceIdPriv64, Bundle).
```

The 96-byte shared secret is `X3DH_SK(64) || DR_HE_seed(32)`. Feed it straight into `dr_init/5`.

Bob's side reconstructs the same shared secret from the values he stored plus the ephemeral pub from Alice's first message:

```erlang
{ok, SharedSecret96} =
    libsignal_protocol_nif:process_pre_key_bundle_bob(
        BobIdPriv64,
        BobSpkPriv32,
        BobOpkPriv32_or_empty,
        AliceIdPub32_ed25519,
        AliceEphPub32_x25519).
```

Pass `<<>>` for `BobOpkPriv` when no one-time prekey was consumed.

Errors: `invalid_bundle`, `invalid_signature`, `signature_verification_failed`, `bundle_too_short`, `invalid_shared_secret_size`.

### Double Ratchet

```erlang
{ok, Session} =
    libsignal_protocol_nif:dr_init(
        SharedSecret96,
        LocalIdPub32,
        RemoteIdPub32,
        SelfIdPriv,        %% Ed25519 64B for Bob; <<>> for Alice
        IsAlice).          %% 1 for the initiator, 0 for the responder
```

Both identity pubs are folded into the per-message MAC scope. Alice passes `<<>>` for her own priv because she uses a fresh ephemeral for the first DH; Bob needs his Ed25519 secret to derive the initial ratchet pair.

Encrypt and decrypt advance the session; the returned `NewSession` replaces the old one:

```erlang
{ok, {Ciphertext, NewSession}} =
    libsignal_protocol_nif:dr_encrypt(Session, Plaintext).

{ok, {Plaintext, NewSession}} =
    libsignal_protocol_nif:dr_decrypt(Session, Ciphertext).
```

Wire envelope (DR with header encryption):

```
version_byte(0x33)
  || protobuf{ enc_header=1: bytes(iv16||AES-256-CBC(header_key, header_pb)),
               ciphertext=2:  bytes(AES-256-CBC(message_key, plaintext)) }
  || mac(8)   %% HMAC-SHA-256 over sender_id||receiver_id||version||outer protobuf
```

The receiver trial-decrypts `enc_header` against the current header key, the next header key, and MKSKIPPED entries. MKSKIPPED is a 32-slot LRU; per-receive `MAX_SKIP=32`. Errors: `malformed_message`, `mac_verification_failed`, `max_skip_exceeded`, `invalid_session_size`, `must_receive_first` (Bob trying to encrypt before Alice's first message arrives).

### PreKeySignalMessage envelope

Alice's first message has to tell Bob which of his stored pre-keys to consume:

```erlang
PreKeyInfo = {RegistrationId, OpkIdOrUndefined, SpkId, AliceEphPub32},

{ok, {WireBytes, NewSession}} =
    libsignal_protocol_nif:dr_encrypt_prekey(Session, Plaintext, PreKeyInfo).
```

`OpkIdOrUndefined` is either an integer or the atom `undefined` when no OPK was consumed.

Bob decodes the envelope, recovers the X3DH shared secret, initializes his DR side, then decrypts the inner message:

```erlang
{ok, {RegistrationId, BaseKey32, IdKey32, OpkId, SpkId, InnerWire}} =
    libsignal_protocol_nif:pksm_decode(WireBytes).
%% OpkId is an integer or undefined.
%% IdKey is Alice's identity pub in X25519 (DJB) form.
```

Errors: `malformed_message`, `unsupported_version`.

## Error atoms

Atoms the NIFs actually return today. Treat any unfamiliar atom as fatal; cryptographic operations don't have recoverable error modes.

| Atom                                                 | Origin                                     |
| ---------------------------------------------------- | ------------------------------------------ |
| `libsodium_init_failed`                              | `init/0`                                   |
| `invalid_signature`, `signature_verification_failed` | sign/verify, X3DH                          |
| `invalid_bundle`, `bundle_too_short`                 | `process_pre_key_bundle/2`                 |
| `invalid_shared_secret_size`                         | `dr_init/5` (must be 96 bytes)             |
| `invalid_session`, `invalid_session_size`            | session API, DR                            |
| `invalid_message`, `malformed_message`               | simple session, DR, PKSM decode            |
| `mac_verification_failed`                            | DR decrypt                                 |
| `max_skip_exceeded`                                  | DR receive (too many skipped messages)     |
| `must_receive_first`                                 | Bob's encrypt before Alice's first message |
| `decryption_failed`, `encryption_failed`             | AES-GCM, simple session                    |
| `unsupported_version`                                | PKSM decode                                |

## Sizes

| Item                    | Size                              |
| ----------------------- | --------------------------------- | --- | --------------- |
| Curve25519 / X25519 key | 32 bytes                          |
| Ed25519 public key      | 32 bytes                          |
| Ed25519 private key     | 64 bytes (libsodium SK encoding)  |
| Ed25519 signature       | 64 bytes                          |
| SHA-256 / HMAC-SHA-256  | 32 bytes                          |
| SHA-512                 | 64 bytes                          |
| AES key                 | 16 / 24 / 32 bytes                |
| AES-GCM IV              | 12 bytes                          |
| AES-GCM tag             | 12-16 bytes                       |
| X3DH shared secret      | 96 bytes (64B SK                  |     | 32B DR-HE seed) |
| DR session blob         | ~2.6 KB (MKSKIPPED + DR-HE state) |
| DR MAC                  | 8 bytes (truncated HMAC-SHA-256)  |
| PreKeyBundle wire       | 128 bytes minimum (160 with OPK)  |

## End-to-end flow

For complete X3DH + Double Ratchet + PreKeySignalMessage flows see `test/erl/unit/protocol/`. The most useful suites:

- `x3dh_dr_compose_SUITE` -- Alice and Bob compose X3DH into a DR session and round-trip messages.
- `pksm_SUITE` -- the full PreKeySignalMessage handshake with and without OPK.
- `double_ratchet_reorder_SUITE` -- out-of-order delivery against the MKSKIPPED cache.
- `dr_he_envelope_SUITE` -- header encryption: counter and ratchet-key are hidden, tampering rejected.
