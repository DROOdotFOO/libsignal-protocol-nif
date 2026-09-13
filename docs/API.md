# API reference

Two Erlang NIF modules ship in this repo. `signal_nif` is lower-level crypto primitives. `libsignal_protocol_nif` is the Signal Protocol surface: identity keys, X3DH, the Double Ratchet, and the PreKeySignalMessage envelope.

All NIF calls return `{ok, Term} | {error, Atom}` unless noted. Sensitive scratch buffers are wiped with `sodium_memzero`. A failed `load_nif/0` fails closed -- the module refuses to load, the calling process gets `UndefinedFunctionError`.

Sizes match the 0.3.0 wire format: Ed25519 identities (32-byte pub, 64-byte priv), X25519 for DH (32B), 96-byte X3DH shared secret (32B root key || 32B header-key seed A || 32B header-key seed B).

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
{ok, Mac}    = signal_nif:hmac_sha256(Key, Data). %% 32 bytes; key any length (RFC 2104)
```

### AES-GCM

```erlang
{ok, Ct, Tag} = signal_nif:aes_gcm_encrypt(Key, IV, Plaintext, AAD, TagLen).
{ok, Pt}      = signal_nif:aes_gcm_decrypt(Key, IV, Ct, AAD, Tag, PlaintextLen).
```

- `Key`: exactly 32 bytes (AES-256 only; libsodium's `crypto_aead_aes256gcm_*`).
- `IV`: exactly 12 bytes.
- `AAD`: any length, may be `<<>>`.
- `TagLen`: must be 16. `Tag` on decrypt must be exactly 16 bytes.
- `PlaintextLen` on decrypt must equal `byte_size(Ct)`.
- Any other size returns `{error, invalid_parameters}`. `{error, aes_gcm_not_available}` when libsodium's hardware-accelerated AES-GCM is unavailable on the host CPU (it has no software fallback).
- Decrypt failure returns `{error, decryption_failed}` -- includes failed tag verification.

## libsignal_protocol_nif

Signal Protocol module. libsodium is initialised when the NIF loads (`-on_load`); a failed `sodium_init()` makes the module refuse to load, so no per-VM setup call is required.

### Lifecycle

```erlang
ok = libsignal_protocol_nif:init().
%% Optional. Always returns ok once the module has loaded; kept for callers
%% that want an explicit "is the NIF present" probe. Idempotent.
```

### Identity and pre-keys

```erlang
{ok, {IdPub, IdPriv}} = libsignal_protocol_nif:generate_identity_key_pair().
%% IdPub: 32B Ed25519 pub. IdPriv: 64B Ed25519 secret-key encoding.

{ok, {KeyId, PreKeyPub}} = libsignal_protocol_nif:generate_pre_key(KeyId).
%% PreKeyPub: 32B X25519. The private half is generated and discarded -- this
%% function cannot produce a pre-key Bob can later use in
%% process_pre_key_bundle_bob/5. Use signal_nif:generate_curve25519_keypair/0
%% and keep the private key yourself (see test/erl/unit/protocol/pksm_SUITE.erl).

{ok, {KeyId, SpkPub, Sig}} =
    libsignal_protocol_nif:generate_signed_pre_key(IdPriv, KeyId).
%% SpkPub: 32B X25519. Sig: 64B Ed25519 over SpkPub. Same caveat: the SPK
%% private key is discarded. Generate the pair with
%% signal_nif:generate_curve25519_keypair/0 and sign SpkPub with
%% signal_nif:sign_data/2 instead.
```

### Simple session (ChaCha20-Poly1305)

A static-key AEAD session. Real Signal flows should use the Double Ratchet below; this is here for callers who already have a DH-derived shared key and want a one-shot encrypted channel. The Gleam wrapper does not expose it; the Elixir wrapper still does via `LibsignalProtocol.create_session/2`.

```erlang
{ok, Session} =
    libsignal_protocol_nif:create_session(LocalPriv32, RemotePub32).
%% Session: 64-byte binary; the first 32 bytes are the derived key.

{ok, Envelope}  = libsignal_protocol_nif:encrypt_message(Session, Plaintext).
%% Envelope: nonce(12) || ChaCha20-Poly1305(plaintext) || tag(16).

{ok, Plaintext} = libsignal_protocol_nif:decrypt_message(Session, Envelope).
```

Both peers derive the same key and use it in both directions, there is no AAD, the nonce is 12 random bytes per message, and there is no counter. Consequences: a ciphertext one side produced also decrypts on that same side (no direction binding), messages can be replayed, and the random nonce has a birthday bound of about 2^32 messages per session. Use the Double Ratchet for anything beyond a one-shot exchange.

Errors: `invalid_key_sizes` (inputs not 32 bytes), `key_agreement_failed`, `invalid_session` (session shorter than 32 bytes), `invalid_message` (envelope too short), `encryption_failed`, `decryption_failed`.

### X3DH

Alice's side. The `Bundle` is the wire form Bob publishes:

```
id_pub(32) || spk_pub(32) || signature(64) [|| opk_pub(32)]
```

`signature` is Ed25519 over `spk_pub` under the identity key carried in the same bundle. That is X3DH as specified -- the bundle is self-describing and trust in `id_pub` comes from out-of-band identity verification, which is the embedder's job. The trailing OPK is optional; any bundle of 160 bytes or more is read as having one, and 128..159-byte or over-long bundles are not rejected (only the first 128 or 160 bytes are used).

```erlang
{ok, {SharedSecret96, AliceEphPub32}} =
    libsignal_protocol_nif:process_pre_key_bundle(AliceIdPriv64, Bundle).
```

The 96-byte shared secret is `root(32) || seed_a(32) || seed_b(32)`: the first 32 bytes seed the DR root key and the two trailing seeds become the initial next-header-keys, assigned mirror-wise by role (Alice sends under `seed_b`, receives under `seed_a`; Bob the reverse). Feed it straight into `dr_init/5`.

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

Errors (Alice): `invalid_local_identity_key_size`, `invalid_bundle_size` (under 128 bytes), `identity_priv_conversion_failed`, `identity_pub_conversion_failed`, `signature_verification_failed`, `ephemeral_key_generation_failed`, `dh1_calculation_failed` .. `dh4_calculation_failed`, `kdf_failed`, `memory_allocation_failed`. Errors (Bob): `invalid_identity_priv_size`, `invalid_signed_pre_key_priv_size`, `invalid_one_time_pre_key_priv_size`, `invalid_remote_identity_pub_size`, `invalid_remote_ephemeral_pub_size`, `identity_priv_conversion_failed`, `identity_pub_conversion_failed`, `dh1_calculation_failed` .. `dh4_calculation_failed`, `kdf_failed`.

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

Both identity pubs are folded into the per-message MAC scope. Alice passes `<<>>` for her own priv because she uses a fresh ephemeral for the first DH; Bob needs his Ed25519 secret because his *identity* key (converted to X25519) is his initial ratchet key -- a deviation from the Signal spec, which uses the signed pre-key (see `SECURITY.md`).

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
  || protobuf{ enc_header=1: bytes(iv(16) || AES-256-CBC(hk_cipher, header_pb) || tag(16)),
               ciphertext=2:  bytes(AES-256-CBC(message_key, plaintext)) }
  || mac(8)   %% HMAC-SHA-256 over sender_id||receiver_id||version||outer protobuf
```

`enc_header` is always exactly 80 bytes: a random IV, one 48-byte CBC block-triple (the inner header is 38..46 bytes), and a 16-byte truncated HMAC-SHA-256 over `iv || ct` under a MAC key derived alongside the cipher key from the header key. The receiver trial-opens it against the current receive header key, the next one, and each MKSKIPPED entry: the tag is checked first (constant time), so a header that does not authenticate under a key is never decrypted or parsed. Any other length is rejected as `malformed_message` before any key is used. MKSKIPPED is a 64-slot LRU; one `MAX_SKIP=32` budget covers a whole receive, including both sides of a DH ratchet (previous-chain tail plus new-chain prefix), so a single message can never insert more than 32 keys and never evicts the previous receive's keys.

Errors: `invalid_session_size`, `session_not_initialized`, `must_receive_first` (Bob trying to encrypt before Alice's first message arrives), `message_too_short`, `unsupported_version`, `malformed_message`, `bad_mac` (no candidate header key decrypts the header, or the outer MAC fails), `too_many_skipped` (the header's counters imply more than `MAX_SKIP` skipped messages), `dh_ratchet_failed`, `kdf_failed`, `decryption_failed`, `encryption_failed`, `mac_failed`, `memory_allocation_failed`.

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
%% IdKey is Alice's identity pub in X25519 (DJB) form. dr_init/5 and
%% process_pre_key_bundle_bob/5 need the Ed25519 form, which is not
%% recoverable from this field -- Bob must obtain Alice's Ed25519 identity
%% pub out of band (e.g. from her published bundle) for now.
```

Errors: `malformed_message` (bad version byte, truncated, or unparseable protobuf). `dr_encrypt_prekey/3` additionally returns `pksm_encode_failed`.

A PreKeySignalMessage carries no freshness on its own: if Bob does not delete the one-time pre-key it consumed (or the message used none), the same envelope can be replayed to re-derive the session and re-decrypt the first message. Delete OPKs on first use.

## Error atoms

Every atom the NIFs return today, grouped by origin. Treat any unfamiliar atom as fatal; cryptographic operations don't have recoverable error modes. Wrong-type arguments (non-binary where a binary is expected, non-integer ids) raise `badarg` instead.

| Origin | Atoms |
| --- | --- |
| `signal_nif` keygen | `key_generation_failed` |
| `signal_nif` sign / verify | `invalid_private_key`, `signing_failed`, `invalid_public_key`, `invalid_signature` |
| `signal_nif` key conversion | `invalid_secret_key_size`, `invalid_public_key_size`, `conversion_failed` |
| `signal_nif` HMAC | `hmac_failed` |
| `signal_nif` AES-GCM | `invalid_parameters`, `aes_gcm_not_available`, `memory_allocation_failed`, `encryption_failed`, `decryption_failed` |
| `generate_*_pre_key` | `key_generation_failed`, `invalid_identity_key_size`, `signature_failed` |
| simple session | `invalid_key_sizes`, `key_agreement_failed`, `invalid_session`, `invalid_message`, `encryption_failed`, `decryption_failed` |
| `process_pre_key_bundle/2` | `invalid_local_identity_key_size`, `invalid_bundle_size`, `identity_priv_conversion_failed`, `identity_pub_conversion_failed`, `signature_verification_failed`, `ephemeral_key_generation_failed`, `dh1_calculation_failed`, `dh2_calculation_failed`, `dh3_calculation_failed`, `dh4_calculation_failed`, `kdf_failed`, `memory_allocation_failed` |
| `process_pre_key_bundle_bob/5` | `invalid_identity_priv_size`, `invalid_signed_pre_key_priv_size`, `invalid_one_time_pre_key_priv_size`, `invalid_remote_identity_pub_size`, `invalid_remote_ephemeral_pub_size`, `identity_priv_conversion_failed`, `identity_pub_conversion_failed`, `dh1_calculation_failed` .. `dh4_calculation_failed`, `kdf_failed` |
| `dr_init/5` | `invalid_shared_secret_size`, `invalid_identity_pub_size`, `invalid_self_priv_size`, `identity_pub_conversion_failed`, `identity_priv_conversion_failed`, `key_generation_failed`, `dh_failed`, `kdf_failed` |
| `dr_encrypt/2`, `dr_encrypt_prekey/3` | `invalid_session_size`, `session_not_initialized`, `must_receive_first`, `kdf_failed`, `encryption_failed`, `mac_failed`, `memory_allocation_failed`, `pksm_encode_failed` |
| `dr_decrypt/2` | `invalid_session_size`, `session_not_initialized`, `message_too_short`, `unsupported_version`, `malformed_message`, `bad_mac`, `too_many_skipped`, `dh_ratchet_failed`, `kdf_failed`, `decryption_failed`, `mac_failed`, `memory_allocation_failed` |
| `pksm_decode/1` | `malformed_message` |

## Sizes

| Item                    | Size                                     |
| ----------------------- | ---------------------------------------- |
| Curve25519 / X25519 key | 32 bytes                                 |
| Ed25519 public key      | 32 bytes                                 |
| Ed25519 private key     | 64 bytes (libsodium SK encoding)         |
| Ed25519 signature       | 64 bytes                                 |
| SHA-256 / HMAC-SHA-256  | 32 bytes                                 |
| SHA-512                 | 64 bytes                                 |
| AES-GCM key             | 32 bytes (AES-256 only)                  |
| AES-GCM IV              | 12 bytes                                 |
| AES-GCM tag             | 16 bytes                                 |
| X3DH shared secret      | 96 bytes (root 32 \|\| seed_a 32 \|\| seed_b 32) |
| DR session blob         | `sizeof(double_ratchet_state_t)`, ~5.3 KB; layout is compiler/ABI-specific, see `SECURITY.md` |
| DR MAC                  | 8 bytes (truncated HMAC-SHA-256)         |
| DR `enc_header`         | 80 bytes (iv 16 \|\| AES-CBC 48 \|\| tag 16) |
| PreKeyBundle wire       | 128 bytes (160 with OPK)                 |

## End-to-end flow

For complete X3DH + Double Ratchet + PreKeySignalMessage flows see `test/erl/unit/protocol/`. The most useful suites:

- `x3dh_dr_compose_SUITE` -- Alice and Bob compose X3DH into a DR session and round-trip messages.
- `pksm_SUITE` -- the full PreKeySignalMessage handshake with and without OPK.
- `double_ratchet_reorder_SUITE` -- out-of-order delivery against the MKSKIPPED cache.
- `dr_he_envelope_SUITE` -- header encryption: counter and ratchet-key are hidden, tampering rejected.
