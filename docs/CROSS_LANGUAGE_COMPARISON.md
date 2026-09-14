# Cross-language comparison

All three wrappers call the same C NIF. Crypto behavior is identical. Differences are at the surface: idiom, error shape, type system.

## Packages

|                 | Erlang                                 | Elixir                                                               | Gleam                                        |
| --------------- | -------------------------------------- | -------------------------------------------------------------------- | -------------------------------------------- |
| Hex package     | `libsignal_protocol_nif`               | `libsignal_protocol`                                                 | `libsignal_protocol_gleam`                   |
| Entry module(s) | `signal_nif`, `libsignal_protocol_nif` | `SignalProtocol`, `LibsignalProtocol`, `SignalProtocol.PreKeyBundle` | `signal_protocol`, `pre_key_bundle`, `utils` |
| Return shape    | `{ok, T} \| {error, atom}`             | `{:ok, term} \| {:error, atom}`                                      | `Result(_, String)` as declared; see Errors  |
| Test framework  | Common Test                            | ExUnit                                                               | gleeunit                                     |
| Static analysis | Dialyzer                               | Dialyzer, Credo                                                      | Gleam compiler                               |

Both wrappers expose the same surface as the NIF: identity / pre-key generation, X3DH, the Double Ratchet, and the PreKeySignalMessage envelope. The flow is `process_pre_key_bundle` -> `init_double_ratchet` -> `dr_encrypt_message`. (The static-key ChaCha20-Poly1305 "simple session" API was removed in 0.3.)

For the lower-level primitives (`sha256/1`, `aes_gcm_encrypt/5`, `sign_data/2`, etc.) call `:signal_nif` directly from Elixir or `@external` to `signal_nif` from Gleam -- there are no wrapper modules around those.

## Keygen

```erlang
{ok, {Pub, Priv}} = libsignal_protocol_nif:generate_identity_key_pair().
{ok, {KeyId, PreKeyPub, PreKeyPriv}} = libsignal_protocol_nif:generate_pre_key(1).
{ok, {KeyId, SpkPub, SpkPriv, Sig}} =
    libsignal_protocol_nif:generate_signed_pre_key(Priv, 2).
```

```elixir
{:ok, {pub, priv}} = SignalProtocol.generate_identity_key_pair()
{:ok, {key_id, pre_key_pub, pre_key_priv}} = SignalProtocol.generate_pre_key(1)
{:ok, {key_id, spk_pub, spk_priv, sig}} =
  SignalProtocol.generate_signed_pre_key(priv, 2)
```

```gleam
let assert Ok(identity) = signal_protocol.generate_identity_key_pair()
let assert Ok(pre_key)  = signal_protocol.generate_pre_key(1)
let assert Ok(spk)      =
  signal_protocol.generate_signed_pre_key(identity.private_key, 2)
```

Every generator hands back the private half; the responder needs the pre-key and signed-pre-key privates to complete X3DH. The Gleam wrapper returns typed records (`IdentityKeyPair`, `PreKey`, `SignedPreKey`); Erlang and Elixir return raw tuples.

## X3DH

```erlang
%% Bundle = id_pub(32) || spk_pub(32) || sig(64) [|| opk_pub(32)]
{ok, {SK96, AliceEphPub32}} =
    libsignal_protocol_nif:process_pre_key_bundle(AliceIdPriv64, Bundle).
```

```elixir
bundle = <<bob_pub::binary, spk_pub::binary, spk_sig::binary, opk_pub::binary>>
{:ok, {sk, alice_eph_pub}} =
  SignalProtocol.process_pre_key_bundle(alice_priv, bundle)
```

```gleam
// Build the 128/160-byte NIF bundle layout directly. `pre_key_bundle.create`
// produces a different, wrapper-local layout that the NIF rejects with
// `invalid_bundle_size`; do not feed it to process_pre_key_bundle.
let bundle = <<bob_pub:bits, spk_pub:bits, spk_sig:bits, opk_pub:bits>>
let assert Ok(#(sk, alice_eph_pub)) =
  signal_protocol.process_pre_key_bundle(alice_priv, bundle)
```

## Double Ratchet

```erlang
{ok, Session} = libsignal_protocol_nif:dr_init(SK96, IdPub, RemPub, <<>>, 1).
{ok, {Ct, Session2}} = libsignal_protocol_nif:dr_encrypt(Session, <<"hi">>).
{ok, {Pt, Session3}} = libsignal_protocol_nif:dr_decrypt(Session2, Ct).
```

```elixir
{:ok, session}        = SignalProtocol.init_double_ratchet(sk, id_pub, rem_pub, <<>>, 1)
{:ok, {ct, session}}  = SignalProtocol.dr_encrypt_message(session, "hi")
{:ok, {pt, session}}  = SignalProtocol.dr_decrypt_message(session, ct)
```

```gleam
let assert Ok(session) =
  signal_protocol.init_double_ratchet(sk, id_pub, rem_pub, <<>>, signal_protocol.Alice)
let assert Ok(#(ct, session)) = signal_protocol.dr_encrypt_message(session, <<"hi">>)
let assert Ok(#(pt, session)) = signal_protocol.dr_decrypt_message(session, ct)
```

The Erlang and Elixir APIs take an `IsAlice` integer (1 or 0). Gleam takes the typed `DrRole.Alice | Bob`.

## Errors

The NIFs return atoms (see `API.md`, "Error atoms", for the full list). Erlang and Elixir preserve them:

```erlang
case libsignal_protocol_nif:dr_decrypt(Session, Ct) of
    {ok, {Pt, S2}} -> ...;
    {error, bad_mac} -> ...;
    {error, too_many_skipped} -> ...;
    {error, Reason} -> ...
end.
```

```elixir
case SignalProtocol.dr_decrypt_message(session, ct) do
  {:ok, {pt, s2}} -> ...
  {:error, :bad_mac} -> ...
  {:error, reason} -> ...
end
```

The Gleam wrapper declares `Result(_, String)`, but most of its externals bind straight to the NIF and the value at runtime is the Erlang atom, not a `String` -- `Error("bad_mac")` will not match and `string.*` functions on the error will crash. Until 0.3 routes every call through the FFI with `atom_to_binary`, treat the error as opaque: match `Error(_)` and log it with `string.inspect`.

## Picking a wrapper

- **Erlang** -- existing OTP codebase, want zero wrapper overhead, OK with raw tuples.
- **Elixir** -- new project, want `{:ok, _}` idiom, Mix/Hex tooling, pattern matching at use sites.
- **Gleam** -- want typed records for keys and sessions, exhaustive pattern matching, compiler-checked tags.

The wrappers do not differ in correctness or performance -- they all bottom out in the same NIF. Pick the host language that suits the rest of your stack.
