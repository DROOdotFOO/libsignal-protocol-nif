# Cross-language comparison

All three wrappers call the same C NIF. Crypto behavior is identical. Differences are at the surface: idiom, error shape, type system.

## Packages

|                 | Erlang                                 | Elixir                                                               | Gleam                                        |
| --------------- | -------------------------------------- | -------------------------------------------------------------------- | -------------------------------------------- |
| Hex package     | `libsignal_protocol_nif`               | `libsignal_protocol`                                                 | `libsignal_protocol_gleam`                   |
| Entry module(s) | `signal_nif`, `libsignal_protocol_nif` | `SignalProtocol`, `LibsignalProtocol`, `SignalProtocol.PreKeyBundle` | `signal_protocol`, `pre_key_bundle`, `utils` |
| Return shape    | `{ok, T} \| {error, atom}`             | `{:ok, term} \| {:error, atom}`                                      | `Result(_, String)`                          |
| Test framework  | Common Test                            | ExUnit                                                               | gleeunit                                     |
| Static analysis | Dialyzer                               | Dialyzer, Credo                                                      | Gleam compiler                               |

The Elixir and Gleam wrappers expose the Signal Protocol surface (X3DH, Double Ratchet, PreKeySignalMessage) plus identity / pre-key generation. The simple ChaCha20-Poly1305 session API (`create_session/2`, `encrypt_message/2`, `decrypt_message/2`) is only on the Erlang NIF -- the wrappers dropped it because the legacy "session" naming was misleading; the real Signal flow is `process_pre_key_bundle` -> `init_double_ratchet` -> `dr_encrypt_message`.

For the lower-level primitives (`sha256/1`, `aes_gcm_encrypt/5`, `sign_data/2`, etc.) call `:signal_nif` directly from Elixir or `@external` to `signal_nif` from Gleam -- there are no wrapper modules around those.

## Keygen

```erlang
{ok, {Pub, Priv}} = libsignal_protocol_nif:generate_identity_key_pair().
{ok, {KeyId, PreKeyPub}} = libsignal_protocol_nif:generate_pre_key(1).
{ok, {KeyId, SpkPub, Sig}} =
    libsignal_protocol_nif:generate_signed_pre_key(Priv, 2).
```

```elixir
{:ok, {pub, priv}} = SignalProtocol.generate_identity_key_pair()
{:ok, {key_id, pre_key_pub}} = SignalProtocol.generate_pre_key(1)
{:ok, {key_id, spk_pub, sig}} =
  SignalProtocol.generate_signed_pre_key(priv, 2)
```

```gleam
let assert Ok(identity) = signal_protocol.generate_identity_key_pair()
let assert Ok(pre_key)  = signal_protocol.generate_pre_key(1)
let assert Ok(spk)      =
  signal_protocol.generate_signed_pre_key(identity.private_key, 2)
```

The Gleam wrapper returns typed records (`IdentityKeyPair`, `PreKey`, `SignedPreKey`). Erlang and Elixir return raw tuples.

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
// Gleam takes a typed PreKeyBundle; the wrapper serializes it for the NIF.
let assert Ok(bundle) = pre_key_bundle.create(1, bob_pub, opk, spk, <<0>>)
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

The NIFs return atoms. Each wrapper preserves them in its idiom:

```erlang
case libsignal_protocol_nif:dr_decrypt(Session, Ct) of
    {ok, {Pt, S2}} -> ...;
    {error, mac_verification_failed} -> ...;
    {error, Reason} -> ...
end.
```

```elixir
case SignalProtocol.dr_decrypt_message(session, ct) do
  {:ok, {pt, s2}} -> ...
  {:error, :mac_verification_failed} -> ...
  {:error, reason} -> ...
end
```

```gleam
case signal_protocol.dr_decrypt_message(session, ct) {
  Ok(#(pt, s2)) -> ...
  Error("mac_verification_failed") -> ...
  Error(reason) -> ...
}
```

The Gleam wrapper does not box errors in a typed enum -- the underlying NIF atom is converted to a string and surfaced as-is. There is no `Error.InvalidParameters` type; if you want one, build it on top.

## Picking a wrapper

- **Erlang** -- existing OTP codebase, want zero wrapper overhead, OK with raw tuples.
- **Elixir** -- new project, want `{:ok, _}` idiom, Mix/Hex tooling, pattern matching at use sites.
- **Gleam** -- want typed records for keys and sessions, exhaustive pattern matching, compiler-checked tags.

The wrappers do not differ in correctness or performance -- they all bottom out in the same NIF. Pick the host language that suits the rest of your stack.
