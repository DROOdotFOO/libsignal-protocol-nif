# libsignal_protocol

[![Hex.pm](https://img.shields.io/hexpm/v/libsignal_protocol.svg)](https://hex.pm/packages/libsignal_protocol)
[![Hex.pm](https://img.shields.io/hexpm/dt/libsignal_protocol.svg)](https://hex.pm/packages/libsignal_protocol)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Elixir wrapper over `:libsignal_protocol_nif` -- the Erlang NIF in the [parent repo](https://github.com/Hydepwns/libsignal-protocol-nif). The wrapper is a thin facade: it forwards calls to the NIF and returns whatever the NIF returns (`{:ok, term} | {:error, atom}`).

The NIF is not built by this package. Either depend on the parent project's build artifacts or run `make build` in the repo root first. A missing NIF raises `UndefinedFunctionError` at the call site.

## Install

```elixir
def deps do
  [{:libsignal_protocol, "~> 0.2"}]
end
```

## Modules

- `LibsignalProtocol` -- `init/0`, `generate_identity_key_pair/0`, `create_session/2`
- `SignalProtocol` -- keygen, X3DH, Double Ratchet, PreKeySignalMessage
- `SignalProtocol.PreKeyBundle` -- bundle serialize / parse / verify

## Quick start

```elixir
:ok = LibsignalProtocol.init()

# Each party generates an identity key pair (Ed25519)
{:ok, {alice_pub, alice_priv}} = SignalProtocol.generate_identity_key_pair()
{:ok, {bob_pub,   bob_priv}}   = SignalProtocol.generate_identity_key_pair()

# Pre-keys (Bob publishes these)
{:ok, {opk_id, opk_pub}}            = SignalProtocol.generate_pre_key(1)
{:ok, {spk_id, spk_pub, spk_sig}}   = SignalProtocol.generate_signed_pre_key(bob_priv, 2)
```

X3DH against a remote bundle. The bundle binary is `remote_identity_pub(32) ++ signed_prekey_pub(32) ++ signature(64)` with an optional trailing 32-byte one-time prekey. The signature is Ed25519 over `signed_prekey_pub` under the remote identity key.

```elixir
bundle = <<bob_pub::binary, spk_pub::binary, spk_sig::binary, opk_pub::binary>>

{:ok, {shared_secret, alice_eph_pub}} =
  SignalProtocol.process_pre_key_bundle(alice_priv, bundle)
```

Double Ratchet:

```elixir
# Alice is the initiator -> is_alice = 1
{:ok, alice_dr} =
  SignalProtocol.init_double_ratchet(shared_secret, alice_pub, bob_pub, <<>>, 1)

# Alice's first message is wrapped in a PreKeySignalMessage envelope
pre_key_info = {_reg_id = 1, opk_id, spk_id, alice_eph_pub}
{:ok, {wire, alice_dr}} =
  SignalProtocol.dr_encrypt_prekey(alice_dr, "hello", pre_key_info)

# Subsequent messages
{:ok, {ct, alice_dr}} = SignalProtocol.dr_encrypt_message(alice_dr, "second")
```

Bob recovers the same shared secret from the envelope:

```elixir
{:ok, {_reg, _base, _id, opk_id, spk_id, inner}} = SignalProtocol.pksm_decode(wire)

{:ok, bob_shared} =
  SignalProtocol.process_pre_key_bundle_bob(
    bob_priv, spk_priv, opk_priv, alice_pub, alice_eph_pub
  )

# is_alice = 0 for Bob
{:ok, bob_dr} =
  SignalProtocol.init_double_ratchet(bob_shared, bob_pub, alice_pub, bob_priv, 0)

{:ok, {"hello", bob_dr}} = SignalProtocol.dr_decrypt_message(bob_dr, inner)
```

Full inline docs live in `lib/signal_protocol.ex`. End-to-end test flows are in the parent repo under `test/erl/unit/protocol/`.

## Pre-key bundles

`SignalProtocol.PreKeyBundle` handles the higher-level bundle format used between parties (versioned, includes key IDs):

```elixir
{:ok, bundle} =
  SignalProtocol.PreKeyBundle.create(
    registration_id, identity_key, {opk_id, opk_pub},
    {spk_id, spk_pub, spk_sig}, base_key
  )

{:ok, parsed} = SignalProtocol.PreKeyBundle.parse(bundle)
:ok = SignalProtocol.PreKeyBundle.verify_signature(bundle)
```

## Errors

NIF errors are returned verbatim. The wrapper does not translate, rename, or wrap them. If the NIF returns `{:error, :invalid_signature}`, that is what you get.

## License

Apache-2.0.
