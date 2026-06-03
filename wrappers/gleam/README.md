# libsignal_protocol_gleam

[![Hex.pm](https://img.shields.io/hexpm/v/libsignal_protocol_gleam.svg)](https://hex.pm/packages/libsignal_protocol_gleam)
[![Hex.pm](https://img.shields.io/hexpm/dt/libsignal_protocol_gleam.svg)](https://hex.pm/packages/libsignal_protocol_gleam)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Gleam wrapper over `libsignal_protocol_nif` -- the Erlang NIF in the [parent repo](https://github.com/Hydepwns/libsignal-protocol-nif). All calls return `Result(_, String)`. Errors come back as the atoms/strings the NIF produces; there is no typed error enum.

The NIF is not built by this package. Build it in the parent repo (`make build`) before depending on this wrapper.

## Install

```toml
[dependencies]
libsignal_protocol_gleam = "~> 0.2"
```

## Modules

- `signal_protocol` -- keygen, X3DH, Double Ratchet, PreKeySignalMessage
- `pre_key_bundle` -- `create`, `parse`, `verify_signature`, `to_binary`
- `utils` -- `generate_user_keys`, `create_user_bundle` (convenience helpers)

## Types

```gleam
pub type IdentityKeyPair { IdentityKeyPair(public_key: BitArray, private_key: BitArray) }
pub type PreKey          { PreKey(key_id: Int, public_key: BitArray) }
pub type SignedPreKey    { SignedPreKey(key_id: Int, public_key: BitArray, signature: BitArray) }
pub type DrSession       { DrSession(state: BitArray) }
pub type DrRole          { Alice | Bob }
```

## Quick start

```gleam
import gleam/option
import pre_key_bundle
import signal_protocol

let assert Ok(alice) = signal_protocol.generate_identity_key_pair()
let assert Ok(bob)   = signal_protocol.generate_identity_key_pair()
let assert Ok(opk)   = signal_protocol.generate_pre_key(1)
let assert Ok(spk)   = signal_protocol.generate_signed_pre_key(bob.private_key, 2)
```

X3DH. `process_pre_key_bundle` takes a typed `PreKeyBundle`; the wrapper serializes it to the format the NIF expects:

```gleam
let assert Ok(bundle) =
  pre_key_bundle.create(
    registration_id: 1,
    identity_key: bob.public_key,
    pre_key: opk,
    signed_pre_key: spk,
    base_key: <<0>>,
  )

let assert Ok(#(shared_secret, alice_eph_pub)) =
  signal_protocol.process_pre_key_bundle(alice.private_key, bundle)
```

Double Ratchet:

```gleam
let assert Ok(alice_dr) =
  signal_protocol.init_double_ratchet(
    shared_secret,
    alice.public_key,
    bob.public_key,
    <<>>,
    signal_protocol.Alice,
  )

let info =
  signal_protocol.PreKeyInfo(
    registration_id: 1,
    one_time_pre_key_id: option.Some(opk.key_id),
    signed_pre_key_id: spk.key_id,
    alice_ephemeral_pub: alice_eph_pub,
  )

let assert Ok(#(wire, alice_dr)) =
  signal_protocol.dr_encrypt_prekey(alice_dr, <<"hello">>, info)

let assert Ok(#(ct, alice_dr)) =
  signal_protocol.dr_encrypt_message(alice_dr, <<"second">>)
```

Bob recovers the shared secret from the envelope and initializes his side with `signal_protocol.Bob`. See `src/signal_protocol.gleam` for per-function docs and `test/` for end-to-end examples.

## Errors

Everything returns `Result(_, String)`. The string is whatever the NIF returned (e.g. `"invalid_signature"`, `"malformed_message"`). The wrapper does not translate or rewrite errors.

## License

Apache-2.0.
