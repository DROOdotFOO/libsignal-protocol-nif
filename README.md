# libsignal-protocol-nif

[![Erlang/OTP](https://img.shields.io/hexpm/v/libsignal_protocol_nif.svg?label=Erlang%2FOTP&style=flat-square)](https://hex.pm/packages/libsignal_protocol_nif)
[![Elixir](https://img.shields.io/hexpm/v/libsignal_protocol.svg?label=Elixir&style=flat-square)](https://hex.pm/packages/libsignal_protocol)
[![Gleam](https://img.shields.io/hexpm/v/libsignal_protocol_gleam.svg?label=Gleam&style=flat-square)](https://hex.pm/packages/libsignal_protocol_gleam)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg?style=flat-square)](LICENSE)

Signal Protocol crypto for the BEAM. Erlang NIF, libsodium underneath, idiomatic wrappers for Elixir and Gleam. Three Hex packages ship from this repo:

- `libsignal_protocol_nif` -- Erlang NIF + `.erl` stubs
- `libsignal_protocol` -- Elixir wrapper
- `libsignal_protocol_gleam` -- Gleam wrapper

## What's implemented

- Curve25519 ECDH, Ed25519 sign/verify
- AES-256-GCM, ChaCha20-Poly1305 (AEAD)
- SHA-256, SHA-512, HMAC-SHA256, HKDF-SHA-256
- X3DH key agreement (Alice + Bob sides)
- Double Ratchet with header encryption (DR-HE)
- PreKeySignalMessage envelope encode/decode
- `sodium_memzero` on sensitive scratch buffers

Linux and macOS (Apple Silicon and Intel) are the regularly tested targets. Windows builds are not in CI.

## Build

```bash
git clone https://github.com/Hydepwns/libsignal-protocol-nif.git
cd libsignal-protocol-nif
nix-shell --run "make build"
nix-shell --run "make test-unit"
```

Without Nix you need libsodium and CMake on the path:

- macOS: `brew install libsodium cmake`
- Debian/Ubuntu: `sudo apt-get install libsodium-dev cmake build-essential`

Toolchain: Erlang/OTP 26, Elixir 1.16, rebar 3.22. Exact versions pinned in `.tool-versions`.

`make build` writes two shared libraries to `priv/`: `signal_nif.{so,dylib}` (lower-level crypto) and `libsignal_protocol_nif.{so,dylib}` (sessions, X3DH, Double Ratchet).

## Install

Erlang (`rebar.config`):

```erlang
{deps, [{libsignal_protocol_nif, "0.2.0"}]}.
```

Elixir (`mix.exs`):

```elixir
{:libsignal_protocol, "~> 0.2"}
```

Gleam (`gleam.toml`):

```toml
[dependencies]
libsignal_protocol_gleam = "~> 0.2"
```

The Hex package ships sources only. At consumer `rebar3 compile` time, `c_src/build_nif.sh` fetches a pre-built NIF tarball from the matching GitHub Release for the consumer's platform. Supported triplets:

- `aarch64-apple-darwin` (macOS Apple Silicon)
- `x86_64-apple-darwin` (macOS Intel)
- `aarch64-unknown-linux-gnu` (Linux ARM64)
- `x86_64-unknown-linux-gnu` (Linux x86_64)

For any other platform, or when the download fails, the script falls back to a cmake source build. That requires libsodium + OpenSSL development headers + cmake on the system. Set `LIBSIGNAL_NIF_BUILD_FROM_SOURCE=1` to skip the download attempt and go straight to the source path.

## Erlang example

```erlang
{ok, {Pub, Priv}} = signal_nif:generate_ed25519_keypair(),
Msg = <<"hello">>,
{ok, Sig} = signal_nif:sign_data(Priv, Msg),
ok = signal_nif:verify_signature(Pub, Msg, Sig),

Key = crypto:strong_rand_bytes(32),
IV  = crypto:strong_rand_bytes(12),
{ok, Ct, Tag} = signal_nif:aes_gcm_encrypt(Key, IV, Msg, <<>>, 16),
{ok, Msg}     = signal_nif:aes_gcm_decrypt(Key, IV, Ct, <<>>, Tag, byte_size(Msg)).
```

For full X3DH + Double Ratchet flows see `test/erl/unit/protocol/double_ratchet_SUITE.erl`. Elixir and Gleam examples live in each wrapper's README.

## Troubleshooting

`{error, {load_failed, ...}}`: run `make build` first and confirm `priv/*.{so,dylib}` exists. If only the `default` profile loads, check `scripts/copy_nifs.sh` -- the rebar3 post-compile hook fans NIFs out into `_build/{test,unit+test}/lib/nif/priv/`.

`fatal error: sodium.h: No such file`: install libsodium development headers.

macOS link issues: the Makefile sets `DYLD_LIBRARY_PATH` for the openssl@3 keg. Inspect with `otool -L priv/signal_nif.so`.

## Docs

- [API reference](docs/API.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security notes](docs/SECURITY.md)
- [Cross-language comparison](docs/CROSS_LANGUAGE_COMPARISON.md)

Contributor guide: [CONTRIBUTING.md](CONTRIBUTING.md). Build and CI details: [CLAUDE.md](CLAUDE.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
