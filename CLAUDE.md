# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Erlang NIF exposing Signal Protocol cryptographic primitives (Curve25519, Ed25519, AES-GCM, SHA-256/512, HMAC-SHA256) backed by libsodium, with idiomatic wrappers for Elixir and Gleam. Three Hex packages ship from this repo: `libsignal_protocol_nif` (Erlang), `libsignal_protocol` (Elixir), `libsignal_protocol_gleam` (Gleam).

Toolchain pinned in `.tool-versions`: Erlang/OTP 26.2.4, Elixir 1.16.3-otp-26, rebar 3.22.0. Nix shell (`shell.nix`) is the canonical dev environment — most contributors run commands as `nix-shell --run "<cmd>"`.

## Build

```bash
make build           # cmake + make in c_src/, then fan NIFs out to _build/*/lib/nif/priv/
make clean           # rm priv/*.{so,dylib,dll} and c_src/build
make ci-build        # CI variant — parallel make, only fans out signal_nif.so
make diagnose        # prints state of build dirs; flags nested c_src/build/c_src corruption
```

`make build` produces **two** shared libraries in `priv/` (each has its own `.c` entry point and `add_library` in `c_src/CMakeLists.txt`):

- `signal_nif.{so,dylib}` — lower-level crypto primitives (`erl_src/signal_nif.erl` / `c_src/signal_nif.c`)
- `libsignal_protocol_nif.{so,dylib}` — main module (`erl_src/libsignal_protocol_nif.erl` / `c_src/libsignal_protocol_nif.c`), includes session, X3DH, double ratchet (DR-HE), PKSM, keys

After cmake produces the libs, the Makefile **and** `scripts/copy_nifs.sh` (a rebar3 post-compile hook in `rebar.config`) copy them into per-profile build dirs: `_build/{default,test,unit+test}/lib/nif/priv/` and matching `extras/test/priv/`. If the NIF loads in `default` but not in `unit+test`, the copy step is the suspect.

macOS-specific: `c_src/CMakeLists.txt` links each NIF with `-undefined dynamic_lookup` so `enif_*` symbols resolve at load time against the host BEAM (no explicit `erl_interface` link). The Makefile sets `DYLD_LIBRARY_PATH` for the openssl@3 keg so tests can find it.

## Test

```bash
make test             # rebar3 ct (default profile -- pinned to signal_crypto_SUITE)
make test-unit        # rebar3 as unit ct -- the full DR/X3DH/crypto suite
make test-cover       # rebar3 ct --cover
make test-unit-cover  # rebar3 as unit ct --cover
make perf-test        # erl -eval 'performance_test:run_benchmarks()'
make test-clean       # rm -rf tmp/ and log artifacts
```

Rebar3 profiles in `rebar.config`: `test` (default suite) and `unit` (full coverage). The `unit` profile uses `test/erl/config/unit.config`. Test suites live under `test/erl/unit/{crypto,protocol}/*_SUITE.erl`; `test/erl/integration/performance/` holds `perf-test`'s helpers.

Run a single suite or case:

```bash
rebar3 as unit ct --suite test/erl/unit/crypto/signal_crypto_SUITE
rebar3 as unit ct --suite test/erl/unit/protocol/double_ratchet_SUITE --case alice_to_bob_first_message_roundtrips
```

Wrapper tests live alongside the wrappers and are run from their own directories:

```bash
cd wrappers/elixir && mix test           # ExUnit, requires NIF already built in priv/
cd wrappers/gleam  && gleam test         # gleeunit 1.6.0 (Gleam 1.7+ — gleeunit dep history is fragile, see CHANGELOG)
```

Wrapper builds expect `priv/*.{so,dylib}` to exist — `mix.exs` does **not** build the NIF (`# NIF is expected to be built separately by CI`). Always `make build` first.

## Architecture

Layered: `Erlang/Elixir/Gleam app` -> `*.erl NIF stub module (erl_src/)` -> `*.c NIF (c_src/)` -> `libsodium`. The `.erl` stubs use `-on_load(load_nif/0)` with a fallback path list (`priv/`, `./priv/`, `../priv/`, plus several rebar3 `_build/...` ancestors) — this is why the copy-fanout matters.

C source under `c_src/` is flat, split by concern across files:

- `signal_nif.c` — entry for the `signal_nif` NIF (lower-level primitives).
- `libsignal_protocol_nif.c` — entry + dispatch table for the main NIF.
- `dr.c` / `dr.h` — Double Ratchet state struct (`double_ratchet_state_t`) and the four NIF entry points (`dr_init`, `dr_encrypt`, `dr_encrypt_prekey`, `dr_decrypt`).
- `dr_proto.{c,h}` — DR wire-format protobuf encode/decode (DrMessage header + DrEnvelope).
- `dr_crypto.{c,h}` — HKDF-SHA-256, AES-256-CBC, HMAC MAC, per-message/per-header key derivation, trial-decrypt for DR-HE. `DR_MAC_LEN` lives here.
- `dr_chain.{c,h}` — chain-key advance, message-key derive, MKSKIPPED cache, `dh_ratchet_recv`, `hk_is_nonzero`.
- `session.c` / `session.h` — X3DH (Alice and Bob sides), `create_session`, ChaCha20-Poly1305 encrypt/decrypt for the simple session API. Calls `hkdf_sha256` from `dr_crypto.h`.
- `pksm.{c,h}` — PreKeySignalMessage protobuf encode/decode (wraps Alice's first DR message).
- `keys.{c,h}` — keypair generation helpers used by the NIF.

The Erlang `libsignal_protocol_nif` module exposes session lifecycle (`create_session`, `process_pre_key_bundle`, `process_pre_key_bundle_bob`, `encrypt_message`, `decrypt_message`) and Double Ratchet (`dr_init`, `dr_encrypt`, `dr_encrypt_prekey`, `dr_decrypt`); `signal_nif` exposes the lower-level crypto primitives.

Wrapper structure: `wrappers/elixir/lib/{libsignal_protocol,signal_protocol,session,pre_key_bundle}.ex` call into `:libsignal_protocol_nif` and translate atoms/binaries to idiomatic Elixir return shapes (`{:ok, ...} | {:error, String.t()}`). `wrappers/gleam/src/*.gleam` wraps the same NIF with `Result` types. Both wrappers depend on the parent project producing `priv/libsignal_protocol_nif.{so,dylib}` — they do not build C themselves.

## Conventions

- C: snake_case, sodium_memzero for sensitive buffers, return `{ok, ...} | {error, atom_reason}` as `ERL_NIF_TERM`. CMake target list in `c_src/CMakeLists.txt` is the source of truth for which libraries are built.
- Erlang: rebar3 format, `@spec` on public functions, `{ok, T} | {error, term()}` return convention.
- Wrappers mirror the Erlang return shape in their host idiom — do not invent new error vocabularies in the wrappers.
- When adding a new NIF function: add the `*.c` implementation, register it in the C dispatch table, add the `-export` and stub in the matching `.erl` module, and add a CT suite under `test/erl/unit/<area>/`. The post-compile hook will fan the rebuilt `.so` out — no rebar.config changes needed unless you add a new profile.

## Release

Versioning via `VERSION` (currently `0.2.0`) and `scripts/release.sh`. `make release-{patch,minor,major}` drives it. `make publish-wrappers` runs `mix hex.publish` and `rebar3 hex publish` from each wrapper after a fresh build. CI lives in `.github/workflows/{ci.yml,gleam-ci.yml}`.
