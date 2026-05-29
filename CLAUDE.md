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

`make build` produces **three** shared libraries in `priv/` (each has its own `.c` entry point and `add_library` in `c_src/CMakeLists.txt`):

- `signal_nif.{so,dylib}` — legacy crypto primitives entry (`signal_nif.erl` / `c_src/signal_nif.c`)
- `libsignal_protocol_nif.{so,dylib}` — main module (`erl_src/libsignal_protocol_nif.erl` / `c_src/libsignal_protocol_nif.c`), includes session, double-ratchet, cache
- `libsignal_protocol_nif_v2.{so,dylib}` — clean function-table redesign (`libsignal_protocol_nif_v2.{erl,c}`)

After cmake produces the libs, the Makefile **and** `scripts/copy_nifs.sh` (a rebar3 post-compile hook in `rebar.config`) copy them into per-profile build dirs: `_build/{default,test,unit+test,integration+test,smoke+test}/lib/nif/priv/` and matching `extras/test/priv/`. If the NIF loads in `default` but not in `unit+test`, the copy step is the suspect.

macOS-specific: `c_src/CMakeLists.txt` links each NIF with `-undefined dynamic_lookup` so `enif_*` symbols resolve at load time against the host BEAM (no explicit `erl_interface` link). The Makefile sets `DYLD_LIBRARY_PATH` for the openssl@3 keg so tests can find it.

## Test

```bash
make test             # rebar3 ct (default profile)
make test-unit        # rebar3 as unit ct
make test-integration # rebar3 as integration ct
make test-smoke       # rebar3 as smoke ct
make test-cover       # rebar3 ct --cover
make perf-test        # erl -eval 'performance_test:run_benchmarks()'
make test-clean       # rm -rf tmp/ and log artifacts
```

Test tiers are rebar3 profiles in `rebar.config`, each with its own `ct_opts` config file under `test/erl/config/`:

- `unit` — `test/erl/unit/{crypto,nif,protocol,session}/*_SUITE.erl`, pinned to `signal_crypto_SUITE` by default
- `integration` — `test/erl/integration/integration_SUITE.erl` + `performance/`
- `smoke` — `test/erl/smoke/*_SUITE.erl` (simple/debug sanity)

Run a single suite:

```bash
rebar3 as unit ct --suite test/erl/unit/crypto/signal_crypto_SUITE
rebar3 as unit ct --suite test/erl/unit/nif/nif_functions_SUITE --case generate_curve25519_keypair_test
```

Wrapper tests live alongside the wrappers and are run from their own directories:

```bash
cd wrappers/elixir && mix test           # ExUnit, requires NIF already built in priv/
cd wrappers/gleam  && gleam test         # gleeunit 1.6.0 (Gleam 1.7+ — gleeunit dep history is fragile, see CHANGELOG)
```

Wrapper builds expect `priv/*.{so,dylib}` to exist — `mix.exs` does **not** build the NIF (`# NIF is expected to be built separately by CI`). Always `make build` first.

## Architecture

Layered: `Erlang/Elixir/Gleam app` -> `*.erl NIF stub module (erl_src/)` -> `*.c NIF (c_src/)` -> `libsodium`. The `.erl` stubs use `-on_load(load_nif/0)` with a fallback path list (`priv/`, `./priv/`, `../priv/`, plus several rebar3 `_build/...` ancestors) — this is why the copy-fanout matters.

C source under `c_src/` is split by concern: `crypto/` (primitives), `keys/` (key generation, identity, prekey), `session/` (session state), `protocol/` (Signal protocol logic), `cache/` (LRU stats), `utils/` (errors, common helpers). `types.h` and `constants.h` are shared. The Erlang `libsignal_protocol_nif` module exposes session lifecycle (`create_session`, `process_pre_key_bundle`, `encrypt_message`, `decrypt_message`), Double Ratchet (`init_double_ratchet`, `dr_*`), and cache stats; `signal_nif` exposes the lower-level crypto primitives.

Wrapper structure: `wrappers/elixir/lib/{libsignal_protocol,signal_protocol,session,pre_key_bundle}.ex` call into `:libsignal_protocol_nif` and translate atoms/binaries to idiomatic Elixir return shapes (`{:ok, ...} | {:error, String.t()}`). `wrappers/gleam/src/*.gleam` wraps the same NIF with `Result` types. Both wrappers depend on the parent project producing `priv/libsignal_protocol_nif.{so,dylib}` — they do not build C themselves.

## Conventions

- C: snake_case, sodium_memzero for sensitive buffers, return `{ok, ...} | {error, atom_reason}` as `ERL_NIF_TERM`. CMake target list in `c_src/CMakeLists.txt` is the source of truth for which libraries are built.
- Erlang: rebar3 format, `@spec` on public functions, `{ok, T} | {error, term()}` return convention.
- Wrappers mirror the Erlang return shape in their host idiom — do not invent new error vocabularies in the wrappers.
- When adding a new NIF function: add the `*.c` implementation, register it in the C dispatch table, add the `-export` and stub in the matching `.erl` module, and add a CT suite under `test/erl/unit/<area>/`. The post-compile hook will fan the rebuilt `.so` out — no rebar.config changes needed unless you add a new profile.

## Release

Versioning via `VERSION` (currently `0.1.1`) and `scripts/release.sh`. `make release-{patch,minor,major}` drives it. `make publish-wrappers` runs `mix hex.publish` and `rebar3 hex publish` from each wrapper after a fresh build. CI lives in `.github/workflows/{ci.yml,gleam-ci.yml}`.
