# Contributing

## Setup

```bash
git clone https://github.com/Hydepwns/libsignal-protocol-nif.git
cd libsignal-protocol-nif
nix-shell --run "make build && make test-unit"
```

Without Nix you need libsodium, OpenSSL 3, CMake, Erlang/OTP 26, Elixir 1.16, and rebar 3.22. The pinned versions live in `.tool-versions`.

Layout, build internals, and the NIF copy-fanout are in [CLAUDE.md](CLAUDE.md). The short version: `make build` produces two shared libraries in `priv/` and `scripts/copy_nifs.sh` fans them into per-profile dirs. If the NIF loads in `default` but not `unit+test`, look there first.

## Build and test

```bash
make build              # cmake + copy NIFs
make test               # default profile (signal_crypto_SUITE only)
make test-unit          # full DR / X3DH / crypto suite
make test-cover         # default + coverage
make test-unit-cover    # full + coverage
make perf-test          # performance_test:run_benchmarks/0
make diagnose           # flags nested c_src/build/c_src corruption
```

Single suite or case:

```bash
rebar3 as unit ct --suite test/erl/unit/crypto/signal_crypto_SUITE
rebar3 as unit ct --suite test/erl/unit/protocol/double_ratchet_SUITE \
                 --case alice_to_bob_first_message_roundtrips
```

Wrapper tests run from their own directories and expect `priv/*.{so,dylib}` to already exist:

```bash
cd wrappers/elixir && mix test
cd wrappers/gleam  && gleam test
```

## Style

- **C**: snake_case, `sodium_memzero` on sensitive buffers, return `{ok, ...} | {error, atom_reason}`. The CMake target list in `c_src/CMakeLists.txt` is the source of truth for what gets built.
- **Erlang**: `rebar3 format`. `@spec` on public functions. `{ok, T} | {error, term()}` returns.
- **Wrappers**: mirror the Erlang return shape; do not invent new error vocabularies. The Elixir wrapper returns atoms verbatim; the Gleam wrapper returns the atom/string as `Result(_, String)`.

## Adding a NIF function

1. Implement in the matching `c_src/*.c` file.
2. Register in the dispatch table at the top of `c_src/libsignal_protocol_nif.c` (or `signal_nif.c`).
3. Add `-export` and a stub in the matching `src/*.erl`, with `-spec`.
4. Add a CT suite under `test/erl/unit/<area>/` and run `make test-unit`.

The post-compile hook fans the rebuilt `.so` out, so no `rebar.config` changes unless you add a new profile.

## Pre-PR checklist

- `make test-unit` passes.
- `rebar3 format --verify` is clean (CI runs this).
- Wrapper tests pass if you touched a wrapper.
- A CT suite covers the change. Tests live alongside the layer they exercise.
- If you changed the C dispatch table or any wire format, note it in `CHANGELOG.md` under `[Unreleased]`. Breaking changes are clearly flagged there.
- Don't commit `priv/*.{so,dylib}` -- they're built artifacts.
- Don't run with `--no-verify`. If a hook fails, fix the cause.

## PR description

Title under 70 chars. In the body:

- What changed and why.
- Whether the change is wire-breaking (DR session blobs, bundle layout, PKSM envelope).
- How you tested it -- which suite, which case.

## Release

`VERSION` is the source of truth. `make release-{patch,minor,major}` runs `scripts/release.sh`. CI workflows live in `.github/workflows/{ci.yml,gleam-ci.yml,release.yml}`.

The publish sequence has multiple steps because the Hex tarball references binaries that don't exist until the release workflow runs:

1. Bump VERSION, mix.exs, gleam.toml, `src/*.app.src` if needed.
2. `git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z`. The push triggers `release.yml`, which builds the NIF on four platforms and creates a GitHub Release with the per-platform tarballs and `CHECKSUMS.txt` attached. Wait for this to finish (~10 min).
3. Locally: `make hex-package`. Builds a clean source tarball at `_build/default/lib/libsignal_protocol_nif/hex/libsignal_protocol_nif-X.Y.Z.tar`.
4. `rebar3 hex publish` from the repo root publishes the Erlang package. At install time, consumers' `c_src/build_nif.sh` (shipped in the tarball) fetches the matching binary from the GitHub Release created in step 2.
5. `make publish-wrappers` publishes the Elixir and Gleam wrappers via `mix hex.publish` and `rebar3 hex publish` in `wrappers/{elixir,gleam}/`.

## Reporting bugs

GitHub Issues. Include OS, Erlang/OTP version, the failing command, and the output. For security issues see [docs/SECURITY.md](docs/SECURITY.md) before filing publicly.
