{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    erlang
    rebar3
    cmake
    gcc
    gdb
    libsodium
    # c_src/CMakeLists.txt does find_package(OpenSSL REQUIRED) for AES-256-CBC.
    openssl
    pkg-config
    # Wrapper toolchains; not needed for the Erlang NIF itself.
    elixir
    gleam
  ];
  
  shellHook = ''
    echo "libsignal-protocol-nif dev shell"
    echo "Erlang/OTP $(erl -noshell -eval 'io:format("~s~n", [erlang:system_info(otp_release)]), halt().')"
    echo "  make build       # Build the NIF into priv/"
    echo "  make test-unit   # Run every CT suite"
    echo "  cd wrappers/elixir && mix test"
    echo "  cd wrappers/gleam  && gleam test"
  '';
} 