defmodule LibsignalProtocol.MixProject do
  use Mix.Project

  def project do
    [
      app: :libsignal_protocol,
      version: "0.2.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_coverage: [tool: ExCoveralls, output: "tmp/cover"],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test,
        "coveralls.github": :test
      ],
      docs: [output: "tmp/doc"],
      aliases: aliases(),
      description:
        "High-performance Elixir wrapper for Signal Protocol cryptographic primitives with libsodium. Provides idiomatic APIs for key generation, digital signatures, encryption, and session management.",
      package: package(),
      source_url: "https://github.com/hydepwns/libsignal-protocol-nif",
      homepage_url: "https://hex.pm/packages/libsignal_protocol"
    ]
  end

  defp package do
    [
      name: "libsignal_protocol",
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/hydepwns/libsignal-protocol-nif"},
      files: ~w(lib mix.exs README.md LICENSE),
      maintainers: ["hydepwns"],
      keywords: [
        "signal",
        "protocol",
        "cryptography",
        "encryption",
        "security",
        "nif",
        "libsodium",
        "curve25519",
        "ed25519",
        "aes-gcm"
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:castore, "~> 1.0"},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:excoveralls, "~> 0.18", only: :test},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.3", only: [:dev], runtime: false}
    ]
  end

  # NIF is expected to be built separately by CI
  defp aliases do
    [
      compile: ["compile"],
      clean: ["clean"]
    ]
  end
end
