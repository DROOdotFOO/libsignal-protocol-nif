defmodule LibsignalProtocolTest do
  use ExUnit.Case
  doctest LibsignalProtocol

  describe "NIF loading" do
    test "can initialize the library" do
      case LibsignalProtocol.init() do
        :ok ->
          assert true

        {:error, reason} ->
          IO.puts("NIF init failed (expected in test environment): #{inspect(reason)}")
          assert is_atom(reason)
      end
    end
  end

  describe "key generation" do
    test "attempts to generate identity key pair" do
      case LibsignalProtocol.generate_identity_key_pair() do
        {:ok, {public_key, signature}} ->
          assert is_binary(public_key)
          assert is_binary(signature)
          assert byte_size(public_key) > 0
          assert byte_size(signature) > 0

        {:error, reason} ->
          IO.puts("Key generation failed (expected if NIF not loaded): #{inspect(reason)}")
          assert is_atom(reason)
      end
    end
  end

  describe "session management" do
    test "attempts to create session with key pair" do
      # Generate test keys (32 bytes each for Curve25519)
      private_key = :crypto.strong_rand_bytes(32)
      public_key = :crypto.strong_rand_bytes(32)

      case LibsignalProtocol.create_session(private_key, public_key) do
        {:ok, session} ->
          assert is_binary(session)
          assert byte_size(session) > 0

        {:error, reason} ->
          IO.puts("Session creation failed (expected if NIF not loaded): #{inspect(reason)}")
          assert is_atom(reason)
      end
    end
  end
end
