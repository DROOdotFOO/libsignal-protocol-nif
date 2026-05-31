defmodule SignalProtocolTest do
  use ExUnit.Case, async: true

  test "generate_identity_key_pair returns two 32-byte binaries" do
    assert {:ok, {pub, priv}} = SignalProtocol.generate_identity_key_pair()
    assert byte_size(pub) == 32
    assert byte_size(priv) == 32
    assert pub != priv
  end

  test "generate_pre_key echoes the key_id with a 32-byte public key" do
    key_id = :rand.uniform(1000)
    assert {:ok, {^key_id, public_key}} = SignalProtocol.generate_pre_key(key_id)
    assert byte_size(public_key) == 32
  end

  test "generate_signed_pre_key returns key_id, 32B public, 32B signature" do
    {:ok, {identity_key, _}} = SignalProtocol.generate_identity_key_pair()
    key_id = :rand.uniform(1000)

    assert {:ok, {^key_id, public_key, signature}} =
             SignalProtocol.generate_signed_pre_key(identity_key, key_id)

    assert byte_size(public_key) == 32
    assert byte_size(signature) == 32
  end

  test "create_session returns a non-empty binary session id" do
    {:ok, {local, _}} = SignalProtocol.generate_identity_key_pair()
    {:ok, {remote, _}} = SignalProtocol.generate_identity_key_pair()

    assert {:ok, session} = SignalProtocol.create_session(local, remote)
    assert is_binary(session)
    assert byte_size(session) > 0
  end
end
