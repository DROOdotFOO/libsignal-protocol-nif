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

  describe "Double Ratchet" do
    setup do
      {:ok, {bob_pub, bob_priv}} = :signal_nif.generate_curve25519_keypair()
      shared_secret = :crypto.strong_rand_bytes(64)
      {:ok, alice} = SignalProtocol.init_double_ratchet(shared_secret, bob_pub, <<>>, 1)
      {:ok, bob} = SignalProtocol.init_double_ratchet(shared_secret, <<>>, bob_priv, 0)
      %{alice: alice, bob: bob}
    end

    test "Alice -> Bob first message round-trips", %{alice: alice, bob: bob} do
      msg = "hello from alice"
      assert {:ok, {ct, _alice1}} = SignalProtocol.dr_encrypt_message(alice, msg)
      assert {:ok, {^msg, _bob1}} = SignalProtocol.dr_decrypt_message(bob, ct)
    end

    test "bob cannot send before receiving Alice's first message", %{bob: bob} do
      assert {:error, :must_receive_first} =
               SignalProtocol.dr_encrypt_message(bob, "premature reply")
    end

    test "bidirectional handshake", %{alice: alice, bob: bob} do
      {:ok, {ct_a2b, _alice1}} = SignalProtocol.dr_encrypt_message(alice, "hi bob")
      {:ok, {"hi bob", bob1}} = SignalProtocol.dr_decrypt_message(bob, ct_a2b)
      {:ok, {ct_b2a, _bob2}} = SignalProtocol.dr_encrypt_message(bob1, "hi alice")
      {:ok, {"hi alice", _alice2}} = SignalProtocol.dr_decrypt_message(alice, ct_b2a)
    end
  end
end
