defmodule SignalProtocolTest do
  use ExUnit.Case, async: true

  test "generate_identity_key_pair returns an Ed25519 keypair (32B pub, 64B priv)" do
    assert {:ok, {pub, priv}} = SignalProtocol.generate_identity_key_pair()
    assert byte_size(pub) == 32
    assert byte_size(priv) == 64
    assert pub != priv
  end

  test "generate_pre_key echoes the key_id with a 32-byte public key" do
    key_id = :rand.uniform(1000)
    assert {:ok, {^key_id, public_key}} = SignalProtocol.generate_pre_key(key_id)
    assert byte_size(public_key) == 32
  end

  test "generate_signed_pre_key returns key_id, 32B public, 64B Ed25519 signature" do
    {:ok, {_pub, priv}} = SignalProtocol.generate_identity_key_pair()
    key_id = :rand.uniform(1000)

    assert {:ok, {^key_id, public_key, signature}} =
             SignalProtocol.generate_signed_pre_key(priv, key_id)

    assert byte_size(public_key) == 32
    assert byte_size(signature) == 64
  end

  test "process_pre_key_bundle performs X3DH and returns {shared_secret, ephemeral_pub}" do
    {:ok, {_alice_pub, alice_priv}} = SignalProtocol.generate_identity_key_pair()
    {:ok, {bob_id_pub, bob_id_priv}} = SignalProtocol.generate_identity_key_pair()
    {:ok, {_key_id, spk_pub, signature}} =
      SignalProtocol.generate_signed_pre_key(bob_id_priv, 1)
    bundle = bob_id_pub <> spk_pub <> signature

    assert {:ok, {shared_secret, ephemeral_pub}} =
             SignalProtocol.process_pre_key_bundle(alice_priv, bundle)
    assert byte_size(shared_secret) == 96
    assert byte_size(ephemeral_pub) == 32
  end

  describe "Double Ratchet" do
    setup do
      {:ok, {alice_pub, _alice_priv}} = SignalProtocol.generate_identity_key_pair()
      {:ok, {bob_pub, bob_priv}} = SignalProtocol.generate_identity_key_pair()
      shared_secret = :crypto.strong_rand_bytes(96)

      {:ok, alice} =
        SignalProtocol.init_double_ratchet(shared_secret, alice_pub, bob_pub, <<>>, 1)

      {:ok, bob} =
        SignalProtocol.init_double_ratchet(shared_secret, bob_pub, alice_pub, bob_priv, 0)

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

  describe "PreKeySignalMessage end-to-end" do
    test "Alice -> Bob first message via PKSM, without OPK" do
      {:ok, {alice_pub, alice_priv}} = SignalProtocol.generate_identity_key_pair()
      {:ok, {bob_pub, bob_priv}} = SignalProtocol.generate_identity_key_pair()

      # Mint Bob's SPK ourselves so we retain the private half.
      {:ok, {spk_pub, spk_priv}} = :signal_nif.generate_curve25519_keypair()
      bob_seed = binary_part(bob_priv, 0, 32)
      {:ok, signature} = :signal_nif.sign_data(bob_seed, spk_pub)
      bundle = bob_pub <> spk_pub <> signature

      {:ok, {sk, alice_eph_pub}} =
        SignalProtocol.process_pre_key_bundle(alice_priv, bundle)

      {:ok, alice_dr} =
        SignalProtocol.init_double_ratchet(sk, alice_pub, bob_pub, <<>>, 1)

      plaintext = "first contact"

      {:ok, {wire, _alice_dr2}} =
        SignalProtocol.dr_encrypt_prekey(
          alice_dr,
          plaintext,
          {1234, nil, 42, alice_eph_pub}
        )

      # Bob parses and recovers the SK.
      {:ok, {1234, ^alice_eph_pub, _id_key_x, nil, 42, inner}} =
        SignalProtocol.pksm_decode(wire)

      {:ok, ^sk} =
        SignalProtocol.process_pre_key_bundle_bob(
          bob_priv,
          spk_priv,
          <<>>,
          alice_pub,
          alice_eph_pub
        )

      {:ok, bob_dr} =
        SignalProtocol.init_double_ratchet(sk, bob_pub, alice_pub, bob_priv, 0)

      assert {:ok, {^plaintext, _bob_dr2}} =
               SignalProtocol.dr_decrypt_message(bob_dr, inner)
    end

    test "pksm_decode returns {:error, :malformed_message} on garbage" do
      assert {:error, :malformed_message} =
               SignalProtocol.pksm_decode(<<0x22, 1, 2, 3>>)

      assert {:error, :malformed_message} =
               SignalProtocol.pksm_decode(<<>>)
    end
  end
end
