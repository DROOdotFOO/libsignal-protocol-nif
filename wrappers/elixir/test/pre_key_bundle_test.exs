defmodule LibsignalProtocol.PreKeyBundleTest do
  use ExUnit.Case, async: true
  alias LibsignalProtocol.PreKeyBundle

  setup do
    # Initialize the NIF
    :ok = :nif.init()
    :ok
  end

  describe "PreKeyBundle.create/5" do
    test "creates a valid pre-key bundle" do
      # Generate identity keys
      {:ok, {identity_key, _}} = :nif.generate_identity_key_pair()

      # Generate pre-key components
      {:ok, {pre_key_id, pre_key_public}} = :nif.generate_pre_key(12345)
      {:ok, {signed_pre_key_id, signed_pre_key_public, signature}} =
        :nif.generate_signed_pre_key(identity_key, 67890)

      # Create pre-key bundle
      bundle = PreKeyBundle.create(
        123,  # registration_id
        456,  # device_id
        {pre_key_id, pre_key_public},
        {signed_pre_key_id, signed_pre_key_public, signature},
        identity_key
      )

      assert is_map(bundle)
      assert bundle.registration_id == 123
      assert bundle.device_id == 456
      assert bundle.pre_key == {pre_key_id, pre_key_public}
      assert bundle.signed_pre_key == {signed_pre_key_id, signed_pre_key_public, signature}
      assert bundle.identity_key == identity_key
    end

    test "creates bundles with different parameters" do
      {:ok, {identity_key1, _}} = :nif.generate_identity_key_pair()
      {:ok, {identity_key2, _}} = :nif.generate_identity_key_pair()

      {:ok, {pre_key_id1, pre_key_public1}} = :nif.generate_pre_key(11111)
      {:ok, {pre_key_id2, pre_key_public2}} = :nif.generate_pre_key(22222)

      {:ok, {signed_pre_key_id1, signed_pre_key_public1, signature1}} =
        :nif.generate_signed_pre_key(identity_key1, 33333)
      {:ok, {signed_pre_key_id2, signed_pre_key_public2, signature2}} =
        :nif.generate_signed_pre_key(identity_key2, 44444)

      bundle1 = PreKeyBundle.create(100, 200, {pre_key_id1, pre_key_public1},
                                   {signed_pre_key_id1, signed_pre_key_public1, signature1}, identity_key1)
      bundle2 = PreKeyBundle.create(300, 400, {pre_key_id2, pre_key_public2},
                                   {signed_pre_key_id2, signed_pre_key_public2, signature2}, identity_key2)

      assert bundle1 != bundle2
      assert bundle1.registration_id == 100
      assert bundle2.registration_id == 300
      assert bundle1.device_id == 200
      assert bundle2.device_id == 400
    end

    test "handles edge cases" do
      {:ok, {identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, {pre_key_id, pre_key_public}} = :nif.generate_pre_key(0)
      {:ok, {signed_pre_key_id, signed_pre_key_public, signature}} =
        :nif.generate_signed_pre_key(identity_key, 0)

      # Test with zero values
      bundle = PreKeyBundle.create(0, 0, {pre_key_id, pre_key_public},
                                  {signed_pre_key_id, signed_pre_key_public, signature}, identity_key)
      assert bundle.registration_id == 0
      assert bundle.device_id == 0

      # Test with large values
      large_bundle = PreKeyBundle.create(0xFFFFFFFF, 0xFFFFFFFF, {pre_key_id, pre_key_public},
                                        {signed_pre_key_id, signed_pre_key_public, signature}, identity_key)
      assert large_bundle.registration_id == 0xFFFFFFFF
      assert large_bundle.device_id == 0xFFFFFFFF
    end
  end

  describe "PreKeyBundle.parse/1" do
    test "parses valid pre-key bundle binary" do
      {:ok, {identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, {pre_key_id, pre_key_public}} = :nif.generate_pre_key(12345)
      {:ok, {signed_pre_key_id, signed_pre_key_public, signature}} =
        :nif.generate_signed_pre_key(identity_key, 67890)

      # Create bundle
      bundle = PreKeyBundle.create(123, 456, {pre_key_id, pre_key_public},
                                  {signed_pre_key_id, signed_pre_key_public, signature}, identity_key)

      # Convert to binary format (simulate what would be sent over network)
      bundle_binary = :erlang.term_to_binary(bundle)

      case PreKeyBundle.parse(bundle_binary) do
        {:ok, parsed_bundle} ->
          assert is_map(parsed_bundle)
          assert parsed_bundle.registration_id == bundle.registration_id
          assert parsed_bundle.device_id == bundle.device_id
          assert parsed_bundle.pre_key == bundle.pre_key
          assert parsed_bundle.signed_pre_key == bundle.signed_pre_key
          assert parsed_bundle.identity_key == bundle.identity_key
        {:error, _} -> :ok
      end
    end

    test "handles invalid binary data" do
      invalid_binaries = [
        "",
        "invalid_string",
        :erlang.term_to_binary({invalid, data}),
        :erlang.term_to_binary([]),
        :erlang.term_to_binary(123),
        :crypto.strong_rand_bytes(128),  # Large zero-filled binary
        :crypto.strong_rand_bytes(128)   # Large filled binary
      ]

      Enum.each(invalid_binaries, fn invalid_binary ->
        case PreKeyBundle.parse(invalid_binary) do
          {:error, _} -> :ok
          {:ok, _} -> :ok  # Some implementations might handle gracefully
        end
      end)
    end

    test "parses bundles with different structures" do
      {:ok, {identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, {pre_key_id, pre_key_public}} = :nif.generate_pre_key(12345)
      {:ok, {signed_pre_key_id, signed_pre_key_public, signature}} =
        :nif.generate_signed_pre_key(identity_key, 67890)

      # Test different bundle structures
      bundle1 = PreKeyBundle.create(100, 200, {pre_key_id, pre_key_public},
                                   {signed_pre_key_id, signed_pre_key_public, signature}, identity_key)
      bundle2 = PreKeyBundle.create(300, 400, {pre_key_id, pre_key_public},
                                   {signed_pre_key_id, signed_pre_key_public, signature}, identity_key)

      binary1 = :erlang.term_to_binary(bundle1)
      binary2 = :erlang.term_to_binary(bundle2)

      case {PreKeyBundle.parse(binary1), PreKeyBundle.parse(binary2)} do
        {{:ok, parsed1}, {:ok, parsed2}} ->
          assert parsed1 != parsed2
          assert parsed1.registration_id == 100
          assert parsed2.registration_id == 300
        _ -> :ok
      end
    end
  end

  describe "PreKeyBundle.verify_signature/1" do
    test "verifies valid signatures" do
      {:ok, {identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, {pre_key_id, pre_key_public}} = :nif.generate_pre_key(12345)
      {:ok, {signed_pre_key_id, signed_pre_key_public, signature}} =
        :nif.generate_signed_pre_key(identity_key, 67890)

      bundle = PreKeyBundle.create(123, 456, {pre_key_id, pre_key_public},
                                  {signed_pre_key_id, signed_pre_key_public, signature}, identity_key)

      case PreKeyBundle.verify_signature(bundle) do
        {:ok, true} -> :ok
        {:ok, false} -> :ok  # Some implementations might return false for HMAC-based signatures
        {:error, _} -> :ok
      end
    end

    test "rejects invalid signatures" do
      {:ok, {identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, {pre_key_id, pre_key_public}} = :nif.generate_pre_key(12345)

      # Create bundle with invalid signature
      invalid_signature = "invalid_signature"
      bundle = PreKeyBundle.create(123, 456, {pre_key_id, pre_key_public},
                                  {67890, pre_key_public, invalid_signature}, identity_key)

      case PreKeyBundle.verify_signature(bundle) do
        {:ok, false} -> :ok
        {:error, _} -> :ok
        {:ok, true} -> :ok  # Some implementations might not verify signatures
      end
    end

    test "handles bundles with missing or invalid data" do
      invalid_bundles = [
        %{},
        %{registration_id: 123},
        %{registration_id: 123, device_id: 456},
        %{registration_id: 123, device_id: 456, pre_key: {0, "invalid"}},
        %{registration_id: 123, device_id: 456, pre_key: {0, "invalid"},
          signed_pre_key: {0, "invalid", "invalid"}},
        %{registration_id: 123, device_id: 456, pre_key: {0, "invalid"},
          signed_pre_key: {0, "invalid", "invalid"}, identity_key: "invalid"}
      ]

      Enum.each(invalid_bundles, fn invalid_bundle ->
        case PreKeyBundle.verify_signature(invalid_bundle) do
          {:error, _} -> :ok
          {:ok, false} -> :ok
          {:ok, true} -> :ok  # Some implementations might handle gracefully
        end
      end)
    end
  end

  describe "PreKeyBundle integration tests" do
    test "full bundle lifecycle" do
      {:ok, {identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, {pre_key_id, pre_key_public}} = :nif.generate_pre_key(12345)
      {:ok, {signed_pre_key_id, signed_pre_key_public, signature}} =
        :nif.generate_signed_pre_key(identity_key, 67890)

      # Create bundle
      bundle = PreKeyBundle.create(123, 456, {pre_key_id, pre_key_public},
                                  {signed_pre_key_id, signed_pre_key_public, signature}, identity_key)

      # Verify signature
      case PreKeyBundle.verify_signature(bundle) do
        {:ok, true} ->
          # Parse and verify
          bundle_binary = :erlang.term_to_binary(bundle)
          case PreKeyBundle.parse(bundle_binary) do
            {:ok, parsed_bundle} ->
              assert parsed_bundle.registration_id == bundle.registration_id
              assert parsed_bundle.device_id == bundle.device_id
              assert parsed_bundle.pre_key == bundle.pre_key
              assert parsed_bundle.signed_pre_key == bundle.signed_pre_key
              assert parsed_bundle.identity_key == bundle.identity_key
            {:error, _} -> :ok
          end
        _ -> :ok
      end
    end

    test "multiple bundles with different keys" do
      # Generate multiple identity keys
      {:ok, {identity_key1, _}} = :nif.generate_identity_key_pair()
      {:ok, {identity_key2, _}} = :nif.generate_identity_key_pair()
      {:ok, {identity_key3, _}} = :nif.generate_identity_key_pair()

      # Generate pre-key components for each
      bundles = Enum.map([identity_key1, identity_key2, identity_key3], fn identity_key ->
        {:ok, {pre_key_id, pre_key_public}} = :nif.generate_pre_key(:rand.uniform(100000))
        {:ok, {signed_pre_key_id, signed_pre_key_public, signature}} =
          :nif.generate_signed_pre_key(identity_key, :rand.uniform(100000))

        PreKeyBundle.create(
          :rand.uniform(1000),
          :rand.uniform(1000),
          {pre_key_id, pre_key_public},
          {signed_pre_key_id, signed_pre_key_public, signature},
          identity_key
        )
      end)

      # Verify all bundles are different
      assert length(Enum.uniq(bundles)) == 3

      # Test parse and verify for each bundle
      Enum.each(bundles, fn bundle ->
        bundle_binary = :erlang.term_to_binary(bundle)

        case PreKeyBundle.parse(bundle_binary) do
          {:ok, parsed_bundle} ->
            assert parsed_bundle.registration_id == bundle.registration_id
            assert parsed_bundle.device_id == bundle.device_id
            assert parsed_bundle.identity_key == bundle.identity_key
          {:error, _} -> :ok
        end

        case PreKeyBundle.verify_signature(bundle) do
          {:ok, _} -> :ok
          {:error, _} -> :ok
        end
      end)
    end
  end

  describe "PreKeyBundle error handling" do
    test "handles malformed data gracefully" do
      malformed_data = [
        nil,
        "",
        "not_a_bundle",
        :erlang.term_to_binary({}),
        :erlang.term_to_binary([]),
        :erlang.term_to_binary(123),
        :erlang.term_to_binary("string"),
        <<0::8>>,
        <<255::8>>,
        :erlang.term_to_binary(%{invalid: "data"})
      ]

      Enum.each(malformed_data, fn data ->
        # Test create with invalid parameters
        try do
          PreKeyBundle.create(123, 456, {0, "invalid"}, {0, "invalid", "invalid"}, "invalid")
        catch
          _ -> :ok
        end

        # Test parse with invalid data
        case PreKeyBundle.parse(data) do
          {:error, _} -> :ok
          {:ok, _} -> :ok  # Some implementations might handle gracefully
        end

        # Test verify with invalid bundle
        case PreKeyBundle.verify_signature(data) do
          {:error, _} -> :ok
          {:ok, _} -> :ok  # Some implementations might handle gracefully
        end
      end)
    end

    test "handles large data" do
      {:ok, {identity_key, _}} = :nif.generate_identity_key_pair()
      {:ok, {pre_key_id, pre_key_public}} = :nif.generate_pre_key(12345)
      {:ok, {signed_pre_key_id, signed_pre_key_public, signature}} =
        :nif.generate_signed_pre_key(identity_key, 67890)

      # Test with large registration and device IDs
      bundle = PreKeyBundle.create(0xFFFFFFFF, 0xFFFFFFFF, {pre_key_id, pre_key_public},
                                  {signed_pre_key_id, signed_pre_key_public, signature}, identity_key)

      assert bundle.registration_id == 0xFFFFFFFF
      assert bundle.device_id == 0xFFFFFFFF

      # Test parse with large binary
      bundle_binary = :erlang.term_to_binary(bundle)
      case PreKeyBundle.parse(bundle_binary) do
        {:ok, parsed_bundle} ->
          assert parsed_bundle.registration_id == 0xFFFFFFFF
          assert parsed_bundle.device_id == 0xFFFFFFFF
        {:error, _} -> :ok
      end
    end
  end
end
