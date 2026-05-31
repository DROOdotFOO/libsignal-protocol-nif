defmodule SignalProtocol.PreKeyBundleTest do
  use ExUnit.Case, async: true
  alias SignalProtocol.PreKeyBundle

  defp make_bundle(opts \\ []) do
    PreKeyBundle.create(
      Keyword.get(opts, :registration_id, 999),
      Keyword.get(opts, :identity_key, :crypto.strong_rand_bytes(32)),
      Keyword.get(opts, :pre_key, {12_345, :crypto.strong_rand_bytes(32)}),
      Keyword.get(opts, :signed_pre_key, {
        67_890,
        :crypto.strong_rand_bytes(32),
        :crypto.strong_rand_bytes(64)
      }),
      Keyword.get(opts, :base_key, :crypto.strong_rand_bytes(32))
    )
  end

  test "create/5 then parse/1 round-trips every field" do
    identity_key = :crypto.strong_rand_bytes(32)
    pre_key = {12_345, :crypto.strong_rand_bytes(32)}
    signed_pre_key =
      {67_890, :crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(64)}
    base_key = :crypto.strong_rand_bytes(32)

    {:ok, binary} =
      make_bundle(
        registration_id: 999,
        identity_key: identity_key,
        pre_key: pre_key,
        signed_pre_key: signed_pre_key,
        base_key: base_key
      )

    {pre_key_id, pre_key_public} = pre_key
    {signed_pre_key_id, signed_pre_key_public, signature} = signed_pre_key

    assert {:ok, parsed} = PreKeyBundle.parse(binary)
    assert parsed.version == 1
    assert parsed.registration_id == 999
    assert parsed.pre_key_id == pre_key_id
    assert parsed.signed_pre_key_id == signed_pre_key_id
    assert parsed.identity_key == identity_key
    assert parsed.pre_key_public == pre_key_public
    assert parsed.signed_pre_key_public == signed_pre_key_public
    assert parsed.signed_pre_key_signature == signature
    assert parsed.base_key == base_key
  end

  test "parse/1 returns {:error, :invalid_bundle} on garbage" do
    assert {:error, :invalid_bundle} = PreKeyBundle.parse(<<>>)
    assert {:error, :invalid_bundle} = PreKeyBundle.parse("not a bundle")
    assert {:error, :invalid_bundle} = PreKeyBundle.parse(:crypto.strong_rand_bytes(64))
  end

  test "verify_signature/1 accepts a bundle whose signature is 64 bytes" do
    {:ok, binary} = make_bundle()
    assert :ok = PreKeyBundle.verify_signature(binary)
  end

  test "verify_signature/1 returns parse error when bundle is malformed" do
    assert {:error, :invalid_bundle} = PreKeyBundle.verify_signature(<<>>)
  end
end
