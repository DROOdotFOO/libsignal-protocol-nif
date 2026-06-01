defmodule SignalProtocol do
  @moduledoc """
  Thin Elixir facade over the `:libsignal_protocol_nif` Erlang NIF.

  All functions return `{:ok, term} | {:error, term}` as the NIF does. A
  missing NIF raises `UndefinedFunctionError` at the call site -- callers
  must ensure the NIF is built and on the load path before use.
  """

  @nif :libsignal_protocol_nif

  @spec generate_identity_key_pair() :: {:ok, {binary(), binary()}} | {:error, term()}
  def generate_identity_key_pair, do: @nif.generate_identity_key_pair()

  @spec generate_pre_key(non_neg_integer()) :: {:ok, {non_neg_integer(), binary()}} | {:error, term()}
  def generate_pre_key(key_id) when is_integer(key_id), do: @nif.generate_pre_key(key_id)

  @spec generate_signed_pre_key(binary(), non_neg_integer()) ::
          {:ok, {non_neg_integer(), binary(), binary()}} | {:error, term()}
  def generate_signed_pre_key(identity_key, key_id)
      when is_binary(identity_key) and is_integer(key_id) do
    @nif.generate_signed_pre_key(identity_key, key_id)
  end

  @doc """
  Performs X3DH key agreement against a remote pre-key bundle.

  The bundle is a binary in the format expected by the C NIF:
  `remote_identity_pub(32) ++ signed_prekey_pub(32) ++ signature(32)`
  with an optional trailing `one_time_prekey(32)`. The signature is
  `HMAC-SHA256(signed_prekey_pub, key=remote_identity_pub)`.

  Returns `{:ok, {shared_secret(64), ephemeral_pub(32)}}` on success. The
  shared secret is suitable to feed into `init_double_ratchet/5` as the
  Double Ratchet root seed.
  """
  @spec process_pre_key_bundle(binary(), binary()) ::
          {:ok, {binary(), binary()}} | {:error, term()}
  def process_pre_key_bundle(local_identity_priv, bundle)
      when is_binary(local_identity_priv) and is_binary(bundle) do
    @nif.process_pre_key_bundle(local_identity_priv, bundle)
  end

  # ============================================================================
  # Double Ratchet
  #
  # Per the Signal DR spec: Alice (initiator) sends first using Bob's identity
  # pub; Bob (responder) holds his identity priv and cannot send until Alice's
  # first message arrives. `is_alice` is `1` for the initiator, `0` for the
  # responder. `local_identity_pub` and `remote_identity_pub` are stored in DR
  # state and folded into every message MAC (Signal-spec scope). For Alice,
  # `self_identity_priv` may be `<<>>` (she uses a fresh ephemeral for DH).
  # ============================================================================

  @spec init_double_ratchet(binary(), binary(), binary(), binary(), 0 | 1) ::
          {:ok, binary()} | {:error, term()}
  def init_double_ratchet(
        shared_secret,
        local_identity_pub,
        remote_identity_pub,
        self_identity_priv,
        is_alice
      )
      when is_binary(shared_secret) and is_binary(local_identity_pub) and
             is_binary(remote_identity_pub) and is_binary(self_identity_priv) and
             is_alice in [0, 1] do
    @nif.init_double_ratchet(
      shared_secret,
      local_identity_pub,
      remote_identity_pub,
      self_identity_priv,
      is_alice
    )
  end

  @spec dr_encrypt_message(binary(), binary()) ::
          {:ok, {binary(), binary()}} | {:error, term()}
  def dr_encrypt_message(dr_session, message)
      when is_binary(dr_session) and is_binary(message) do
    @nif.dr_encrypt_message(dr_session, message)
  end

  @spec dr_decrypt_message(binary(), binary()) ::
          {:ok, {binary(), binary()}} | {:error, term()}
  def dr_decrypt_message(dr_session, ciphertext)
      when is_binary(dr_session) and is_binary(ciphertext) do
    @nif.dr_decrypt_message(dr_session, ciphertext)
  end
end
