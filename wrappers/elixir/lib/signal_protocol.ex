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

  @spec create_session(binary(), binary()) :: {:ok, binary()} | {:error, term()}
  def create_session(local_identity_key, remote_identity_key)
      when is_binary(local_identity_key) and is_binary(remote_identity_key) do
    @nif.create_session(local_identity_key, remote_identity_key)
  end

  @spec process_pre_key_bundle(reference(), binary()) :: :ok | {:error, term()}
  def process_pre_key_bundle(session, bundle) when is_reference(session) and is_binary(bundle) do
    @nif.process_pre_key_bundle(session, bundle)
  end

  @spec encrypt_message(reference(), binary()) :: {:ok, binary()} | {:error, term()}
  def encrypt_message(session, message) when is_reference(session) and is_binary(message) do
    @nif.encrypt_message(session, message)
  end

  @spec decrypt_message(reference(), binary()) :: {:ok, binary()} | {:error, term()}
  def decrypt_message(session, ciphertext) when is_reference(session) and is_binary(ciphertext) do
    @nif.decrypt_message(session, ciphertext)
  end

  # ============================================================================
  # Double Ratchet
  #
  # Per the Signal DR spec: Alice (initiator) sends first using Bob's identity
  # pub; Bob (responder) holds his identity priv and cannot send until Alice's
  # first message arrives. `is_alice` is `1` for the initiator, `0` for the
  # responder. For Alice, `self_identity_priv` is ignored (she uses a fresh
  # ephemeral); for Bob, `remote_identity_pub` is ignored.
  # ============================================================================

  @spec init_double_ratchet(binary(), binary(), binary(), 0 | 1) ::
          {:ok, binary()} | {:error, term()}
  def init_double_ratchet(shared_secret, remote_identity_pub, self_identity_priv, is_alice)
      when is_binary(shared_secret) and is_binary(remote_identity_pub) and
             is_binary(self_identity_priv) and is_alice in [0, 1] do
    @nif.init_double_ratchet(shared_secret, remote_identity_pub, self_identity_priv, is_alice)
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
