defmodule LibsignalProtocol do
  @moduledoc """
  Elixir wrapper for the Signal Protocol NIF.

  Mirrors the NIF's `{:ok, term} | {:error, atom}` return shape; consistent
  with `SignalProtocol`. A missing NIF raises `UndefinedFunctionError` at
  the call site -- callers must ensure the NIF is built and on the load
  path.
  """

  @nif :libsignal_protocol_nif

  @spec init() :: :ok | {:error, atom()}
  def init do
    :code.ensure_loaded(@nif)
    @nif.init()
  end

  @spec create_session(binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def create_session(local_private_key, remote_public_key)
      when is_binary(local_private_key) and is_binary(remote_public_key) do
    @nif.create_session(local_private_key, remote_public_key)
  end

  @spec generate_identity_key_pair() :: {:ok, {binary(), binary()}} | {:error, atom()}
  def generate_identity_key_pair do
    @nif.generate_identity_key_pair()
  end
end
