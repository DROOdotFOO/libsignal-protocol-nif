defmodule LibsignalProtocol do
  @moduledoc """
  Elixir wrapper for the Signal Protocol NIF.

  Mirrors the NIF's `{:ok, term} | {:error, atom}` return shape; consistent
  with `SignalProtocol`. A missing NIF raises `UndefinedFunctionError` at
  the call site -- callers must ensure the NIF is built and on the load
  path.
  """

  @nif :libsignal_protocol_nif

  @spec init() :: :ok
  def init do
    :code.ensure_loaded(@nif)
    @nif.init()
  end

  @spec generate_identity_key_pair() :: {:ok, {binary(), binary()}} | {:error, atom()}
  def generate_identity_key_pair do
    @nif.generate_identity_key_pair()
  end
end
