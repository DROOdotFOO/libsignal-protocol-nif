defmodule LibsignalProtocol do
  @moduledoc """
  Elixir wrapper for the Signal Protocol NIF.

  Normalizes NIF error terms to strings; otherwise returns NIF results
  unchanged. A missing NIF raises `UndefinedFunctionError` at the call
  site -- callers must ensure the NIF is built and on the load path.
  """

  @nif :libsignal_protocol_nif

  @spec init() :: :ok | {:error, String.t()}
  def init do
    :code.ensure_loaded(@nif)
    @nif.init() |> normalize()
  end

  @spec create_session(binary(), binary()) :: {:ok, binary()} | {:error, String.t()}
  def create_session(local_private_key, remote_public_key)
      when is_binary(local_private_key) and is_binary(remote_public_key) do
    @nif.create_session(local_private_key, remote_public_key) |> normalize()
  end

  @spec generate_identity_key_pair() :: {:ok, {binary(), binary()}} | {:error, String.t()}
  def generate_identity_key_pair do
    @nif.generate_identity_key_pair() |> normalize()
  end

  defp normalize(:ok), do: :ok
  defp normalize({:ok, _} = ok), do: ok
  defp normalize({:error, reason}) when is_binary(reason), do: {:error, reason}
  defp normalize({:error, reason}) when is_atom(reason), do: {:error, Atom.to_string(reason)}
  defp normalize({:error, reason}), do: {:error, inspect(reason)}
end
