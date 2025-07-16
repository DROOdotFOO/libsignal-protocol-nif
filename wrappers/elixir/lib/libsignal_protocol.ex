defmodule LibsignalProtocol do
  @moduledoc """
  Elixir wrapper for the Signal Protocol library.
  Provides a clean, idiomatic interface for secure messaging.
  """

  # Suppress warnings for undefined NIF functions during development
  @compile {:no_warn_undefined, {:libsignal_protocol_nif, :init, 0}}
  @compile {:no_warn_undefined, {:libsignal_protocol_nif, :create_session, 1}}
  @compile {:no_warn_undefined, {:libsignal_protocol_nif, :create_session, 2}}
  @compile {:no_warn_undefined, {:libsignal_protocol_nif, :generate_identity_key_pair, 0}}

  # No @on_load - we'll use the existing Erlang NIF module directly

  @doc """
  Initializes the Signal Protocol library.
  Returns `:ok` on success or `{:error, reason}` on failure.
  """
  @spec init() :: :ok | {:error, String.t()}
  def init do
    try do
      # Ensure the NIF module is loaded first
      :code.ensure_loaded(:libsignal_protocol_nif)

      case :libsignal_protocol_nif.init() do
        :ok -> :ok
        {:error, reason} when is_atom(reason) -> {:error, Atom.to_string(reason)}
        {:error, reason} when is_binary(reason) -> {:error, reason}
        {:error, reason} -> {:error, inspect(reason)}
      end
    rescue
      UndefinedFunctionError ->
        {:error, "NIF not loaded - libsignal_protocol_nif.init/0 not found"}
    catch
      :error, :undef ->
        {:error, "NIF not loaded - function undefined"}
    end
  end

  @doc """
  Creates a new session for a recipient using a public key.
  Returns `{:ok, session}` on success or `{:error, reason}` on failure.
  """
  @spec create_session(binary()) :: {:ok, binary()} | {:error, String.t()}
  def create_session(public_key) when is_binary(public_key) do
    try do
      case :libsignal_protocol_nif.create_session(public_key) do
        {:ok, session} -> {:ok, session}
        {:error, reason} when is_atom(reason) -> {:error, Atom.to_string(reason)}
        {:error, reason} when is_binary(reason) -> {:error, reason}
        {:error, reason} -> {:error, inspect(reason)}
      end
    rescue
      UndefinedFunctionError ->
        {:error, "NIF function create_session/1 not found"}
    catch
      :error, :undef ->
        {:error, "NIF function create_session/1 undefined"}
    end
  end

  @doc """
  Creates a new session using local private key and remote public key.
  Returns `{:ok, session}` on success or `{:error, reason}` on failure.
  """
  @spec create_session(binary(), binary()) :: {:ok, binary()} | {:error, String.t()}
  def create_session(local_private_key, remote_public_key)
      when is_binary(local_private_key) and is_binary(remote_public_key) do
    try do
      case :libsignal_protocol_nif.create_session(local_private_key, remote_public_key) do
        {:ok, session} -> {:ok, session}
        {:error, reason} when is_atom(reason) -> {:error, Atom.to_string(reason)}
        {:error, reason} when is_binary(reason) -> {:error, reason}
        {:error, reason} -> {:error, inspect(reason)}
      end
    rescue
      UndefinedFunctionError ->
        {:error, "NIF function create_session/2 not found"}
    catch
      :error, :undef ->
        {:error, "NIF function create_session/2 undefined"}
    end
  end

  @doc """
  Generates a new identity key pair.
  Returns `{:ok, {public_key, signature}}` on success.
  """
  @spec generate_identity_key_pair() :: {:ok, {binary(), binary()}} | {:error, String.t()}
  def generate_identity_key_pair do
    try do
      case :libsignal_protocol_nif.generate_identity_key_pair() do
        {:ok, {public_key, signature}} -> {:ok, {public_key, signature}}
        {:error, reason} when is_atom(reason) -> {:error, Atom.to_string(reason)}
        {:error, reason} when is_binary(reason) -> {:error, reason}
        {:error, reason} -> {:error, inspect(reason)}
      end
    rescue
      UndefinedFunctionError ->
        {:error, "NIF function generate_identity_key_pair/0 not found"}
    catch
      :error, :undef ->
        {:error, "NIF function generate_identity_key_pair/0 undefined"}
    end
  end

  # Simplified API - only include the functions that are most likely to work
  # Other functions can be added once basic functionality is confirmed

  # NIF stubs - these will be replaced by the actual NIF functions
  def load_nif_stub, do: :erlang.nif_error(:nif_not_loaded)
end
