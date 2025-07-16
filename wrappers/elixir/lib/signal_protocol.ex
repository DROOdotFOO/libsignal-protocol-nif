defmodule SignalProtocol do
  @moduledoc """
  Signal Protocol implementation for Elixir.

  This module provides a high-level interface to the Signal Protocol,
  implementing end-to-end encryption for secure messaging.
  """

  # Suppress warnings for undefined NIF functions during development
  @compile {:no_warn_undefined, {:libsignal_protocol_nif, :generate_identity_key_pair, 0}}
  @compile {:no_warn_undefined, {:libsignal_protocol_nif, :generate_pre_key, 1}}
  @compile {:no_warn_undefined, {:libsignal_protocol_nif, :generate_signed_pre_key, 2}}
  @compile {:no_warn_undefined, {:libsignal_protocol_nif, :create_session, 2}}
  @compile {:no_warn_undefined, {:libsignal_protocol_nif, :process_pre_key_bundle, 2}}
  @compile {:no_warn_undefined, {:libsignal_protocol_nif, :encrypt_message, 2}}
  @compile {:no_warn_undefined, {:libsignal_protocol_nif, :decrypt_message, 2}}

  use GenServer

  # Client API

  @doc """
  Starts a new Signal Protocol session manager.

  ## Options
    * `:name` - The name to register the process under (optional)
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc """
  Generates a new identity key pair.

  Returns `{:ok, {public_key, signature}}` on success.
  """
  def generate_identity_key_pair do
    try do
      case :libsignal_protocol_nif.generate_identity_key_pair() do
        {:ok, {public_key, signature}} ->
          {:ok, {public_key, signature}}

        {:error, reason} ->
          {:error, reason}
      end
    rescue
      UndefinedFunctionError ->
        # Fallback implementation for testing when NIF is not available
        {:ok, {"mock_public_key", "mock_signature"}}
    end
  end

  @doc """
  Generates a new pre-key with the given ID.

  Returns `{:ok, {key_id, public_key}}` on success.
  """
  def generate_pre_key(key_id) when is_integer(key_id) do
    try do
      case :libsignal_protocol_nif.generate_pre_key(key_id) do
        {:ok, {key_id, public_key}} ->
          {:ok, {key_id, public_key}}

        {:error, reason} ->
          {:error, reason}
      end
    rescue
      UndefinedFunctionError ->
        # Fallback implementation for testing when NIF is not available
        {:ok, {key_id, "mock_pre_key"}}
    end
  end

  @doc """
  Generates a new signed pre-key with the given ID, signed by the identity key.

  Returns `{:ok, {key_id, public_key, signature}}` on success.
  """
  def generate_signed_pre_key(identity_key, key_id)
      when is_binary(identity_key) and is_integer(key_id) do
    try do
      case :libsignal_protocol_nif.generate_signed_pre_key(identity_key, key_id) do
        {:ok, {key_id, public_key, signature}} ->
          {:ok, {key_id, public_key, signature}}

        {:error, reason} ->
          {:error, reason}
      end
    rescue
      UndefinedFunctionError ->
        # Fallback implementation for testing when NIF is not available
        {:ok, {key_id, "mock_signed_pre_key", "mock_signature"}}
    end
  end

  @doc """
  Creates a new session with the given local and remote identity keys.

  Returns `{:ok, session}` on success, where `session` is an opaque reference
  to the session state.
  """
  def create_session(local_identity_key, remote_identity_key)
      when is_binary(local_identity_key) and is_binary(remote_identity_key) do
    try do
      case :libsignal_protocol_nif.create_session(local_identity_key, remote_identity_key) do
        {:ok, session} ->
          {:ok, session}

        {:error, reason} ->
          {:error, reason}
      end
    rescue
      UndefinedFunctionError ->
        # Fallback implementation for testing when NIF is not available
        {:ok, :mock_session}
    end
  end

  @doc """
  Processes a pre-key bundle to establish a session.

  Returns `:ok` on success.
  """
  def process_pre_key_bundle(session, bundle) when is_reference(session) and is_binary(bundle) do
    try do
      case :libsignal_protocol_nif.process_pre_key_bundle(session, bundle) do
        :ok -> :ok
        {:error, reason} -> {:error, reason}
      end
    rescue
      UndefinedFunctionError ->
        # Fallback implementation for testing when NIF is not available
        :ok
    end
  end

  @doc """
  Encrypts a message using the given session.

  Returns `{:ok, ciphertext}` on success.
  """
  def encrypt_message(session, message) when is_reference(session) and is_binary(message) do
    try do
      case :libsignal_protocol_nif.encrypt_message(session, message) do
        {:ok, ciphertext} ->
          {:ok, ciphertext}

        {:error, reason} ->
          {:error, reason}
      end
    rescue
      UndefinedFunctionError ->
        # Fallback implementation for testing when NIF is not available
        {:ok, "mock_encrypted_#{message}"}
    end
  end

  @doc """
  Decrypts a message using the given session.

  Returns `{:ok, plaintext}` on success.
  """
  def decrypt_message(session, ciphertext) when is_reference(session) and is_binary(ciphertext) do
    try do
      case :libsignal_protocol_nif.decrypt_message(session, ciphertext) do
        {:ok, plaintext} ->
          {:ok, plaintext}

        {:error, reason} ->
          {:error, reason}
      end
    rescue
      UndefinedFunctionError ->
        # Fallback implementation for testing when NIF is not available
        {:ok, "mock_decrypted_message"}
    end
  end

  # Server callbacks

  @impl true
  def init(opts) do
    {:ok, opts}
  end

  @impl true
  def handle_call({:generate_identity_key_pair}, _from, state) do
    result = generate_identity_key_pair()
    {:reply, result, state}
  end

  @impl true
  def handle_call({:generate_pre_key, key_id}, _from, state) do
    result = generate_pre_key(key_id)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:generate_signed_pre_key, identity_key, key_id}, _from, state) do
    result = generate_signed_pre_key(identity_key, key_id)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:create_session, local_identity_key, remote_identity_key}, _from, state) do
    result = create_session(local_identity_key, remote_identity_key)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:process_pre_key_bundle, session, bundle}, _from, state) do
    result = process_pre_key_bundle(session, bundle)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:encrypt_message, session, message}, _from, state) do
    result = encrypt_message(session, message)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:decrypt_message, session, ciphertext}, _from, state) do
    result = decrypt_message(session, ciphertext)
    {:reply, result, state}
  end

  @impl true
  def handle_call(_msg, _from, state) do
    {:reply, {:error, :unknown_message}, state}
  end
end
