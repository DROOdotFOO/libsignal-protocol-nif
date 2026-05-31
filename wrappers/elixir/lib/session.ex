defmodule SignalProtocol.Session do
  @moduledoc """
  Handles Signal Protocol sessions for secure messaging.

  This module provides a high-level interface for managing Signal Protocol
  sessions, including session creation, message encryption, and decryption.
  """

  @doc """
  Creates a new session with the given local and remote identity keys.

  ## Parameters
    * `local_identity_key` - The local user's identity key
    * `remote_identity_key` - The remote user's identity key

  Returns `{:ok, session}` on success, where `session` is a reference to
  the session state.
  """
  def create(local_identity_key, remote_identity_key)
      when is_binary(local_identity_key) and is_binary(remote_identity_key) do
    SignalProtocol.create_session(local_identity_key, remote_identity_key)
  end

  @doc """
  Processes a pre-key bundle to establish a session.

  ## Parameters
    * `session` - The session reference
    * `bundle` - The pre-key bundle to process

  Returns `:ok` on success.
  """
  def process_pre_key_bundle(session, bundle)
      when is_reference(session) and is_binary(bundle) do
    SignalProtocol.process_pre_key_bundle(session, bundle)
  end

  @doc """
  Encrypts a message using the given session.

  ## Parameters
    * `session` - The session reference
    * `message` - The message to encrypt

  Returns `{:ok, ciphertext}` on success.
  """
  def encrypt_message(session, message)
      when is_reference(session) and is_binary(message) do
    SignalProtocol.encrypt_message(session, message)
  end

  @doc """
  Decrypts a message using the given session.

  ## Parameters
    * `session` - The session reference
    * `ciphertext` - The encrypted message to decrypt

  Returns `{:ok, plaintext}` on success.
  """
  def decrypt_message(session, ciphertext)
      when is_reference(session) and is_binary(ciphertext) do
    SignalProtocol.decrypt_message(session, ciphertext)
  end

  @doc """
  Creates a new session and processes a pre-key bundle in one step.

  ## Parameters
    * `local_identity_key` - The local user's identity key
    * `remote_identity_key` - The remote user's identity key
    * `bundle` - The pre-key bundle to process

  Returns `{:ok, session}` on success.
  """
  def create_and_process_bundle(local_identity_key, remote_identity_key, bundle)
      when is_binary(local_identity_key) and
             is_binary(remote_identity_key) and
             is_binary(bundle) do
    with {:ok, session} <- create(local_identity_key, remote_identity_key),
         :ok <- process_pre_key_bundle(session, bundle) do
      {:ok, session}
    end
  end

  @doc """
  Sends a message through a session, handling encryption.

  ## Parameters
    * `session` - The session reference
    * `message` - The message to send

  Returns `{:ok, ciphertext}` on success.
  """
  def send_message(session, message)
      when is_reference(session) and is_binary(message) do
    encrypt_message(session, message)
  end

  @doc """
  Receives a message through a session, handling decryption.

  ## Parameters
    * `session` - The session reference
    * `ciphertext` - The encrypted message to receive

  Returns `{:ok, plaintext}` on success.
  """
  def receive_message(session, ciphertext)
      when is_reference(session) and is_binary(ciphertext) do
    decrypt_message(session, ciphertext)
  end
end
