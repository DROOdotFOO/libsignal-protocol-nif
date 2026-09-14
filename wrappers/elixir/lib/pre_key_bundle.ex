defmodule SignalProtocol.PreKeyBundle do
  @moduledoc """
  Serialization for the pre-key bundle a party publishes so others can start
  sessions with them asynchronously.

  The wire form is exactly what the NIF's `process_pre_key_bundle/2` consumes:

      identity_pub(32) || signed_pre_key_pub(32) || signature(64) [|| one_time_pre_key_pub(32)]

  128 bytes, or 160 with a one-time pre-key. `signature` is Ed25519 over
  `signed_pre_key_pub` under the identity key -- produced by
  `SignalProtocol.generate_signed_pre_key/2`.

  Key ids and the registration id are *not* part of this binary: they travel
  in the PreKeySignalMessage of the first message, where the responder needs
  them to look up which private keys to use.
  """

  @key 32
  @sig 64

  @type t :: %__MODULE__{
          identity_key: binary(),
          signed_pre_key: binary(),
          signature: binary(),
          one_time_pre_key: binary() | nil
        }

  defstruct [:identity_key, :signed_pre_key, :signature, one_time_pre_key: nil]

  @doc """
  Serializes a bundle to the NIF wire form.

  Returns `{:error, :invalid_key_size}` if any component is the wrong length,
  rather than emitting a binary the NIF would reject with
  `:invalid_bundle_size` or a signature failure.
  """
  @spec encode(t()) :: {:ok, binary()} | {:error, :invalid_key_size}
  def encode(%__MODULE__{
        identity_key: id_key,
        signed_pre_key: spk,
        signature: sig,
        one_time_pre_key: opk
      })
      when byte_size(id_key) == @key and byte_size(spk) == @key and
             byte_size(sig) == @sig and (is_nil(opk) or byte_size(opk) == @key) do
    {:ok, <<id_key::binary, spk::binary, sig::binary, opk_bytes(opk)::binary>>}
  end

  def encode(%__MODULE__{}), do: {:error, :invalid_key_size}

  @doc """
  Parses a bundle from its wire form. Accepts exactly 128 or 160 bytes.
  """
  @spec decode(binary()) :: {:ok, t()} | {:error, :invalid_bundle_size}
  def decode(<<id_key::binary-size(@key), spk::binary-size(@key), sig::binary-size(@sig)>>) do
    {:ok, %__MODULE__{identity_key: id_key, signed_pre_key: spk, signature: sig}}
  end

  def decode(<<id_key::binary-size(@key), spk::binary-size(@key), sig::binary-size(@sig),
               opk::binary-size(@key)>>) do
    {:ok,
     %__MODULE__{
       identity_key: id_key,
       signed_pre_key: spk,
       signature: sig,
       one_time_pre_key: opk
     }}
  end

  def decode(bundle) when is_binary(bundle), do: {:error, :invalid_bundle_size}

  @doc """
  Verifies the bundle's Ed25519 signature over its signed pre-key, under the
  identity key the bundle itself carries. Returns `:ok` or the bare atom
  `:invalid_signature`, mirroring `signal_nif:verify_signature/3`.

  This is the same check `process_pre_key_bundle/2` performs, exposed for
  callers who want to validate a bundle before using it. It proves internal
  consistency only: trust in `identity_key` has to come from out-of-band
  identity verification.
  """
  @spec verify_signature(t()) :: :ok | :invalid_signature | {:error, atom()}
  def verify_signature(%__MODULE__{
        identity_key: id_key,
        signed_pre_key: spk,
        signature: sig
      }) do
    :signal_nif.verify_signature(id_key, spk, sig)
  end

  defp opk_bytes(nil), do: <<>>
  defp opk_bytes(opk), do: opk
end
