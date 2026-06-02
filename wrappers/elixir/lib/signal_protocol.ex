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

  @doc """
  Bob's side of X3DH. Recovers the same 96-byte shared secret Alice derived
  via `process_pre_key_bundle/2` (64B X3DH SK || 32B shared header-key seed
  for DR-HE).

  Inputs:
    * `identity_priv` - Bob's 64-byte Ed25519 identity private key.
    * `signed_pre_key_priv` - 32-byte X25519 private key matching the SPK
      Alice consumed from Bob's bundle.
    * `one_time_pre_key_priv` - 32-byte X25519 private key matching the OPK
      Alice consumed, or `<<>>` if no OPK was used.
    * `remote_identity_pub` - Alice's 32-byte Ed25519 identity public key,
      extracted from the PreKeySignalMessage.
    * `remote_ephemeral_pub` - Alice's 32-byte X25519 ephemeral public key,
      also extracted from the PreKeySignalMessage (the `base_key` field).
  """
  @spec process_pre_key_bundle_bob(binary(), binary(), binary(), binary(), binary()) ::
          {:ok, binary()} | {:error, term()}
  def process_pre_key_bundle_bob(
        identity_priv,
        signed_pre_key_priv,
        one_time_pre_key_priv,
        remote_identity_pub,
        remote_ephemeral_pub
      )
      when is_binary(identity_priv) and is_binary(signed_pre_key_priv) and
             is_binary(one_time_pre_key_priv) and is_binary(remote_identity_pub) and
             is_binary(remote_ephemeral_pub) do
    @nif.process_pre_key_bundle_bob(
      identity_priv,
      signed_pre_key_priv,
      one_time_pre_key_priv,
      remote_identity_pub,
      remote_ephemeral_pub
    )
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
    @nif.dr_init(
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
    @nif.dr_encrypt(dr_session, message)
  end

  @spec dr_decrypt_message(binary(), binary()) ::
          {:ok, {binary(), binary()}} | {:error, term()}
  def dr_decrypt_message(dr_session, ciphertext)
      when is_binary(dr_session) and is_binary(ciphertext) do
    @nif.dr_decrypt(dr_session, ciphertext)
  end

  @doc """
  Encrypt Alice's first message and wrap it in a PreKeySignalMessage envelope
  so Bob can recover the X3DH shared secret before decrypting.

  `pre_key_info` is a 4-tuple `{registration_id, one_time_pre_key_id_or_nil,
  signed_pre_key_id, alice_x3dh_ephemeral_pub}`. The ephemeral pub is the
  32-byte X25519 key returned by `process_pre_key_bundle/2`.

  Returns `{:ok, {pksm_wire_bytes, new_session}}` on success.
  """
  @spec dr_encrypt_prekey(binary(), binary(),
          {non_neg_integer(), non_neg_integer() | nil, non_neg_integer(), binary()}) ::
          {:ok, {binary(), binary()}} | {:error, term()}
  def dr_encrypt_prekey(dr_session, message,
        {registration_id, opk_id, spk_id, alice_ephemeral_pub} = _pre_key_info)
      when is_binary(dr_session) and is_binary(message) and
             is_integer(registration_id) and (is_nil(opk_id) or is_integer(opk_id)) and
             is_integer(spk_id) and is_binary(alice_ephemeral_pub) do
    opk_term = if opk_id == nil, do: :undefined, else: opk_id
    @nif.dr_encrypt_prekey(dr_session, message,
                           {registration_id, opk_term, spk_id, alice_ephemeral_pub})
  end

  @doc """
  Decode a PreKeySignalMessage wire envelope produced by `dr_encrypt_prekey/3`.

  Returns
    `{:ok, {registration_id, base_key, identity_key, one_time_pre_key_id_or_nil,
            signed_pre_key_id, inner_dr_message}}`
  on success, or `{:error, :malformed_message}` on malformed input.

  Bob's typical flow:
    1. `pksm_decode/1` to extract fields and the inner DR message.
    2. Look up his SPK + OPK private keys by id.
    3. `process_pre_key_bundle_bob/5` to derive the same SK Alice has.
    4. `init_double_ratchet/5` (as Bob, `is_alice = 0`).
    5. `dr_decrypt_message/2` on the inner DR message.
  """
  @spec pksm_decode(binary()) ::
          {:ok, {non_neg_integer(), binary(), binary(),
                 non_neg_integer() | nil, non_neg_integer(), binary()}}
          | {:error, term()}
  def pksm_decode(wire) when is_binary(wire) do
    case @nif.pksm_decode(wire) do
      {:ok, {reg, base, id, :undefined, spk, msg}} ->
        {:ok, {reg, base, id, nil, spk, msg}}

      other ->
        other
    end
  end
end
