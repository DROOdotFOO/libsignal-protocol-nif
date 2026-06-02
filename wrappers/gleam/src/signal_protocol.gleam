import gleam/option.{type Option}
import gleam/result

/// Pre-key bundle: the public material a remote party publishes so others
/// can initiate sessions with them asynchronously.
pub type PreKeyBundle {
  PreKeyBundle(
    registration_id: Int,
    identity_key: BitArray,
    pre_key: #(Int, BitArray),
    signed_pre_key: #(Int, BitArray, BitArray),
    base_key: BitArray,
  )
}

/// Identity key pair (Ed25519). `public_key` is 32 bytes; `private_key` is
/// 64 bytes (libsodium's secret-key encoding: seed ++ derived pub).
pub type IdentityKeyPair {
  IdentityKeyPair(public_key: BitArray, private_key: BitArray)
}

/// One-time pre-key.
pub type PreKey {
  PreKey(key_id: Int, public_key: BitArray)
}

/// Signed pre-key with HMAC-SHA512-256 signature over the public key.
pub type SignedPreKey {
  SignedPreKey(key_id: Int, public_key: BitArray, signature: BitArray)
}

/// Opaque Double Ratchet session state (~2.6 KB).
pub type DrSession {
  DrSession(state: BitArray)
}

/// Whether this party initiates (Alice) or responds (Bob) in the DR handshake.
pub type DrRole {
  Alice
  Bob
}

// --- FFI: libsignal_protocol_nif integration ---
@external(erlang, "libsignal_protocol_nif", "generate_identity_key_pair")
fn call_nif_generate_identity_key_pair() -> Result(#(BitArray, BitArray), String)

@external(erlang, "libsignal_protocol_nif", "generate_pre_key")
fn call_nif_generate_pre_key(key_id: Int) -> Result(#(Int, BitArray), String)

@external(erlang, "libsignal_protocol_nif", "generate_signed_pre_key")
fn call_nif_generate_signed_pre_key(
  identity_key: BitArray,
  key_id: Int,
) -> Result(#(Int, BitArray, BitArray), String)

@external(erlang, "libsignal_protocol_nif", "process_pre_key_bundle")
fn call_nif_process_pre_key_bundle(
  local_identity_priv: BitArray,
  bundle: BitArray,
) -> Result(#(BitArray, BitArray), String)

@external(erlang, "libsignal_protocol_nif", "dr_init")
fn call_nif_init_double_ratchet(
  shared_secret: BitArray,
  local_identity_pub: BitArray,
  remote_identity_pub: BitArray,
  self_identity_priv: BitArray,
  is_alice: Int,
) -> Result(BitArray, String)

@external(erlang, "libsignal_protocol_nif", "dr_encrypt")
fn call_nif_dr_encrypt(
  dr_session: BitArray,
  message: BitArray,
) -> Result(#(BitArray, BitArray), String)

@external(erlang, "libsignal_protocol_nif", "dr_decrypt")
fn call_nif_dr_decrypt(
  dr_session: BitArray,
  ciphertext: BitArray,
) -> Result(#(BitArray, BitArray), String)

@external(erlang, "libsignal_protocol_gleam_ffi", "process_pre_key_bundle_bob")
fn call_nif_process_pre_key_bundle_bob(
  identity_priv: BitArray,
  signed_pre_key_priv: BitArray,
  one_time_pre_key_priv: BitArray,
  remote_identity_pub: BitArray,
  remote_ephemeral_pub: BitArray,
) -> Result(BitArray, String)

@external(erlang, "libsignal_protocol_gleam_ffi", "dr_encrypt_prekey")
fn call_nif_dr_encrypt_prekey(
  dr_session: BitArray,
  message: BitArray,
  pre_key_info: #(Int, Option(Int), Int, BitArray),
) -> Result(#(BitArray, BitArray), String)

@external(erlang, "libsignal_protocol_gleam_ffi", "pksm_decode")
fn call_nif_pksm_decode(
  wire: BitArray,
) -> Result(
  #(Int, BitArray, BitArray, Option(Int), Int, BitArray),
  String,
)

// --- Key generation ---

/// Generates a new identity key pair.
pub fn generate_identity_key_pair() -> Result(IdentityKeyPair, String) {
  call_nif_generate_identity_key_pair()
  |> result.map(fn(pair) {
    let #(public_key, signature) = pair
    IdentityKeyPair(public_key, signature)
  })
}

/// Generates a new pre-key with the given ID.
pub fn generate_pre_key(key_id: Int) -> Result(PreKey, String) {
  call_nif_generate_pre_key(key_id)
  |> result.map(fn(pair) {
    let #(id, public_key) = pair
    PreKey(id, public_key)
  })
}

/// Generates a new signed pre-key with the given ID, signed by the identity key.
pub fn generate_signed_pre_key(
  identity_key: BitArray,
  key_id: Int,
) -> Result(SignedPreKey, String) {
  call_nif_generate_signed_pre_key(identity_key, key_id)
  |> result.map(fn(triple) {
    let #(id, public_key, signature) = triple
    SignedPreKey(id, public_key, signature)
  })
}

// --- X3DH ---

/// Performs X3DH key agreement against a remote pre-key bundle.
///
/// Returns `#(shared_secret, ephemeral_pub)` where the 96-byte shared secret
/// (64B X3DH SK || 32B DR-HE shared header-key seed) is suitable to feed
/// into `init_double_ratchet` as the DR root seed.
pub fn process_pre_key_bundle(
  local_identity_priv: BitArray,
  bundle: PreKeyBundle,
) -> Result(#(BitArray, BitArray), String) {
  call_nif_process_pre_key_bundle(local_identity_priv, encode_bundle(bundle))
}

// Serialize a pre-key bundle to the format the C NIF expects:
//   remote_identity_pub(32) ++ signed_prekey_pub(32) ++ signature(32)
// followed optionally by a 32-byte one-time prekey.
fn encode_bundle(bundle: PreKeyBundle) -> BitArray {
  let #(_pre_key_id, pre_key_public) = bundle.pre_key
  let #(_signed_pre_key_id, signed_pre_key_public, signed_pre_key_signature) =
    bundle.signed_pre_key
  <<
    bundle.identity_key:bits,
    signed_pre_key_public:bits,
    signed_pre_key_signature:bits,
    pre_key_public:bits,
  >>
}

// --- Double Ratchet ---

/// Initialize a Double Ratchet session.
///
/// `shared_secret` must be 96 bytes (typically the X3DH output).
/// `local_identity_pub` and `remote_identity_pub` are 32-byte Ed25519 pubs;
/// both are stored in DR state and folded into every message MAC (Signal
/// spec: HMAC scope is `sender_id || receiver_id || version || message`).
///
/// - Alice: `self_identity_priv` may be empty (she uses a fresh ephemeral
///   for DH).
/// - Bob: `self_identity_priv` is his 64-byte Ed25519 secret, used as the
///   initial DH ratchet pair. Bob's encrypt fails until he receives Alice's
///   first message.
pub fn init_double_ratchet(
  shared_secret: BitArray,
  local_identity_pub: BitArray,
  remote_identity_pub: BitArray,
  self_identity_priv: BitArray,
  role: DrRole,
) -> Result(DrSession, String) {
  let is_alice = case role {
    Alice -> 1
    Bob -> 0
  }
  call_nif_init_double_ratchet(
    shared_secret,
    local_identity_pub,
    remote_identity_pub,
    self_identity_priv,
    is_alice,
  )
  |> result.map(DrSession)
}

/// Encrypt a message under the Double Ratchet. Returns the ciphertext and the
/// advanced session state.
pub fn dr_encrypt_message(
  session: DrSession,
  message: BitArray,
) -> Result(#(BitArray, DrSession), String) {
  let DrSession(state) = session
  call_nif_dr_encrypt(state, message)
  |> result.map(fn(pair) {
    let #(ct, next) = pair
    #(ct, DrSession(next))
  })
}

/// Decrypt a Double Ratchet ciphertext. Returns the plaintext and the
/// advanced session state.
pub fn dr_decrypt_message(
  session: DrSession,
  ciphertext: BitArray,
) -> Result(#(BitArray, DrSession), String) {
  let DrSession(state) = session
  call_nif_dr_decrypt(state, ciphertext)
  |> result.map(fn(pair) {
    let #(pt, next) = pair
    #(pt, DrSession(next))
  })
}

// --- PreKeySignalMessage (Alice's first message envelope) ---

/// Information Alice must include in her first PreKeySignalMessage so Bob
/// can identify which of his prekeys to consume and recover the X3DH
/// shared secret.
pub type PreKeyInfo {
  PreKeyInfo(
    registration_id: Int,
    one_time_pre_key_id: Option(Int),
    signed_pre_key_id: Int,
    alice_ephemeral_pub: BitArray,
  )
}

/// A parsed PreKeySignalMessage. `inner_message` is the serialized inner
/// SignalMessage and is fed to `dr_decrypt_message` after the recipient
/// has initialized their Double Ratchet from the recovered X3DH secret.
pub type PksmMessage {
  PksmMessage(
    registration_id: Int,
    base_key: BitArray,
    identity_key: BitArray,
    one_time_pre_key_id: Option(Int),
    signed_pre_key_id: Int,
    inner_message: BitArray,
  )
}

/// Bob's side of X3DH. Returns the same 96-byte shared secret Alice
/// derives from `process_pre_key_bundle` (64B X3DH SK || 32B DR-HE shared
/// header-key seed).
///
/// Pass an empty `BitArray` for `one_time_pre_key_priv` when no OPK is
/// being used.
pub fn process_pre_key_bundle_bob(
  identity_priv: BitArray,
  signed_pre_key_priv: BitArray,
  one_time_pre_key_priv: BitArray,
  remote_identity_pub: BitArray,
  remote_ephemeral_pub: BitArray,
) -> Result(BitArray, String) {
  call_nif_process_pre_key_bundle_bob(
    identity_priv,
    signed_pre_key_priv,
    one_time_pre_key_priv,
    remote_identity_pub,
    remote_ephemeral_pub,
  )
}

/// Encrypt Alice's first message and wrap it in a PreKeySignalMessage so
/// Bob can recover the X3DH shared secret before decrypting.
pub fn dr_encrypt_prekey(
  session: DrSession,
  message: BitArray,
  info: PreKeyInfo,
) -> Result(#(BitArray, DrSession), String) {
  let DrSession(state) = session
  let PreKeyInfo(reg_id, opk_id, spk_id, eph_pub) = info
  call_nif_dr_encrypt_prekey(
    state,
    message,
    #(reg_id, opk_id, spk_id, eph_pub),
  )
  |> result.map(fn(pair) {
    let #(wire, next) = pair
    #(wire, DrSession(next))
  })
}

/// Decode a PreKeySignalMessage wire envelope.
pub fn pksm_decode(wire: BitArray) -> Result(PksmMessage, String) {
  call_nif_pksm_decode(wire)
  |> result.map(fn(t) {
    let #(reg, base, id, opk, spk, msg) = t
    PksmMessage(reg, base, id, opk, spk, msg)
  })
}
