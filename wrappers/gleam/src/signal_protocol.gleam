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

/// Identity key pair (Curve25519): public key + signature material.
pub type IdentityKeyPair {
  IdentityKeyPair(public_key: BitArray, signature: BitArray)
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

@external(erlang, "libsignal_protocol_nif", "init_double_ratchet")
fn call_nif_init_double_ratchet(
  shared_secret: BitArray,
  remote_identity_pub: BitArray,
  self_identity_priv: BitArray,
  is_alice: Int,
) -> Result(BitArray, String)

@external(erlang, "libsignal_protocol_nif", "dr_encrypt_message")
fn call_nif_dr_encrypt(
  dr_session: BitArray,
  message: BitArray,
) -> Result(#(BitArray, BitArray), String)

@external(erlang, "libsignal_protocol_nif", "dr_decrypt_message")
fn call_nif_dr_decrypt(
  dr_session: BitArray,
  ciphertext: BitArray,
) -> Result(#(BitArray, BitArray), String)

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
/// Returns `#(shared_secret, ephemeral_pub)` where the 64-byte shared secret
/// is suitable to feed into `init_double_ratchet` as the DR root seed.
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
/// `shared_secret` must be 64 bytes (typically the X3DH output).
///
/// - Alice: `remote_identity_pub` is Bob's 32-byte identity pub;
///   `self_identity_priv` is ignored (she uses a fresh ephemeral).
/// - Bob: `remote_identity_pub` is ignored; `self_identity_priv` is his
///   32-byte identity priv. Bob's encrypt fails until he receives Alice's
///   first message.
pub fn init_double_ratchet(
  shared_secret: BitArray,
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
