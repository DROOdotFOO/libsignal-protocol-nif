import signal_protocol.{type PreKeyBundle, type Session, Session}

// --- FFI: libsignal_protocol_nif integration ---
@external(erlang, "libsignal_protocol_nif", "create_session")
fn call_nif_create_session(
  local_key: BitArray,
  remote_key: BitArray,
) -> Result(BitArray, String)

@external(erlang, "libsignal_protocol_nif", "process_pre_key_bundle")
fn call_nif_process_bundle(
  session_ref: BitArray,
  bundle: BitArray,
) -> Result(Nil, String)

@external(erlang, "libsignal_protocol_nif", "encrypt_message")
fn call_nif_encrypt(
  session_ref: BitArray,
  message: BitArray,
) -> Result(BitArray, String)

@external(erlang, "libsignal_protocol_nif", "decrypt_message")
fn call_nif_decrypt(
  session_ref: BitArray,
  ciphertext: BitArray,
) -> Result(BitArray, String)

/// Creates a new session with the given local and remote identity keys.
pub fn create(
  local_identity_key: BitArray,
  remote_identity_key: BitArray,
) -> Result(Session, String) {
  case call_nif_create_session(local_identity_key, remote_identity_key) {
    Ok(reference) -> Ok(Session(reference))
    Error(reason) -> Error(reason)
  }
}

/// Processes a pre-key bundle to establish a session.
pub fn process_pre_key_bundle(
  session: Session,
  bundle: PreKeyBundle,
) -> Result(Nil, String) {
  let bundle_binary = create_bundle_binary(bundle)
  case call_nif_process_bundle(session_reference(session), bundle_binary) {
    Ok(Nil) -> Ok(Nil)
    Error(reason) -> Error(reason)
  }
}

/// Encrypts a message using the given session.
pub fn encrypt_message(
  session: Session,
  message: BitArray,
) -> Result(BitArray, String) {
  call_nif_encrypt(session_reference(session), message)
}

/// Decrypts a message using the given session.
pub fn decrypt_message(
  session: Session,
  ciphertext: BitArray,
) -> Result(BitArray, String) {
  call_nif_decrypt(session_reference(session), ciphertext)
}

/// Creates a new session and processes a pre-key bundle in one step.
pub fn create_and_process_bundle(
  local_identity_key: BitArray,
  remote_identity_key: BitArray,
  bundle: PreKeyBundle,
) -> Result(Session, String) {
  let session = create(local_identity_key, remote_identity_key)
  case session {
    Ok(session) -> {
      case process_pre_key_bundle(session, bundle) {
        Ok(Nil) -> Ok(session)
        Error(e) -> Error(e)
      }
    }
    Error(e) -> Error(e)
  }
}

/// Sends a message through a session, handling encryption.
pub fn send_message(session: Session, message: BitArray) -> Result(BitArray, String) {
  encrypt_message(session, message)
}

/// Receives a message through a session, handling decryption.
pub fn receive_message(
  session: Session,
  ciphertext: BitArray,
) -> Result(BitArray, String) {
  decrypt_message(session, ciphertext)
}

// Helper function to extract the reference from a Session
fn session_reference(session: Session) -> BitArray {
  case session {
    Session(reference) -> reference
  }
}

// Serialize a pre-key bundle to the format expected by the C NIF's
// process_pre_key_bundle: identity_key(32) ++ signed_prekey_public(32) ++
// signature(32) ++ one_time_prekey(32).
fn create_bundle_binary(bundle: PreKeyBundle) -> BitArray {
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
