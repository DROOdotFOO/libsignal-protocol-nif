import pre_key_bundle
import signal_protocol.{
  type IdentityKeyPair, type PreKey, type PreKeyBundle, type SignedPreKey,
}

/// Generates a complete set of keys for a new user.
pub fn generate_user_keys() -> Result(
  #(IdentityKeyPair, PreKey, SignedPreKey),
  String,
) {
  case signal_protocol.generate_identity_key_pair() {
    Ok(identity_key_pair) -> {
      case signal_protocol.generate_pre_key(1) {
        Ok(pre_key) -> {
          case
            signal_protocol.generate_signed_pre_key(
              identity_key_pair.public_key,
              1,
            )
          {
            Ok(signed_pre_key) -> {
              Ok(#(identity_key_pair, pre_key, signed_pre_key))
            }
            Error(e) -> Error("Failed to generate signed pre-key: " <> e)
          }
        }
        Error(e) -> Error("Failed to generate pre-key: " <> e)
      }
    }
    Error(e) -> Error("Failed to generate identity key pair: " <> e)
  }
}

/// Creates a pre-key bundle from user keys.
pub fn create_user_bundle(
  registration_id: Int,
  identity_key: BitArray,
  pre_key: PreKey,
  signed_pre_key: SignedPreKey,
) -> Result(PreKeyBundle, String) {
  pre_key_bundle.create(
    registration_id,
    identity_key,
    pre_key,
    signed_pre_key,
    <<0>>,
    // Base key will be generated during session creation
  )
}
