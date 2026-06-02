import signal_protocol.{
  type PreKey, type PreKeyBundle, type SignedPreKey, PreKeyBundle,
}

/// Creates a new pre-key bundle.
pub fn create(
  registration_id: Int,
  identity_key: BitArray,
  pre_key: PreKey,
  signed_pre_key: SignedPreKey,
  base_key: BitArray,
) -> Result(PreKeyBundle, String) {
  Ok(PreKeyBundle(
    registration_id,
    identity_key,
    #(pre_key.key_id, pre_key.public_key),
    #(
      signed_pre_key.key_id,
      signed_pre_key.public_key,
      signed_pre_key.signature,
    ),
    base_key,
  ))
}

// --- FFI: Elixir.SignalProtocol.PreKeyBundle integration ---
@external(erlang, "Elixir.SignalProtocol.PreKeyBundle", "parse")
fn call_elixir_parse(bundle_binary: BitArray) -> Result(PreKeyBundle, String)

@external(erlang, "Elixir.SignalProtocol.PreKeyBundle", "verify_signature")
fn call_elixir_verify_signature(bundle_binary: BitArray) -> Result(Nil, String)

/// Parses a pre-key bundle from its binary representation.
pub fn parse(bundle_binary: BitArray) -> Result(PreKeyBundle, String) {
  call_elixir_parse(bundle_binary)
}

/// Verifies the signature of a pre-key bundle.
pub fn verify_signature(bundle: PreKeyBundle) -> Result(Nil, String) {
  call_elixir_verify_signature(to_binary(bundle))
}

// Serializes a PreKeyBundle into the canonical wire binary that
// Elixir.SignalProtocol.PreKeyBundle.parse/1 consumes. Layout:
// <<1:8, reg_id:32, pre_key_id:32, signed_pre_key_id:32,
//   identity_key:bits, pre_key_public:bits, signed_pre_key_public:bits,
//   signed_pre_key_signature:bits, base_key:bits>>
pub fn to_binary(bundle: PreKeyBundle) -> BitArray {
  let #(pre_key_id, pre_key_public) = bundle.pre_key
  let #(signed_pre_key_id, signed_pre_key_public, signed_pre_key_signature) =
    bundle.signed_pre_key
  <<
    1:8,
    bundle.registration_id:32,
    pre_key_id:32,
    signed_pre_key_id:32,
    bundle.identity_key:bits,
    pre_key_public:bits,
    signed_pre_key_public:bits,
    signed_pre_key_signature:bits,
    bundle.base_key:bits,
  >>
}
