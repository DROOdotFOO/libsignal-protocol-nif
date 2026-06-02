import gleam/bit_array
import gleeunit
import gleeunit/should
import pre_key_bundle
import signal_protocol.{PreKeyBundle}

@external(erlang, "crypto", "strong_rand_bytes")
fn strong_rand_bytes(n: Int) -> BitArray

pub fn main() {
  gleeunit.main()
}

pub fn create_bundle_test() {
  case signal_protocol.generate_identity_key_pair() {
    Ok(identity_key_pair) -> {
      case signal_protocol.generate_pre_key(1) {
        Ok(pre_key) -> {
          case
            signal_protocol.generate_signed_pre_key(
              identity_key_pair.private_key,
              1,
            )
          {
            Ok(signed_pre_key) -> {
              case
                pre_key_bundle.create(
                  1,
                  identity_key_pair.public_key,
                  pre_key,
                  signed_pre_key,
                  <<"base_key_placeholder":utf8>>,
                )
              {
                Ok(_bundle) -> should.equal(True, True)
                Error(_e) -> panic as "Failed to create bundle"
              }
            }
            Error(_e) -> panic as "Failed to generate signed pre-key"
          }
        }
        Error(_e) -> panic as "Failed to generate pre-key"
      }
    }
    Error(_e) -> panic as "Failed to generate identity key pair"
  }
}

// Verifies that to_binary produces the canonical wire layout consumed by
// Elixir.SignalProtocol.PreKeyBundle.parse/1: header fields big-endian,
// followed by identity_key || pre_key_public || signed_pre_key_public ||
// signature || base_key. Sizes are chosen to match the Signal Protocol
// post-Ed25519 format (signature is 64B, all keys are 32B).
pub fn to_binary_canonical_layout_test() {
  let identity_key = strong_rand_bytes(32)
  let pre_key_public = strong_rand_bytes(32)
  let signed_pre_key_public = strong_rand_bytes(32)
  let signature = strong_rand_bytes(64)
  let base_key = strong_rand_bytes(32)

  let bundle =
    PreKeyBundle(
      registration_id: 1234,
      identity_key: identity_key,
      pre_key: #(11, pre_key_public),
      signed_pre_key: #(22, signed_pre_key_public, signature),
      base_key: base_key,
    )

  let expected = <<
    1:8,
    1234:32,
    11:32,
    22:32,
    identity_key:bits,
    pre_key_public:bits,
    signed_pre_key_public:bits,
    signature:bits,
    base_key:bits,
  >>

  let actual = pre_key_bundle.to_binary(bundle)
  should.equal(actual, expected)
  // 1 + 4 + 4 + 4 + 32 + 32 + 32 + 64 + 32 = 205
  should.equal(bit_array.byte_size(actual), 205)
}
