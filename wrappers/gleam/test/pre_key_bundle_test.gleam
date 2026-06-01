import gleeunit
import gleeunit/should
import pre_key_bundle
import signal_protocol

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
              identity_key_pair.public_key,
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
