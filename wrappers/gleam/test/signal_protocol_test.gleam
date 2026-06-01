import gleam/bit_array
import gleeunit
import gleeunit/should
import signal_protocol

pub fn main() {
  gleeunit.main()
}

pub fn generate_identity_key_pair_test() {
  case signal_protocol.generate_identity_key_pair() {
    Ok(identity_key_pair) -> {
      should.equal(bit_array.byte_size(identity_key_pair.public_key) > 0, True)
      should.equal(bit_array.byte_size(identity_key_pair.private_key) > 0, True)
    }
    Error(_e) -> should.fail()
  }
}

pub fn generate_pre_key_test() {
  case signal_protocol.generate_pre_key(1) {
    Ok(pre_key) -> {
      should.equal(pre_key.key_id, 1)
      should.equal(bit_array.byte_size(pre_key.public_key) > 0, True)
    }
    Error(_e) -> should.fail()
  }
}

pub fn generate_signed_pre_key_test() {
  case signal_protocol.generate_identity_key_pair() {
    Ok(identity_key_pair) -> {
      case
        signal_protocol.generate_signed_pre_key(identity_key_pair.private_key, 1)
      {
        Ok(signed_pre_key) -> {
          should.equal(signed_pre_key.key_id, 1)
          should.equal(bit_array.byte_size(signed_pre_key.public_key) > 0, True)
          should.equal(bit_array.byte_size(signed_pre_key.signature) > 0, True)
        }
        Error(_e) -> should.fail()
      }
    }
    Error(_e) -> should.fail()
  }
}

pub fn basic_functionality_test() {
  // Test that we can at least generate keys without errors
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
              // All key generation successful
              should.equal(
                bit_array.byte_size(identity_key_pair.public_key) > 0,
                True,
              )
              should.equal(pre_key.key_id, 1)
              should.equal(signed_pre_key.key_id, 1)
            }
            Error(_e) -> should.fail()
          }
        }
        Error(_e) -> should.fail()
      }
    }
    Error(_e) -> should.fail()
  }
}
