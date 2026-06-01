import gleam/bit_array
import gleeunit/should
import utils

pub fn generate_user_keys_test() {
  case utils.generate_user_keys() {
    Ok(#(identity_key_pair, pre_key, signed_pre_key)) -> {
      should.equal(bit_array.byte_size(identity_key_pair.public_key) > 0, True)
      should.equal(bit_array.byte_size(identity_key_pair.signature) > 0, True)
      should.equal(pre_key.key_id, 1)
      should.equal(bit_array.byte_size(pre_key.public_key) > 0, True)
      should.equal(signed_pre_key.key_id, 1)
      should.equal(bit_array.byte_size(signed_pre_key.public_key) > 0, True)
      should.equal(bit_array.byte_size(signed_pre_key.signature) > 0, True)
    }
    Error(_e) -> should.fail()
  }
}

pub fn create_user_bundle_test() {
  case utils.generate_user_keys() {
    Ok(#(identity_key_pair, pre_key, signed_pre_key)) -> {
      case
        utils.create_user_bundle(
          1,
          identity_key_pair.public_key,
          pre_key,
          signed_pre_key,
        )
      {
        Ok(bundle) -> {
          should.equal(bundle.registration_id, 1)
          should.equal(bundle.identity_key, identity_key_pair.public_key)
          should.equal(bundle.pre_key, #(pre_key.key_id, pre_key.public_key))
          should.equal(bundle.signed_pre_key, #(
            signed_pre_key.key_id,
            signed_pre_key.public_key,
            signed_pre_key.signature,
          ))
        }
        Error(_e) -> should.fail()
      }
    }
    Error(_e) -> should.fail()
  }
}
