import gleeunit
import gleeunit/should
import session
import signal_protocol

pub fn main() {
  gleeunit.main()
}

pub fn create_session_test() {
  case signal_protocol.generate_identity_key_pair() {
    Ok(local_identity) -> {
      case signal_protocol.generate_identity_key_pair() {
        Ok(remote_identity) -> {
          case
            session.create(
              local_identity.public_key,
              remote_identity.public_key,
            )
          {
            Ok(_session) -> should.equal(True, True)
            Error(_e) -> should.fail()
          }
        }
        Error(_e) -> should.fail()
      }
    }
    Error(_e) -> should.fail()
  }
}
