import gleeunit

@external(erlang, "libsignal_protocol_gleam_ffi", "test_setup")
fn test_setup() -> Nil

pub fn main() {
  test_setup()
  gleeunit.main()
}
