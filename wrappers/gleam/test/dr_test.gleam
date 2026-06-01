import gleam/bit_array
import gleeunit/should
import signal_protocol.{Alice, Bob}

@external(erlang, "crypto", "strong_rand_bytes")
fn strong_rand_bytes(n: Int) -> BitArray

fn setup_parties() {
  // Bob's identity must be an Ed25519 keypair so dr_init can convert it to
  // X25519 for the initial ratchet.
  let assert Ok(bob_keys) = signal_protocol.generate_identity_key_pair()
  let shared_secret = strong_rand_bytes(64)
  let assert Ok(alice) =
    signal_protocol.init_double_ratchet(
      shared_secret,
      bob_keys.public_key,
      <<>>,
      Alice,
    )
  let assert Ok(bob) =
    signal_protocol.init_double_ratchet(
      shared_secret,
      <<>>,
      bob_keys.private_key,
      Bob,
    )
  #(alice, bob)
}

pub fn alice_to_bob_first_message_test() {
  let #(alice, bob) = setup_parties()
  let msg = <<"hello from alice":utf8>>
  let assert Ok(#(ct, _alice1)) = signal_protocol.dr_encrypt_message(alice, msg)
  let assert Ok(#(pt, _bob1)) = signal_protocol.dr_decrypt_message(bob, ct)
  should.equal(bit_array.byte_size(pt), bit_array.byte_size(msg))
  should.equal(pt, msg)
}

pub fn bob_cannot_send_before_receiving_test() {
  let #(_alice, bob) = setup_parties()
  let result = signal_protocol.dr_encrypt_message(bob, <<"premature":utf8>>)
  should.be_error(result)
}

pub fn bidirectional_handshake_test() {
  let #(alice, bob) = setup_parties()
  let assert Ok(#(ct_a2b, _)) =
    signal_protocol.dr_encrypt_message(alice, <<"hi bob":utf8>>)
  let assert Ok(#(_, bob1)) = signal_protocol.dr_decrypt_message(bob, ct_a2b)
  let assert Ok(#(ct_b2a, _)) =
    signal_protocol.dr_encrypt_message(bob1, <<"hi alice":utf8>>)
  let assert Ok(#(pt, _)) = signal_protocol.dr_decrypt_message(alice, ct_b2a)
  should.equal(pt, <<"hi alice":utf8>>)
}
