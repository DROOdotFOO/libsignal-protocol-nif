import gleam/bit_array
import gleam/option.{None}
import gleeunit/should
import signal_protocol.{Alice, Bob, PreKeyInfo, PreKeyBundle}

@external(erlang, "crypto", "strong_rand_bytes")
fn strong_rand_bytes(n: Int) -> BitArray

fn setup_parties() {
  // Both identities must be Ed25519 keypairs so dr_init can convert them to
  // X25519 for the DH ratchet and for the MAC binding.
  let assert Ok(alice_keys) = signal_protocol.generate_identity_key_pair()
  let assert Ok(bob_keys) = signal_protocol.generate_identity_key_pair()
  let shared_secret = strong_rand_bytes(96)
  let assert Ok(alice) =
    signal_protocol.init_double_ratchet(
      shared_secret,
      alice_keys.public_key,
      bob_keys.public_key,
      <<>>,
      Alice,
    )
  let assert Ok(bob) =
    signal_protocol.init_double_ratchet(
      shared_secret,
      bob_keys.public_key,
      alice_keys.public_key,
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

pub fn pksm_first_message_test() {
  // Full X3DH + PKSM + DR handshake end-to-end through the Gleam surface.
  let assert Ok(alice_keys) = signal_protocol.generate_identity_key_pair()
  let assert Ok(bob_keys) = signal_protocol.generate_identity_key_pair()
  let assert Ok(spk) =
    signal_protocol.generate_signed_pre_key(bob_keys.private_key, 1)

  let bundle =
    PreKeyBundle(
      identity_key: bob_keys.public_key,
      signed_pre_key: spk.public_key,
      signature: spk.signature,
      one_time_pre_key: None,
    )
  // The wire form is exactly what the NIF consumes: 128 bytes, no OPK.
  should.equal(bit_array.byte_size(signal_protocol.encode_bundle(bundle)), 128)
  should.equal(
    signal_protocol.decode_bundle(signal_protocol.encode_bundle(bundle)),
    Ok(bundle),
  )

  let assert Ok(#(alice_sk, alice_eph_pub)) =
    signal_protocol.process_pre_key_bundle(alice_keys.private_key, bundle)

  let assert Ok(alice_dr) =
    signal_protocol.init_double_ratchet(
      alice_sk,
      alice_keys.public_key,
      bob_keys.public_key,
      <<>>,
      Alice,
    )

  let plaintext = <<"hello via PKSM":utf8>>
  let info =
    PreKeyInfo(
      registration_id: 1234,
      one_time_pre_key_id: None,
      signed_pre_key_id: 42,
      alice_ephemeral_pub: alice_eph_pub,
    )
  let assert Ok(#(wire, _alice_dr2)) =
    signal_protocol.dr_encrypt_prekey(alice_dr, plaintext, info)

  let assert Ok(pksm) = signal_protocol.pksm_decode(wire)
  should.equal(pksm.registration_id, 1234)
  should.equal(pksm.signed_pre_key_id, 42)
  should.equal(pksm.one_time_pre_key_id, None)
  should.equal(pksm.base_key, alice_eph_pub)

  // Bob bootstraps entirely from the envelope: pksm.identity_key is Alice's
  // Ed25519 pub, pksm.base_key her X3DH ephemeral.
  let assert Ok(bob_sk) =
    signal_protocol.process_pre_key_bundle_bob(
      bob_keys.private_key,
      spk.private_key,
      <<>>,
      pksm.identity_key,
      pksm.base_key,
    )
  should.equal(bob_sk, alice_sk)

  let assert Ok(bob_dr) =
    signal_protocol.init_double_ratchet(
      bob_sk,
      bob_keys.public_key,
      pksm.identity_key,
      bob_keys.private_key,
      Bob,
    )
  let assert Ok(#(pt, _)) = signal_protocol.dr_decrypt_message(bob_dr, pksm.inner_message)
  should.equal(pt, plaintext)
}

// The NIF returns {error, Atom}; the FFI must convert it so the declared
// Result(_, String) is honest and Error("malformed_message") matches.
pub fn pksm_decode_malformed_test() {
  should.equal(
    signal_protocol.pksm_decode(<<0x22, 1, 2, 3>>),
    Error("malformed_message"),
  )
}
