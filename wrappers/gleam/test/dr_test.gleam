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

@external(erlang, "signal_nif", "generate_curve25519_keypair")
fn generate_curve25519_keypair() -> Result(#(BitArray, BitArray), String)

@external(erlang, "signal_nif", "sign_data")
fn sign_data(seed: BitArray, message: BitArray) -> Result(BitArray, String)

pub fn pksm_first_message_test() {
  // Full X3DH + PKSM + DR handshake end-to-end through the Gleam surface.
  let assert Ok(alice_keys) = signal_protocol.generate_identity_key_pair()
  let assert Ok(bob_keys) = signal_protocol.generate_identity_key_pair()

  // Mint Bob's signed pre-key ourselves so we retain the private half.
  let assert Ok(#(spk_pub, spk_priv)) = generate_curve25519_keypair()
  let assert Ok(signature) = sign_data(bob_keys.private_key, spk_pub)

  // PreKeyBundle's pre_key field is required by the type; with the no-OPK
  // path under test we still supply it but it isn't fed into Bob X3DH.
  let bundle =
    PreKeyBundle(
      registration_id: 0,
      identity_key: bob_keys.public_key,
      pre_key: #(0, <<>>),
      signed_pre_key: #(1, spk_pub, signature),
      base_key: <<>>,
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

  let assert Ok(bob_sk) =
    signal_protocol.process_pre_key_bundle_bob(
      bob_keys.private_key,
      spk_priv,
      <<>>,
      alice_keys.public_key,
      alice_eph_pub,
    )
  should.equal(bob_sk, alice_sk)

  let assert Ok(bob_dr) =
    signal_protocol.init_double_ratchet(
      bob_sk,
      bob_keys.public_key,
      alice_keys.public_key,
      bob_keys.private_key,
      Bob,
    )
  let assert Ok(#(pt, _)) = signal_protocol.dr_decrypt_message(bob_dr, pksm.inner_message)
  should.equal(pt, plaintext)
}

pub fn pksm_decode_malformed_test() {
  let result = signal_protocol.pksm_decode(<<0x22, 1, 2, 3>>)
  should.be_error(result)
}
