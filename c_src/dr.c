#include <erl_nif.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <time.h>
#include <stdbool.h>
#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include "dr.h"
#include "dr_chain.h"
#include "dr_crypto.h"
#include "dr_proto.h"
#include "pksm.h"

// Signal Protocol wire version. Encoded as (v << 4) | v in the leading byte.
#define DR_SIGNAL_VERSION 3
#define DR_VERSION_BYTE ((DR_SIGNAL_VERSION << 4) | DR_SIGNAL_VERSION)  // 0x33

// Double Ratchet init (per Signal DR spec section 3.3).
// Args: SharedSecret(64), LocalIdentityPub(32), RemoteIdentityPub(32),
//       SelfIdentityPriv(32 or 64), IsAlice(int).
// LocalIdentityPub and RemoteIdentityPub are Ed25519 pubs; they are converted
// to X25519 and stored in state for use as the Signal-spec MAC binding (every
// message MAC is HMAC(macKey, local_id || remote_id || version || proto)).
// Alice: SelfIdentityPriv may be empty (she uses a fresh ephemeral for DH).
//   She does an initial send ratchet against the remote pub.
// Bob:   SelfIdentityPriv must be his Ed25519 64B secret. He stores it as
//   his initial DH ratchet pair; send_chain_key is derived on first receive.
ERL_NIF_TERM dr_init(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 5) {
        return enif_make_badarg(env);
    }

    ErlNifBinary shared_secret, local_identity_pub, remote_identity_pub, self_priv;
    int is_alice;

    if (!enif_inspect_binary(env, argv[0], &shared_secret) ||
        !enif_inspect_binary(env, argv[1], &local_identity_pub) ||
        !enif_inspect_binary(env, argv[2], &remote_identity_pub) ||
        !enif_inspect_binary(env, argv[3], &self_priv) ||
        !enif_get_int(env, argv[4], &is_alice)) {
        return enif_make_badarg(env);
    }

    if (shared_secret.size != 96) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "invalid_shared_secret_size"));
    }
    if (local_identity_pub.size != crypto_sign_PUBLICKEYBYTES ||
        remote_identity_pub.size != crypto_sign_PUBLICKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "invalid_identity_pub_size"));
    }

    double_ratchet_state_t state;
    memset(&state, 0, sizeof(state));
    memcpy(state.root_key, shared_secret.data, 32);

    // DR-HE bootstrap: shared_secret[64..96) seeds the next-header-key for
    // both directions. After the first DH ratchet step on each side, the
    // active header_key for that direction is rotated in from this seed,
    // so Alice's HKs at time t == Bob's HKr at time t. header_key_send /
    // header_key_recv stay zero until that first rotation.
    // shared_secret[32..64) belongs to the 64B X3DH SK and is reserved
    // for future Signal-spec wire elements; not consumed by DR.
    memcpy(state.next_header_key_send, shared_secret.data + 64, 32);
    memcpy(state.next_header_key_recv, shared_secret.data + 64, 32);

    // Convert + store both identity pubs as X25519 form (used as MAC binding).
    if (crypto_sign_ed25519_pk_to_curve25519(state.local_identity_pub,
                                             local_identity_pub.data) != 0 ||
        crypto_sign_ed25519_pk_to_curve25519(state.remote_identity_pub,
                                             remote_identity_pub.data) != 0) {
        sodium_memzero(&state, sizeof(state));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "identity_pub_conversion_failed"));
    }

    if (is_alice) {
        // Alice uses the remote identity X25519 form as her initial dh_recv_public.
        memcpy(state.dh_recv_public, state.remote_identity_pub,
               crypto_box_PUBLICKEYBYTES);
        // Fresh ephemeral DH pair
        if (crypto_box_keypair(state.dh_send_public, state.dh_send_private) != 0) {
            sodium_memzero(&state, sizeof(state));
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "key_generation_failed"));
        }
        state.dh_recv_initialized = true;

        // Initial send ratchet: KDF_RK_HE(root, DH(alice_eph_priv, bob_pub)).
        // L=96 output: root(32) || send_chain(32) || next_header_key_send(32).
        // The previously-X3DH-seeded NHKs rotates into HKs at this step.
        unsigned char dh_out[crypto_scalarmult_BYTES];
        if (crypto_scalarmult(dh_out, state.dh_send_private,
                              state.dh_recv_public) != 0) {
            sodium_memzero(&state, sizeof(state));
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "dh_failed"));
        }
        unsigned char kdf_out[96];
        if (hkdf_sha256(kdf_out, 96, state.root_key, 32, dh_out, 32,
                        (const unsigned char *)"DR-RK", 5) != 0) {
            sodium_memzero(dh_out, sizeof(dh_out));
            sodium_memzero(&state, sizeof(state));
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "kdf_failed"));
        }
        memcpy(state.header_key_send, state.next_header_key_send, 32);
        memcpy(state.root_key, kdf_out, 32);
        memcpy(state.send_chain_key, kdf_out + 32, 32);
        memcpy(state.next_header_key_send, kdf_out + 64, 32);
        sodium_memzero(dh_out, sizeof(dh_out));
        sodium_memzero(kdf_out, sizeof(kdf_out));
    } else {
        // Bob's self_identity_priv is his Ed25519 secret key. Convert to
        // X25519 priv for the initial send ratchet.
        if (self_priv.size != crypto_sign_SECRETKEYBYTES) {
            sodium_memzero(&state, sizeof(state));
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "invalid_self_priv_size"));
        }
        if (crypto_sign_ed25519_sk_to_curve25519(state.dh_send_private,
                                                 self_priv.data) != 0) {
            sodium_memzero(&state, sizeof(state));
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "identity_priv_conversion_failed"));
        }
        crypto_scalarmult_base(state.dh_send_public, state.dh_send_private);
        // dh_recv_public stays zero; dh_recv_initialized stays false.
        // send_chain_key / recv_chain_key stay zero -- set on first receive.
    }

    state.initialized = true;
    state.send_message_number = 0;
    state.recv_message_number = 0;
    state.prev_send_length = 0;

    ERL_NIF_TERM dr_session_term;
    unsigned char *dr_session_data =
        enif_make_new_binary(env, DR_STATE_SIZE, &dr_session_term);
    memcpy(dr_session_data, &state, DR_STATE_SIZE);
    sodium_memzero(&state, sizeof(state));

    return enif_make_tuple2(env, enif_make_atom(env, "ok"), dr_session_term);
}

// Cipher + MAC + envelope. On success returns NULL, *out_wire is an
// enif_alloc'd buffer of *out_wire_len bytes (caller frees with enif_free),
// and *state is advanced in place. On failure returns a static error-name
// string and zeroizes any sensitive locals; state is left unmodified.
static const char *dr_encrypt_core(double_ratchet_state_t *state,
                                   const unsigned char *pt, size_t pt_len,
                                   unsigned char **out_wire, size_t *out_wire_len)
{
    const char *err = NULL;
    unsigned char message_key[DR_MESSAGE_KEY_SIZE];
    unsigned char next_chain[DR_CHAIN_KEY_SIZE];
    unsigned char cipher_key[32], mac_key[32], iv[16];
    unsigned char hcipher[32];
    unsigned char inner_header[64];
    unsigned char mac[DR_MAC_LEN];
    unsigned char *cbc_buf = NULL;
    unsigned char *enc_header = NULL;
    unsigned char *envelope = NULL;
    unsigned char *wire = NULL;
    size_t cbc_len = 0, header_ct_len = 0;
    size_t inner_header_len = 0, enc_header_len = 0, envelope_len = 0;
    size_t wire_len = 0;

    if (!state->initialized) { err = "session_not_initialized"; goto cleanup; }
    // Bob cannot send before receiving Alice's first message -- his
    // send_chain_key is only derived during the receive ratchet.
    if (!state->dh_recv_initialized) { err = "must_receive_first"; goto cleanup; }

    // Derive per-message keys: cipher_key(32) || mac_key(32) || iv(16)
    // from messageKey via HKDF (info="WhisperMessageKeys", Signal spec).
    derive_message_key(message_key, state->send_chain_key);
    advance_chain_key(next_chain, state->send_chain_key);

    if (dr_derive_message_keys(cipher_key, mac_key, iv, message_key) != 0) {
        err = "kdf_failed"; goto cleanup;
    }

    // AES-256-CBC + PKCS#7 encrypt. Output is always plaintext_len + 1..16.
    cbc_buf = enif_alloc(pt_len + 16);
    if (!cbc_buf) { err = "memory_allocation_failed"; goto cleanup; }
    if (dr_aes_cbc_encrypt(cbc_buf, &cbc_len, pt, pt_len, cipher_key, iv) != 0) {
        err = "encryption_failed"; goto cleanup;
    }

    // Inner header plaintext: protobuf fields 1-3 only (ratchet_key, counter,
    // previous_counter). Max 46 bytes.
    inner_header_len = dr_serialize_header(inner_header, state->dh_send_public, 32,
                                           state->send_message_number,
                                           state->prev_send_length);

    // Encrypt the inner header under the current send header_key with a
    // fresh random 16B IV. The wire form of enc_header is `iv || ciphertext`
    // so the receiver can run AES-CBC-decrypt with each candidate header_key
    // against the same IV during trial-decrypt. Reusing a static IV across
    // messages in a chain would expose identical leading blocks (the inner
    // header's first 16B are an invariant ratchet_key prefix).
    if (dr_derive_header_cipher_key(hcipher, state->header_key_send) != 0) {
        err = "kdf_failed"; goto cleanup;
    }
    enc_header = enif_alloc(16 + inner_header_len + 16);
    if (!enc_header) { err = "memory_allocation_failed"; goto cleanup; }
    randombytes_buf(enc_header, 16);  // random IV at the head
    if (dr_aes_cbc_encrypt(enc_header + 16, &header_ct_len,
                           inner_header, inner_header_len,
                           hcipher, enc_header) != 0) {
        err = "encryption_failed"; goto cleanup;
    }
    enc_header_len = 16 + header_ct_len;

    // Outer envelope protobuf: {enc_header = 1, ciphertext = 2}.
    // Max overhead: 2 tags + 2 varints = 22 bytes.
    envelope = enif_alloc(22 + enc_header_len + cbc_len);
    if (!envelope) { err = "memory_allocation_failed"; goto cleanup; }
    envelope_len = dr_serialize_envelope(envelope, enc_header, enc_header_len,
                                         cbc_buf, cbc_len);

    // MAC over local_id_pub || remote_id_pub || version || envelope.
    if (dr_compute_mac(mac, mac_key,
                       state->local_identity_pub, state->remote_identity_pub,
                       DR_VERSION_BYTE, envelope, envelope_len) != 0) {
        err = "mac_failed"; goto cleanup;
    }

    // Wire envelope: version(1) || envelope || mac(8).
    wire_len = 1 + envelope_len + DR_MAC_LEN;
    wire = enif_alloc(wire_len);
    if (!wire) { err = "memory_allocation_failed"; goto cleanup; }
    wire[0] = DR_VERSION_BYTE;
    memcpy(wire + 1, envelope, envelope_len);
    memcpy(wire + 1 + envelope_len, mac, DR_MAC_LEN);

    // Commit state and transfer wire to caller.
    memcpy(state->send_chain_key, next_chain, DR_CHAIN_KEY_SIZE);
    state->send_message_number++;
    *out_wire = wire;
    *out_wire_len = wire_len;
    wire = NULL;  // ownership transferred; cleanup must not free

cleanup:
    sodium_memzero(message_key, sizeof(message_key));
    sodium_memzero(next_chain, sizeof(next_chain));
    sodium_memzero(cipher_key, sizeof(cipher_key));
    sodium_memzero(mac_key, sizeof(mac_key));
    sodium_memzero(iv, sizeof(iv));
    sodium_memzero(hcipher, sizeof(hcipher));
    sodium_memzero(inner_header, sizeof(inner_header));
    if (cbc_buf) enif_free(cbc_buf);
    if (enc_header) enif_free(enc_header);
    if (envelope) enif_free(envelope);
    if (wire) enif_free(wire);
    return err;
}

// Double Ratchet: Encrypt message.
ERL_NIF_TERM dr_encrypt(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }

    ErlNifBinary dr_session, plaintext;

    if (!enif_inspect_binary(env, argv[0], &dr_session) ||
        !enif_inspect_binary(env, argv[1], &plaintext)) {
        return enif_make_badarg(env);
    }

    if (dr_session.size != DR_STATE_SIZE) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "invalid_session_size"));
    }

    double_ratchet_state_t state;
    memcpy(&state, dr_session.data, DR_STATE_SIZE);

    unsigned char *wire = NULL;
    size_t wire_len = 0;
    const char *err = dr_encrypt_core(&state, plaintext.data, plaintext.size,
                                      &wire, &wire_len);
    if (err) {
        sodium_memzero(&state, sizeof(state));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, err));
    }

    ERL_NIF_TERM encrypted_term;
    unsigned char *encrypted_data = enif_make_new_binary(env, wire_len, &encrypted_term);
    memcpy(encrypted_data, wire, wire_len);
    enif_free(wire);

    ERL_NIF_TERM updated_session_term;
    unsigned char *updated_session_data =
        enif_make_new_binary(env, DR_STATE_SIZE, &updated_session_term);
    memcpy(updated_session_data, &state, DR_STATE_SIZE);
    sodium_memzero(&state, sizeof(state));

    return enif_make_tuple2(env, enif_make_atom(env, "ok"),
                           enif_make_tuple2(env, encrypted_term, updated_session_term));
}

// Double Ratchet: Encrypt Alice's first message and wrap it in a
// PreKeySignalMessage so Bob can derive the X3DH SK before decrypting.
// argv[0] = DR session binary
// argv[1] = plaintext binary
// argv[2] = {RegistrationId :: uint, OneTimePreKeyIdOrUndefined,
//            SignedPreKeyId :: uint, BaseKey :: 32B binary}
//   where BaseKey is Alice's X3DH ephemeral pub returned by
//   process_pre_key_bundle/2.
// Returns {ok, {PksmWire, NewSession}} | {error, Atom}.
ERL_NIF_TERM dr_encrypt_prekey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 3) {
        return enif_make_badarg(env);
    }

    ErlNifBinary dr_session, plaintext;
    if (!enif_inspect_binary(env, argv[0], &dr_session) ||
        !enif_inspect_binary(env, argv[1], &plaintext)) {
        return enif_make_badarg(env);
    }

    const ERL_NIF_TERM *info_tup;
    int info_arity = 0;
    if (!enif_get_tuple(env, argv[2], &info_arity, &info_tup) || info_arity != 4) {
        return enif_make_badarg(env);
    }

    unsigned int registration_id = 0;
    unsigned int signed_pre_key_id = 0;
    if (!enif_get_uint(env, info_tup[0], &registration_id) ||
        !enif_get_uint(env, info_tup[2], &signed_pre_key_id)) {
        return enif_make_badarg(env);
    }

    unsigned int pre_key_id = 0;
    int has_pre_key_id = 0;
    if (enif_is_atom(env, info_tup[1])) {
        char atom_buf[16];
        if (enif_get_atom(env, info_tup[1], atom_buf, sizeof(atom_buf),
                          ERL_NIF_LATIN1) <= 0 ||
            strcmp(atom_buf, "undefined") != 0) {
            return enif_make_badarg(env);
        }
    } else if (enif_get_uint(env, info_tup[1], &pre_key_id)) {
        has_pre_key_id = 1;
    } else {
        return enif_make_badarg(env);
    }

    ErlNifBinary base_key;
    if (!enif_inspect_binary(env, info_tup[3], &base_key) ||
        base_key.size != crypto_box_PUBLICKEYBYTES) {
        return enif_make_badarg(env);
    }

    if (dr_session.size != DR_STATE_SIZE) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "invalid_session_size"));
    }

    double_ratchet_state_t state;
    memcpy(&state, dr_session.data, DR_STATE_SIZE);

    unsigned char *inner_wire = NULL;
    size_t inner_wire_len = 0;
    const char *err = dr_encrypt_core(&state, plaintext.data, plaintext.size,
                                      &inner_wire, &inner_wire_len);
    if (err) {
        sodium_memzero(&state, sizeof(state));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, err));
    }

    // PKSM body: registration_id, base_key(32), identity_key(32), optional
    // pre_key_id, signed_pre_key_id, inner_message. Worst-case overhead is
    // 6 tags + 6 varints + the two 32B keys = ~80B + inner.
    size_t pksm_cap = 80 + inner_wire_len;
    unsigned char *pksm_buf = enif_alloc(pksm_cap);
    if (!pksm_buf) {
        enif_free(inner_wire);
        sodium_memzero(&state, sizeof(state));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "memory_allocation_failed"));
    }

    int pksm_len = pksm_encode(pksm_buf, pksm_cap,
                               registration_id,
                               base_key.data, base_key.size,
                               state.local_identity_pub, crypto_box_PUBLICKEYBYTES,
                               pre_key_id, has_pre_key_id,
                               signed_pre_key_id,
                               inner_wire, inner_wire_len);
    enif_free(inner_wire);
    if (pksm_len < 0) {
        enif_free(pksm_buf);
        sodium_memzero(&state, sizeof(state));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "pksm_encode_failed"));
    }

    size_t wire_len = 1 + (size_t)pksm_len;
    ERL_NIF_TERM wire_term;
    unsigned char *wire_data = enif_make_new_binary(env, wire_len, &wire_term);
    wire_data[0] = DR_VERSION_BYTE;
    memcpy(wire_data + 1, pksm_buf, (size_t)pksm_len);
    enif_free(pksm_buf);

    ERL_NIF_TERM updated_session_term;
    unsigned char *updated_session_data =
        enif_make_new_binary(env, DR_STATE_SIZE, &updated_session_term);
    memcpy(updated_session_data, &state, DR_STATE_SIZE);
    sodium_memzero(&state, sizeof(state));

    return enif_make_tuple2(env, enif_make_atom(env, "ok"),
                           enif_make_tuple2(env, wire_term, updated_session_term));
}

// Double Ratchet: Decrypt message.
//
// DR-HE flow: parse outer envelope -> trial-decrypt enc_header under each
// candidate header_key (current HKr, then NHKr, then each MKSKIPPED slot's
// header_key). The first candidate whose AES-CBC unpads to a valid inner
// header protobuf identifies the path. MAC over the outer envelope is then
// verified against the message key for that path before the body is touched.
//
// State mutations happen on a stack copy and are only committed to the
// returned session binary on full success, so any path that errors out
// silently discards the partial state changes.
ERL_NIF_TERM dr_decrypt(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }

    ErlNifBinary dr_session, ciphertext;

    if (!enif_inspect_binary(env, argv[0], &dr_session) ||
        !enif_inspect_binary(env, argv[1], &ciphertext)) {
        return enif_make_badarg(env);
    }

    if (dr_session.size != DR_STATE_SIZE) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "invalid_session_size"));
    }

    double_ratchet_state_t state;
    memcpy(&state, dr_session.data, DR_STATE_SIZE);

    if (!state.initialized) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "session_not_initialized"));
    }

    // Outer envelope: version(1) || protobuf || mac(8).
    if (ciphertext.size < 1 + DR_MAC_LEN) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "message_too_short"));
    }
    if (ciphertext.data[0] != DR_VERSION_BYTE) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "unsupported_version"));
    }
    size_t envelope_len = ciphertext.size - 1 - DR_MAC_LEN;
    const unsigned char *envelope = ciphertext.data + 1;
    const unsigned char *received_mac = ciphertext.data + 1 + envelope_len;

    const unsigned char *enc_header = NULL;
    size_t enc_header_len = 0;
    const unsigned char *body_ct = NULL;
    size_t body_ct_len = 0;
    if (dr_parse_envelope(envelope, envelope_len,
                          &enc_header, &enc_header_len,
                          &body_ct, &body_ct_len) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "malformed_message"));
    }
    if (body_ct_len == 0 || (body_ct_len % 16) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "message_too_short"));
    }

    // Trial-decrypt enc_header under each candidate header_key.
    enum { PATH_CURRENT, PATH_RATCHET, PATH_SKIPPED } path = PATH_CURRENT;
    int matched_skipped_idx = -1;
    unsigned char header_plain[64];
    size_t header_plain_len = 0;
    dr_message_t inner;
    int found = 0;

    if (hk_is_nonzero(state.header_key_recv) &&
        dr_try_decrypt_header(header_plain, &header_plain_len, &inner,
                              enc_header, enc_header_len,
                              state.header_key_recv) == 0) {
        path = PATH_CURRENT;
        found = 1;
    } else if (hk_is_nonzero(state.next_header_key_recv) &&
               dr_try_decrypt_header(header_plain, &header_plain_len, &inner,
                                     enc_header, enc_header_len,
                                     state.next_header_key_recv) == 0) {
        path = PATH_RATCHET;
        found = 1;
    } else {
        for (int i = 0; i < MAX_SKIPPED_KEYS; i++) {
            if (!state.mkskipped[i].occupied) continue;
            if (dr_try_decrypt_header(header_plain, &header_plain_len, &inner,
                                      enc_header, enc_header_len,
                                      state.mkskipped[i].header_key) == 0) {
                // Locate the slot matching this (header_key, counter) tuple.
                int idx = mkskipped_find(&state, state.mkskipped[i].header_key,
                                         inner.counter);
                if (idx < 0) {
                    // Header decrypted under a chain's HK, but no cached
                    // message_key for that counter -- treat as malformed
                    // since we have nowhere to take this from.
                    sodium_memzero(header_plain, sizeof(header_plain));
                    return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                           enif_make_atom(env, "bad_mac"));
                }
                matched_skipped_idx = idx;
                path = PATH_SKIPPED;
                found = 1;
                break;
            }
        }
    }

    if (!found) {
        sodium_memzero(header_plain, sizeof(header_plain));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "bad_mac"));
    }

    // Apply path-specific state advance and derive the message key.
    unsigned char message_key[DR_MESSAGE_KEY_SIZE];
    if (path == PATH_SKIPPED) {
        mkskipped_pop(&state, matched_skipped_idx, message_key);
    } else if (path == PATH_CURRENT) {
        // Late delivery within the current chain: counter < recv_message_number
        // means the message's key was already moved into MKSKIPPED when an
        // earlier same-chain message advanced the receive chain past it.
        // PATH_CURRENT trial-decrypt matched because the chain's HKr also
        // keys those cached entries.
        if (inner.counter < state.recv_message_number) {
            int idx = mkskipped_find(&state, state.header_key_recv,
                                     inner.counter);
            if (idx < 0) {
                sodium_memzero(header_plain, sizeof(header_plain));
                return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                       enif_make_atom(env, "bad_mac"));
            }
            mkskipped_pop(&state, idx, message_key);
        } else {
            if (skip_message_keys(&state, inner.counter) != 0) {
                sodium_memzero(header_plain, sizeof(header_plain));
                return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                       enif_make_atom(env, "too_many_skipped"));
            }
            derive_message_key(message_key, state.recv_chain_key);
            advance_chain_key(state.recv_chain_key, state.recv_chain_key);
            state.recv_message_number++;
        }
    } else { // PATH_RATCHET
        if (skip_message_keys(&state, inner.previous_counter) != 0) {
            sodium_memzero(header_plain, sizeof(header_plain));
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "too_many_skipped"));
        }
        if (dh_ratchet_recv(&state, inner.ratchet_key) != 0) {
            sodium_memzero(header_plain, sizeof(header_plain));
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "dh_ratchet_failed"));
        }
        if (skip_message_keys(&state, inner.counter) != 0) {
            sodium_memzero(header_plain, sizeof(header_plain));
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "too_many_skipped"));
        }
        derive_message_key(message_key, state.recv_chain_key);
        advance_chain_key(state.recv_chain_key, state.recv_chain_key);
        state.recv_message_number++;
    }
    sodium_memzero(header_plain, sizeof(header_plain));

    // Derive per-message keys + verify MAC over the outer envelope.
    // MAC binding (Signal-spec swap on receive): peer was sender, so their
    // identity goes first.
    unsigned char cipher_key[32], mac_key[32], iv[16];
    if (dr_derive_message_keys(cipher_key, mac_key, iv, message_key) != 0) {
        sodium_memzero(message_key, sizeof(message_key));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "kdf_failed"));
    }
    unsigned char expected_mac[DR_MAC_LEN];
    if (dr_compute_mac(expected_mac, mac_key,
                       state.remote_identity_pub, state.local_identity_pub,
                       DR_VERSION_BYTE, envelope, envelope_len) != 0) {
        sodium_memzero(message_key, sizeof(message_key));
        sodium_memzero(cipher_key, sizeof(cipher_key));
        sodium_memzero(mac_key, sizeof(mac_key));
        sodium_memzero(iv, sizeof(iv));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "mac_failed"));
    }
    if (CRYPTO_memcmp(expected_mac, received_mac, DR_MAC_LEN) != 0) {
        sodium_memzero(message_key, sizeof(message_key));
        sodium_memzero(cipher_key, sizeof(cipher_key));
        sodium_memzero(mac_key, sizeof(mac_key));
        sodium_memzero(iv, sizeof(iv));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "bad_mac"));
    }

    // MAC OK -- decrypt body. PKCS#7 padding is validated by EVP_DecryptFinal;
    // the padding-oracle channel is closed since we already verified the MAC.
    unsigned char *pt_buf = enif_alloc(body_ct_len);
    if (!pt_buf) {
        sodium_memzero(message_key, sizeof(message_key));
        sodium_memzero(cipher_key, sizeof(cipher_key));
        sodium_memzero(mac_key, sizeof(mac_key));
        sodium_memzero(iv, sizeof(iv));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "memory_allocation_failed"));
    }
    size_t plaintext_len = 0;
    if (dr_aes_cbc_decrypt(pt_buf, &plaintext_len,
                           body_ct, body_ct_len,
                           cipher_key, iv) != 0) {
        enif_free(pt_buf);
        sodium_memzero(message_key, sizeof(message_key));
        sodium_memzero(cipher_key, sizeof(cipher_key));
        sodium_memzero(mac_key, sizeof(mac_key));
        sodium_memzero(iv, sizeof(iv));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "decryption_failed"));
    }

    ERL_NIF_TERM decrypted_term;
    unsigned char *decrypted_data =
        enif_make_new_binary(env, plaintext_len, &decrypted_term);
    memcpy(decrypted_data, pt_buf, plaintext_len);
    sodium_memzero(pt_buf, body_ct_len);
    enif_free(pt_buf);
    sodium_memzero(cipher_key, sizeof(cipher_key));
    sodium_memzero(mac_key, sizeof(mac_key));
    sodium_memzero(iv, sizeof(iv));

    ERL_NIF_TERM updated_session_term;
    unsigned char *updated_session_data =
        enif_make_new_binary(env, DR_STATE_SIZE, &updated_session_term);
    memcpy(updated_session_data, &state, DR_STATE_SIZE);

    sodium_memzero(message_key, sizeof(message_key));
    sodium_memzero(&state, sizeof(state));

    return enif_make_tuple2(env, enif_make_atom(env, "ok"),
                           enif_make_tuple2(env, decrypted_term, updated_session_term));
}

