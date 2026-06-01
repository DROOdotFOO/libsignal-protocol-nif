#include <erl_nif.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include <stdbool.h>
#include <sodium.h>
#include "dr.h"
#include <limits.h>
#include <string.h>

// HKDF-like key derivation using BLAKE2b
static int derive_keys(unsigned char *output, size_t output_len,
                      const unsigned char *input, size_t input_len,
                      const unsigned char *salt, size_t salt_len,
                      const unsigned char *info, size_t info_len) {
    // Use BLAKE2b with salt as key for HKDF-like derivation
    // If salt is provided, use it as the key, otherwise use input directly
    if (salt && salt_len > 0) {
        return crypto_generichash(output, output_len, input, input_len, salt, salt_len);
    } else {
        return crypto_generichash(output, output_len, input, input_len, NULL, 0);
    }
}

// Advance chain key using HMAC
static void advance_chain_key(unsigned char *chain_key, const unsigned char *current_key) {
    // Use HMAC with constant 0x01 to advance chain key
    unsigned char constant = 0x01;
    crypto_auth(chain_key, &constant, 1, current_key);
}

// Derive message key from chain key
static void derive_message_key(unsigned char *message_key, const unsigned char *chain_key) {
    // Use HMAC with constant 0x02 to derive message key
    unsigned char constant = 0x02;
    crypto_auth(message_key, &constant, 1, chain_key);
}

// Find MKSKIPPED slot matching (dh_pub, message_number). Returns slot index
// or -1 if not present.
static int mkskipped_find(const double_ratchet_state_t *state,
                          const unsigned char *dh_pub,
                          unsigned int message_number) {
    for (int i = 0; i < MAX_SKIPPED_KEYS; i++) {
        const skipped_key_t *slot = &state->mkskipped[i];
        if (slot->occupied &&
            slot->message_number == message_number &&
            memcmp(slot->dh_pub, dh_pub, 32) == 0) {
            return i;
        }
    }
    return -1;
}

// Insert a (dh_pub, message_number, message_key) entry. If full, evict the
// least-recently-inserted slot (lowest lru_counter among occupied).
static void mkskipped_insert(double_ratchet_state_t *state,
                             const unsigned char *dh_pub,
                             unsigned int message_number,
                             const unsigned char *message_key) {
    int target = -1;
    for (int i = 0; i < MAX_SKIPPED_KEYS; i++) {
        if (!state->mkskipped[i].occupied) {
            target = i;
            break;
        }
    }
    if (target < 0) {
        unsigned int oldest = UINT_MAX;
        target = 0;
        for (int i = 0; i < MAX_SKIPPED_KEYS; i++) {
            if (state->mkskipped[i].lru_counter < oldest) {
                oldest = state->mkskipped[i].lru_counter;
                target = i;
            }
        }
        sodium_memzero(state->mkskipped[target].message_key, DR_MESSAGE_KEY_SIZE);
    }

    skipped_key_t *slot = &state->mkskipped[target];
    memcpy(slot->dh_pub, dh_pub, 32);
    slot->message_number = message_number;
    memcpy(slot->message_key, message_key, DR_MESSAGE_KEY_SIZE);
    state->mkskipped_lru_clock++;
    slot->lru_counter = state->mkskipped_lru_clock;
    slot->occupied = true;
}

// Copy out the message key and free the slot.
static void mkskipped_pop(double_ratchet_state_t *state, int index,
                          unsigned char *out_message_key) {
    skipped_key_t *slot = &state->mkskipped[index];
    memcpy(out_message_key, slot->message_key, DR_MESSAGE_KEY_SIZE);
    sodium_memzero(slot->message_key, DR_MESSAGE_KEY_SIZE);
    slot->occupied = false;
    slot->message_number = 0;
    memset(slot->dh_pub, 0, 32);
}

// Skip and store keys in the current recv chain up to `until` (exclusive).
// state->recv_chain_key advances as keys are derived; state->recv_message_number
// is bumped to `until`. Returns 0 on success, -1 if the skip exceeds MAX_SKIP.
// No-op when the recv chain hasn't been established yet (Alice pre-receive).
static int skip_message_keys(double_ratchet_state_t *state,
                             const unsigned char *dh_pub,
                             unsigned int until) {
    if (until <= state->recv_message_number) {
        return 0;
    }
    if (until - state->recv_message_number > MAX_SKIP) {
        return -1;
    }
    if (!state->dh_recv_initialized) {
        // No recv chain to derive from; treat as no-op. The DH ratchet that
        // follows will establish the chain at message number 0.
        state->recv_message_number = until;
        return 0;
    }
    unsigned char message_key[DR_MESSAGE_KEY_SIZE];
    while (state->recv_message_number < until) {
        derive_message_key(message_key, state->recv_chain_key);
        advance_chain_key(state->recv_chain_key, state->recv_chain_key);
        mkskipped_insert(state, dh_pub, state->recv_message_number, message_key);
        state->recv_message_number++;
    }
    sodium_memzero(message_key, sizeof(message_key));
    return 0;
}

// Perform DH ratchet step
static int dh_ratchet(double_ratchet_state_t *state, const unsigned char *remote_public_key) {
    // Generate new DH key pair
    if (crypto_box_keypair(state->dh_send_public, state->dh_send_private) != 0) {
        return -1;
    }
    
    // Perform DH with remote public key
    unsigned char dh_output[crypto_box_BEFORENMBYTES];
    if (crypto_box_beforenm(dh_output, remote_public_key, state->dh_send_private) != 0) {
        return -1;
    }
    
    // Derive new root key and sending chain key
    unsigned char root_chain_input[64]; // root_key + dh_output
    memcpy(root_chain_input, state->root_key, 32);
    memcpy(root_chain_input + 32, dh_output, 32);
    
    unsigned char kdf_output[64]; // new_root_key + new_chain_key
    if (crypto_generichash(kdf_output, 64, root_chain_input, 64, NULL, 0) != 0) {
        sodium_memzero(dh_output, sizeof(dh_output));
        return -1;
    }
    
    // Update state
    memcpy(state->root_key, kdf_output, 32);
    memcpy(state->send_chain_key, kdf_output + 32, 32);
    memcpy(state->dh_recv_public, remote_public_key, crypto_box_PUBLICKEYBYTES);
    
    // Reset message counters
    state->prev_send_length = state->send_message_number;
    state->send_message_number = 0;
    
    // Clean up sensitive data
    sodium_memzero(dh_output, sizeof(dh_output));
    sodium_memzero(root_chain_input, sizeof(root_chain_input));
    sodium_memzero(kdf_output, sizeof(kdf_output));

    return 0;
}

// Double Ratchet receive-side ratchet step (per Signal DR spec section 3.5).
// Two KDF passes from the same DH inputs:
//   1. Derive new recv_chain_key from KDF(root, DH(my_current_priv, their_new_pub))
//   2. Generate a fresh keypair and derive new send_chain_key from
//      KDF(new_root, DH(my_new_priv, their_new_pub))
// dh_ratchet() above only does step 2, which is correct for Alice's initial
// send setup but wrong for any receive-triggered ratchet -- the receiver must
// derive recv_chain_key first or decryption fails.
static int dh_ratchet_recv(double_ratchet_state_t *state,
                           const unsigned char *remote_public_key) {
    unsigned char dh_output[crypto_box_BEFORENMBYTES];
    unsigned char kdf_input[64];
    unsigned char kdf_output[64];

    // Step 1: receive ratchet using CURRENT dh_send_private
    if (crypto_box_beforenm(dh_output, remote_public_key, state->dh_send_private) != 0) {
        return -1;
    }
    memcpy(kdf_input, state->root_key, 32);
    memcpy(kdf_input + 32, dh_output, 32);
    if (crypto_generichash(kdf_output, 64, kdf_input, 64, NULL, 0) != 0) {
        sodium_memzero(dh_output, sizeof(dh_output));
        sodium_memzero(kdf_input, sizeof(kdf_input));
        return -1;
    }
    memcpy(state->root_key, kdf_output, 32);
    memcpy(state->recv_chain_key, kdf_output + 32, 32);

    // Step 2: generate new keypair and derive new send chain
    if (crypto_box_keypair(state->dh_send_public, state->dh_send_private) != 0) {
        sodium_memzero(dh_output, sizeof(dh_output));
        sodium_memzero(kdf_input, sizeof(kdf_input));
        sodium_memzero(kdf_output, sizeof(kdf_output));
        return -1;
    }
    if (crypto_box_beforenm(dh_output, remote_public_key, state->dh_send_private) != 0) {
        sodium_memzero(dh_output, sizeof(dh_output));
        sodium_memzero(kdf_input, sizeof(kdf_input));
        sodium_memzero(kdf_output, sizeof(kdf_output));
        return -1;
    }
    memcpy(kdf_input, state->root_key, 32);
    memcpy(kdf_input + 32, dh_output, 32);
    if (crypto_generichash(kdf_output, 64, kdf_input, 64, NULL, 0) != 0) {
        sodium_memzero(dh_output, sizeof(dh_output));
        sodium_memzero(kdf_input, sizeof(kdf_input));
        sodium_memzero(kdf_output, sizeof(kdf_output));
        return -1;
    }
    memcpy(state->root_key, kdf_output, 32);
    memcpy(state->send_chain_key, kdf_output + 32, 32);
    memcpy(state->dh_recv_public, remote_public_key, crypto_box_PUBLICKEYBYTES);

    state->prev_send_length = state->send_message_number;
    state->send_message_number = 0;
    state->recv_message_number = 0;
    state->dh_recv_initialized = true;

    sodium_memzero(dh_output, sizeof(dh_output));
    sodium_memzero(kdf_input, sizeof(kdf_input));
    sodium_memzero(kdf_output, sizeof(kdf_output));
    return 0;
}
// Double Ratchet init (per Signal DR spec section 3.3).
// Args: SharedSecret(64), RemoteIdentityPub(32), SelfIdentityPriv(32), IsAlice(int).
// Alice: SelfIdentityPriv is ignored (she uses a fresh ephemeral). She does an
//   initial send ratchet against the remote pub, populating send_chain_key.
// Bob: RemoteIdentityPub is ignored. He stores his identity keypair and waits
//   for Alice's first message before any chain key is derived; encrypt fails
//   until then. This mirrors the Signal spec asymmetry: initiator sends first.
ERL_NIF_TERM dr_init(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 4) {
        return enif_make_badarg(env);
    }

    ErlNifBinary shared_secret, remote_public_key, self_priv;
    int is_alice;

    if (!enif_inspect_binary(env, argv[0], &shared_secret) ||
        !enif_inspect_binary(env, argv[1], &remote_public_key) ||
        !enif_inspect_binary(env, argv[2], &self_priv) ||
        !enif_get_int(env, argv[3], &is_alice)) {
        return enif_make_badarg(env);
    }

    if (shared_secret.size != 64) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "invalid_shared_secret_size"));
    }

    double_ratchet_state_t state;
    memset(&state, 0, sizeof(state));
    memcpy(state.root_key, shared_secret.data, 32);

    if (is_alice) {
        // Alice's remote_identity_pub is the peer's Ed25519 identity pub.
        // Convert to X25519 for DH.
        if (remote_public_key.size != crypto_sign_PUBLICKEYBYTES) {
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "invalid_remote_public_key_size"));
        }
        if (crypto_sign_ed25519_pk_to_curve25519(state.dh_recv_public,
                                                 remote_public_key.data) != 0) {
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "identity_pub_conversion_failed"));
        }
        // Fresh ephemeral DH pair
        if (crypto_box_keypair(state.dh_send_public, state.dh_send_private) != 0) {
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "key_generation_failed"));
        }
        state.dh_recv_initialized = true;

        // Initial send ratchet: KDF_RK(root, DH(alice_eph_priv, bob_pub))
        unsigned char dh_out[crypto_box_BEFORENMBYTES];
        if (crypto_box_beforenm(dh_out, state.dh_recv_public,
                                state.dh_send_private) != 0) {
            sodium_memzero(&state, sizeof(state));
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "dh_failed"));
        }
        unsigned char kdf_in[64], kdf_out[64];
        memcpy(kdf_in, state.root_key, 32);
        memcpy(kdf_in + 32, dh_out, 32);
        if (crypto_generichash(kdf_out, 64, kdf_in, 64, NULL, 0) != 0) {
            sodium_memzero(dh_out, sizeof(dh_out));
            sodium_memzero(kdf_in, sizeof(kdf_in));
            sodium_memzero(&state, sizeof(state));
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "kdf_failed"));
        }
        memcpy(state.root_key, kdf_out, 32);
        memcpy(state.send_chain_key, kdf_out + 32, 32);
        sodium_memzero(dh_out, sizeof(dh_out));
        sodium_memzero(kdf_in, sizeof(kdf_in));
        sodium_memzero(kdf_out, sizeof(kdf_out));
    } else {
        // Bob's self_identity_priv is his Ed25519 secret key. Convert to
        // X25519 priv for the initial send ratchet.
        if (self_priv.size != crypto_sign_SECRETKEYBYTES) {
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "invalid_self_priv_size"));
        }
        if (crypto_sign_ed25519_sk_to_curve25519(state.dh_send_private,
                                                 self_priv.data) != 0) {
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

    // Validate session size
    if (dr_session.size != DR_STATE_SIZE) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "invalid_session_size"));
    }

    // Copy state from binary
    double_ratchet_state_t state;
    memcpy(&state, dr_session.data, DR_STATE_SIZE);

    if (!state.initialized) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "session_not_initialized"));
    }

    // Bob cannot send before receiving Alice's first message -- his
    // send_chain_key is only derived during the receive ratchet.
    if (!state.dh_recv_initialized) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "must_receive_first"));
    }

    // Derive message key from current chain key
    unsigned char message_key[DR_MESSAGE_KEY_SIZE];
    derive_message_key(message_key, state.send_chain_key);
    
    // Advance chain key
    advance_chain_key(state.send_chain_key, state.send_chain_key);
    
    // Create message header: DH_public_key(32) + prev_chain_length(4) + message_number(4)
    unsigned char header[40];
    memcpy(header, state.dh_send_public, 32);
    memcpy(header + 32, &state.prev_send_length, 4);
    memcpy(header + 36, &state.send_message_number, 4);
    
    // Generate nonce for message encryption
    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    
    // Calculate total message size: header(40) + nonce(12) + ciphertext + MAC
    size_t ciphertext_len = plaintext.size + crypto_aead_chacha20poly1305_ietf_ABYTES;
    size_t total_size = 40 + 12 + ciphertext_len;
    
    ERL_NIF_TERM encrypted_term;
    unsigned char *encrypted_data = enif_make_new_binary(env, total_size, &encrypted_term);
    
    // Store header and nonce
    memcpy(encrypted_data, header, 40);
    memcpy(encrypted_data + 40, nonce, 12);
    
    // Encrypt message
    unsigned long long actual_ciphertext_len;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            encrypted_data + 52, // After header and nonce
            &actual_ciphertext_len,
            plaintext.data, plaintext.size,
            header, 40,  // Use header as additional authenticated data
            NULL,        // No secret nonce
            nonce, message_key) != 0) {
        sodium_memzero(message_key, sizeof(message_key));
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "encryption_failed"));
    }
    
    // Increment message number
    state.send_message_number++;
    
    // Update session state
    ERL_NIF_TERM updated_session_term;
    unsigned char *updated_session_data = enif_make_new_binary(env, DR_STATE_SIZE, &updated_session_term);
    memcpy(updated_session_data, &state, DR_STATE_SIZE);
    
    // Clear sensitive data
    sodium_memzero(message_key, sizeof(message_key));
    sodium_memzero(&state, sizeof(state));
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), 
                           enif_make_tuple2(env, encrypted_term, updated_session_term));
}

// Double Ratchet: Decrypt message.
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
    
    // Validate session size
    if (dr_session.size != DR_STATE_SIZE) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_session_size"));
    }
    
    // Validate minimum message size: header(40) + nonce(12) + MAC(16)
    if (ciphertext.size < 68) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "message_too_short"));
    }
    
    // Copy state from binary
    double_ratchet_state_t state;
    memcpy(&state, dr_session.data, DR_STATE_SIZE);
    
    if (!state.initialized) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "session_not_initialized"));
    }
    
    // Parse message header
    unsigned char *header = ciphertext.data;
    unsigned char *remote_dh_public = header;
    unsigned int prev_chain_length;
    unsigned int message_number;

    memcpy(&prev_chain_length, header + 32, 4);
    memcpy(&message_number, header + 36, 4);

    // Extract nonce and ciphertext
    unsigned char *nonce = ciphertext.data + 40;
    unsigned char *encrypted_payload = ciphertext.data + 52;
    size_t encrypted_payload_len = ciphertext.size - 52;
    size_t plaintext_len = encrypted_payload_len - crypto_aead_chacha20poly1305_ietf_ABYTES;

    unsigned char message_key[DR_MESSAGE_KEY_SIZE];

    // Late delivery: if this (dh_pub, message_number) is in MKSKIPPED, use
    // the cached key. State doesn't advance.
    int skipped_idx = mkskipped_find(&state, remote_dh_public, message_number);
    if (skipped_idx >= 0) {
        mkskipped_pop(&state, skipped_idx, message_key);
    } else {
        // Trigger receive ratchet if this is the first message ever, or if
        // the peer rotated their DH key. Before ratcheting, store the
        // remaining keys from the OLD recv chain (up to prev_chain_length)
        // so late messages on that chain can still be decrypted.
        bool need_ratchet = !state.dh_recv_initialized ||
            memcmp(remote_dh_public, state.dh_recv_public,
                   crypto_box_PUBLICKEYBYTES) != 0;
        if (need_ratchet) {
            if (skip_message_keys(&state, state.dh_recv_public,
                                  prev_chain_length) != 0) {
                return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                       enif_make_atom(env, "too_many_skipped"));
            }
            if (dh_ratchet_recv(&state, remote_dh_public) != 0) {
                return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                       enif_make_atom(env, "dh_ratchet_failed"));
            }
        }

        // Skip and store keys in the (now-current) chain up to message_number.
        if (skip_message_keys(&state, state.dh_recv_public,
                              message_number) != 0) {
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "too_many_skipped"));
        }

        derive_message_key(message_key, state.recv_chain_key);
        advance_chain_key(state.recv_chain_key, state.recv_chain_key);
        state.recv_message_number++;
    }

    ERL_NIF_TERM decrypted_term;
    unsigned char *decrypted_data = enif_make_new_binary(env, plaintext_len, &decrypted_term);

    // Decrypt message
    unsigned long long actual_plaintext_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            decrypted_data, &actual_plaintext_len,
            NULL,  // No secret nonce
            encrypted_payload, encrypted_payload_len,
            header, 40,  // Use header as additional authenticated data
            nonce, message_key) != 0) {
        sodium_memzero(message_key, sizeof(message_key));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "decryption_failed"));
    }
    
    // Update session state
    ERL_NIF_TERM updated_session_term;
    unsigned char *updated_session_data = enif_make_new_binary(env, DR_STATE_SIZE, &updated_session_term);
    memcpy(updated_session_data, &state, DR_STATE_SIZE);
    
    // Clear sensitive data
    sodium_memzero(message_key, sizeof(message_key));
    sodium_memzero(&state, sizeof(state));
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), 
                           enif_make_tuple2(env, decrypted_term, updated_session_term));
}

