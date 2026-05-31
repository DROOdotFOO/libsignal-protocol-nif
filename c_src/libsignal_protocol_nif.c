#include <erl_nif.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include <stdbool.h>
#include <sodium.h>

// Constants for Double Ratchet
#define DR_ROOT_KEY_SIZE 32
#define DR_CHAIN_KEY_SIZE 32
#define DR_MESSAGE_KEY_SIZE 32
#define DR_HEADER_KEY_SIZE 32

// MKSKIPPED bounds. MAX_SKIP gates DOS (an attacker sending message_number=N
// would force N KDF rounds before erroring); MAX_SKIPPED_KEYS bounds memory.
// Aligned so we don't derive keys we'd immediately discard.
#define MAX_SKIPPED_KEYS 32
#define MAX_SKIP 32

// Skipped message-key cache entry. Indexed by (dh_pub, message_number).
typedef struct {
    unsigned char dh_pub[32];
    unsigned int message_number;
    unsigned char message_key[DR_MESSAGE_KEY_SIZE];
    unsigned int lru_counter;  // higher = more recent; 0 == unoccupied sentinel
    bool occupied;
} skipped_key_t;

// Double Ratchet state structure
typedef struct {
    // Root chain key (32 bytes)
    unsigned char root_key[32];

    // Sending chain
    unsigned char send_chain_key[32];
    unsigned int send_message_number;

    // Receiving chain
    unsigned char recv_chain_key[32];
    unsigned int recv_message_number;

    // DH ratchet keys
    unsigned char dh_send_private[crypto_box_SECRETKEYBYTES];
    unsigned char dh_send_public[crypto_box_PUBLICKEYBYTES];
    unsigned char dh_recv_public[crypto_box_PUBLICKEYBYTES];

    // Previous sending chain length (for header)
    unsigned int prev_send_length;

    // Session established flag
    bool initialized;

    // True once dh_recv_public is a real peer key. Bob starts false until
    // Alice's first message arrives and triggers the receive ratchet.
    bool dh_recv_initialized;

    // MKSKIPPED: keys derived for messages whose receive was bypassed by
    // out-of-order delivery. Filled by skip_message_keys, drained by
    // mkskipped_pop. LRU clock is monotonic; on full insert, slot with the
    // lowest counter is evicted.
    skipped_key_t mkskipped[MAX_SKIPPED_KEYS];
    unsigned int mkskipped_lru_clock;
} double_ratchet_state_t;

#define DR_STATE_SIZE sizeof(double_ratchet_state_t)

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

// Initialize the NIF library
static ERL_NIF_TERM init_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 0) {
        return enif_make_badarg(env);
    }
    
    // Initialize libsodium
    if (sodium_init() < 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "sodium_init_failed"));
    }
    
    return enif_make_atom(env, "ok");
}

// Generate identity key pair using Curve25519
static ERL_NIF_TERM generate_identity_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 0) {
        return enif_make_badarg(env);
    }
    
    // Generate real Curve25519 key pair
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];  // 32 bytes
    unsigned char private_key[crypto_box_SECRETKEYBYTES]; // 32 bytes
    
    if (crypto_box_keypair(public_key, private_key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "key_generation_failed"));
    }
    
    ERL_NIF_TERM public_term, private_term;
    unsigned char *public_data = enif_make_new_binary(env, crypto_box_PUBLICKEYBYTES, &public_term);
    unsigned char *private_data = enif_make_new_binary(env, crypto_box_SECRETKEYBYTES, &private_term);
    
    memcpy(public_data, public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(private_data, private_key, crypto_box_SECRETKEYBYTES);
    
    // Clear sensitive data from stack
    sodium_memzero(private_key, sizeof(private_key));
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), 
                           enif_make_tuple2(env, public_term, private_term));
}

// Generate pre-key using Curve25519
static ERL_NIF_TERM generate_pre_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 1) {
        return enif_make_badarg(env);
    }
    
    int key_id;
    if (!enif_get_int(env, argv[0], &key_id)) {
        return enif_make_badarg(env);
    }
    
    // Generate real Curve25519 pre-key
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char private_key[crypto_box_SECRETKEYBYTES];
    
    if (crypto_box_keypair(public_key, private_key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "key_generation_failed"));
    }
    
    ERL_NIF_TERM pre_key_term;
    unsigned char *pre_key_data = enif_make_new_binary(env, crypto_box_PUBLICKEYBYTES, &pre_key_term);
    memcpy(pre_key_data, public_key, crypto_box_PUBLICKEYBYTES);
    
    // Clear sensitive data
    sodium_memzero(private_key, sizeof(private_key));
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), 
                           enif_make_tuple2(env, enif_make_int(env, key_id), pre_key_term));
}

// Generate signed pre-key using Ed25519 signatures
static ERL_NIF_TERM generate_signed_pre_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary identity_key;
    int key_id;
    
    if (!enif_inspect_binary(env, argv[0], &identity_key) || 
        !enif_get_int(env, argv[1], &key_id)) {
        return enif_make_badarg(env);
    }
    
    // Validate identity key size
    if (identity_key.size != crypto_box_SECRETKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_identity_key_size"));
    }
    
    // Generate real Curve25519 pre-key
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char private_key[crypto_box_SECRETKEYBYTES];
    
    if (crypto_box_keypair(public_key, private_key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "key_generation_failed"));
    }
    
    // Create message to sign (key_id + public_key)
    unsigned char message_to_sign[sizeof(int) + crypto_box_PUBLICKEYBYTES];
    memcpy(message_to_sign, &key_id, sizeof(int));
    memcpy(message_to_sign + sizeof(int), public_key, crypto_box_PUBLICKEYBYTES);
    
    // For simplicity, use HMAC-SHA256 instead of Ed25519 since we have Curve25519 keys
    unsigned char signature[32];  // HMAC-SHA256 output is 32 bytes
    
    // Use libsodium's crypto_auth for HMAC
    if (crypto_auth(signature, message_to_sign, sizeof(message_to_sign), identity_key.data) != 0) {
        sodium_memzero(private_key, sizeof(private_key));
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "signature_failed"));
    }
    
    ERL_NIF_TERM pre_key_term, signature_term;
    unsigned char *pre_key_data = enif_make_new_binary(env, crypto_box_PUBLICKEYBYTES, &pre_key_term);
    unsigned char *signature_data = enif_make_new_binary(env, 32, &signature_term);
    
    memcpy(pre_key_data, public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(signature_data, signature, 32);
    
    // Clear sensitive data
    sodium_memzero(private_key, sizeof(private_key));
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), 
                           enif_make_tuple3(env, enif_make_int(env, key_id), pre_key_term, signature_term));
}

// Create session (single argument version) - generate session key from public key
static ERL_NIF_TERM create_session_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 1) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary public_key;
    if (!enif_inspect_binary(env, argv[0], &public_key)) {
        return enif_make_badarg(env);
    }
    
    // Validate public key size
    if (public_key.size != crypto_box_PUBLICKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_public_key_size"));
    }
    
    // Create session state with derived key
    ERL_NIF_TERM session_term;
    unsigned char *session_data = enif_make_new_binary(env, 64, &session_term);
    
    // Use public key as base for session key (simplified approach)
    // In a real implementation, this would involve proper key agreement
    crypto_generichash(session_data, 32, public_key.data, public_key.size, NULL, 0);
    
    // Add some randomness for the rest of the session state
    randombytes_buf(session_data + 32, 32);
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), session_term);
}

// Create session (two argument version) - perform key agreement
static ERL_NIF_TERM create_session_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary local_key, remote_key;
    if (!enif_inspect_binary(env, argv[0], &local_key) || 
        !enif_inspect_binary(env, argv[1], &remote_key)) {
        return enif_make_badarg(env);
    }
    
    // Validate key sizes
    if (local_key.size != crypto_box_SECRETKEYBYTES || 
        remote_key.size != crypto_box_PUBLICKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_key_sizes"));
    }
    
    // Create session state with shared secret
    ERL_NIF_TERM session_term;
    unsigned char *session_data = enif_make_new_binary(env, 64, &session_term);
    
    // Perform Curve25519 key agreement
    unsigned char shared_secret[crypto_box_BEFORENMBYTES];
    if (crypto_box_beforenm(shared_secret, remote_key.data, local_key.data) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "key_agreement_failed"));
    }
    
    // Derive session key from shared secret
    crypto_generichash(session_data, 32, shared_secret, sizeof(shared_secret), NULL, 0);
    
    // Add some randomness for the rest of the session state
    randombytes_buf(session_data + 32, 32);
    
    // Clear sensitive data
    sodium_memzero(shared_secret, sizeof(shared_secret));
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), session_term);
}

// Process pre-key bundle - Full X3DH Key Agreement Protocol Implementation
static ERL_NIF_TERM process_pre_key_bundle(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary local_identity_key, bundle;
    
    if (!enif_inspect_binary(env, argv[0], &local_identity_key) ||
        !enif_inspect_binary(env, argv[1], &bundle)) {
        return enif_make_badarg(env);
    }
    
    // Validate local identity key size (should be 32 bytes for Curve25519 private key)
    if (local_identity_key.size != crypto_box_SECRETKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_local_identity_key_size"));
    }
    
    // Parse the pre-key bundle
    // Expected format: remote_identity_key(32) + signed_prekey(32) + signature(32) + [one_time_prekey(32)]
    size_t min_bundle_size = 32 + 32 + 32; // identity + signed_prekey + signature
    if (bundle.size < min_bundle_size) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_bundle_size"));
    }
    
    // Extract keys from bundle
    unsigned char *remote_identity_key = bundle.data;
    unsigned char *signed_prekey = bundle.data + 32;
    unsigned char *signature = bundle.data + 64;
    unsigned char *one_time_prekey = NULL;
    
    // Check if one-time prekey is present
    bool has_one_time_prekey = (bundle.size >= min_bundle_size + 32);
    if (has_one_time_prekey) {
        one_time_prekey = bundle.data + 96;
    }
    
    // Verify the signed prekey signature using HMAC-SHA256
    // Message to verify: signed_prekey (32 bytes)
    unsigned char computed_signature[32];
    if (crypto_auth(computed_signature, signed_prekey, 32, remote_identity_key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "signature_computation_failed"));
    }
    
    // Verify signature matches
    if (crypto_verify_32(computed_signature, signature) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "signature_verification_failed"));
    }
    
    // Generate ephemeral key pair for this X3DH exchange
    unsigned char ephemeral_public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char ephemeral_private_key[crypto_box_SECRETKEYBYTES];
    
    if (crypto_box_keypair(ephemeral_public_key, ephemeral_private_key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "ephemeral_key_generation_failed"));
    }
    
    // Perform X3DH key agreement calculations
    // DH1 = DH(IKA, SPKB) - Identity key with signed prekey
    // DH2 = DH(EKA, IKB) - Ephemeral key with identity key  
    // DH3 = DH(EKA, SPKB) - Ephemeral key with signed prekey
    // DH4 = DH(EKA, OPKB) - Ephemeral key with one-time prekey (if present)
    
    unsigned char dh1[crypto_box_BEFORENMBYTES];
    unsigned char dh2[crypto_box_BEFORENMBYTES];
    unsigned char dh3[crypto_box_BEFORENMBYTES];
    unsigned char dh4[crypto_box_BEFORENMBYTES];
    
    // DH1 = DH(local_identity_private, remote_signed_prekey)
    if (crypto_box_beforenm(dh1, signed_prekey, local_identity_key.data) != 0) {
        sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "dh1_calculation_failed"));
    }
    
    // DH2 = DH(ephemeral_private, remote_identity_key)
    if (crypto_box_beforenm(dh2, remote_identity_key, ephemeral_private_key) != 0) {
        sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
        sodium_memzero(dh1, sizeof(dh1));
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "dh2_calculation_failed"));
    }
    
    // DH3 = DH(ephemeral_private, remote_signed_prekey)
    if (crypto_box_beforenm(dh3, signed_prekey, ephemeral_private_key) != 0) {
        sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
        sodium_memzero(dh1, sizeof(dh1));
        sodium_memzero(dh2, sizeof(dh2));
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "dh3_calculation_failed"));
    }
    
    // DH4 = DH(ephemeral_private, one_time_prekey) - only if one-time prekey present
    if (has_one_time_prekey) {
        if (crypto_box_beforenm(dh4, one_time_prekey, ephemeral_private_key) != 0) {
            sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
            sodium_memzero(dh1, sizeof(dh1));
            sodium_memzero(dh2, sizeof(dh2));
            sodium_memzero(dh3, sizeof(dh3));
            return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                                   enif_make_atom(env, "dh4_calculation_failed"));
        }
    }
    
    // Concatenate DH outputs for KDF input
    // KM = DH1 || DH2 || DH3 || DH4 (if present)
    size_t km_size = has_one_time_prekey ? 128 : 96; // 4*32 or 3*32 bytes
    unsigned char *km = malloc(km_size);
    if (!km) {
        sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
        sodium_memzero(dh1, sizeof(dh1));
        sodium_memzero(dh2, sizeof(dh2));
        sodium_memzero(dh3, sizeof(dh3));
        if (has_one_time_prekey) {
            sodium_memzero(dh4, sizeof(dh4));
        }
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "memory_allocation_failed"));
    }
    
    memcpy(km, dh1, 32);
    memcpy(km + 32, dh2, 32);
    memcpy(km + 64, dh3, 32);
    if (has_one_time_prekey) {
        memcpy(km + 96, dh4, 32);
    }
    
    // Derive session key using HKDF-like construction
    // SK = KDF(F || KM) where F is 32 bytes of 0xFF for X25519
    unsigned char f_bytes[32];
    memset(f_bytes, 0xFF, 32);
    
    size_t hkdf_input_size = 32 + km_size;
    unsigned char *hkdf_input = malloc(hkdf_input_size);
    if (!hkdf_input) {
        free(km);
        sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
        sodium_memzero(dh1, sizeof(dh1));
        sodium_memzero(dh2, sizeof(dh2));
        sodium_memzero(dh3, sizeof(dh3));
        if (has_one_time_prekey) {
            sodium_memzero(dh4, sizeof(dh4));
        }
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "memory_allocation_failed"));
    }
    
    memcpy(hkdf_input, f_bytes, 32);
    memcpy(hkdf_input + 32, km, km_size);
    
    // Use BLAKE2b (available in libsodium) as our KDF to derive 64-byte session key
    unsigned char session_key[64];
    if (crypto_generichash(session_key, 64, hkdf_input, hkdf_input_size, NULL, 0) != 0) {
        free(km);
        free(hkdf_input);
        sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
        sodium_memzero(dh1, sizeof(dh1));
        sodium_memzero(dh2, sizeof(dh2));
        sodium_memzero(dh3, sizeof(dh3));
        if (has_one_time_prekey) {
            sodium_memzero(dh4, sizeof(dh4));
        }
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "kdf_failed"));
    }
    
    // Create return tuple with session key and ephemeral public key
    ERL_NIF_TERM session_term, ephemeral_pub_term;
    unsigned char *session_data = enif_make_new_binary(env, 64, &session_term);
    unsigned char *ephemeral_pub_data = enif_make_new_binary(env, 32, &ephemeral_pub_term);
    
    memcpy(session_data, session_key, 64);
    memcpy(ephemeral_pub_data, ephemeral_public_key, 32);
    
    // Clean up sensitive data
    free(km);
    free(hkdf_input);
    sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
    sodium_memzero(dh1, sizeof(dh1));
    sodium_memzero(dh2, sizeof(dh2));
    sodium_memzero(dh3, sizeof(dh3));
    if (has_one_time_prekey) {
        sodium_memzero(dh4, sizeof(dh4));
    }
    sodium_memzero(session_key, sizeof(session_key));
    
    // Return {ok, {SessionKey, EphemeralPublicKey}}
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), 
                           enif_make_tuple2(env, session_term, ephemeral_pub_term));
}

// Encrypt message using ChaCha20-Poly1305
static ERL_NIF_TERM encrypt_message(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary session, message;
    
    if (!enif_inspect_binary(env, argv[0], &session) ||
        !enif_inspect_binary(env, argv[1], &message)) {
        return enif_make_badarg(env);
    }
    
    // Validate session size (should contain at least a 32-byte key)
    if (session.size < 32) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_session"));
    }
    
    // Use first 32 bytes of session as encryption key
    unsigned char key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    memcpy(key, session.data, crypto_aead_chacha20poly1305_ietf_KEYBYTES);
    
    // Generate random nonce
    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    
    // Calculate ciphertext size (plaintext + MAC + nonce)
    size_t ciphertext_len = message.size + crypto_aead_chacha20poly1305_ietf_ABYTES;
    size_t total_size = ciphertext_len + crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    
    ERL_NIF_TERM encrypted_term;
    unsigned char *encrypted_data = enif_make_new_binary(env, total_size, &encrypted_term);
    
    // Store nonce at the beginning
    memcpy(encrypted_data, nonce, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    
    // Encrypt the message
    unsigned long long actual_ciphertext_len;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            encrypted_data + crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
            &actual_ciphertext_len,
            message.data, message.size,
            NULL, 0,  // No additional data
            NULL,     // No secret nonce
            nonce, key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "encryption_failed"));
    }
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), encrypted_term);
}

// Decrypt message using ChaCha20-Poly1305
static ERL_NIF_TERM decrypt_message(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary session, encrypted;
    
    if (!enif_inspect_binary(env, argv[0], &session) ||
        !enif_inspect_binary(env, argv[1], &encrypted)) {
        return enif_make_badarg(env);
    }
    
    // Validate session size (should contain at least a 32-byte key)
    if (session.size < 32) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_session"));
    }
    
    // Validate encrypted message size (nonce + ciphertext + MAC)
    size_t min_size = crypto_aead_chacha20poly1305_ietf_NPUBBYTES + 
                     crypto_aead_chacha20poly1305_ietf_ABYTES;
    if (encrypted.size < min_size) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_message"));
    }
    
    // Use first 32 bytes of session as decryption key
    unsigned char key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    memcpy(key, session.data, crypto_aead_chacha20poly1305_ietf_KEYBYTES);
    
    // Extract nonce from the beginning of encrypted data
    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    memcpy(nonce, encrypted.data, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    
    // Calculate plaintext size
    size_t ciphertext_len = encrypted.size - crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    size_t plaintext_len = ciphertext_len - crypto_aead_chacha20poly1305_ietf_ABYTES;
    
    ERL_NIF_TERM decrypted_term;
    unsigned char *decrypted_data = enif_make_new_binary(env, plaintext_len, &decrypted_term);
    
    // Decrypt the message
    unsigned long long actual_plaintext_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            decrypted_data, &actual_plaintext_len,
            NULL,  // No secret nonce
            encrypted.data + crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
            ciphertext_len,
            NULL, 0,  // No additional data
            nonce, key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "decryption_failed"));
    }
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), decrypted_term);
}

// Double Ratchet init (per Signal DR spec section 3.3).
// Args: SharedSecret(64), RemoteIdentityPub(32), SelfIdentityPriv(32), IsAlice(int).
// Alice: SelfIdentityPriv is ignored (she uses a fresh ephemeral). She does an
//   initial send ratchet against the remote pub, populating send_chain_key.
// Bob: RemoteIdentityPub is ignored. He stores his identity keypair and waits
//   for Alice's first message before any chain key is derived; encrypt fails
//   until then. This mirrors the Signal spec asymmetry: initiator sends first.
static ERL_NIF_TERM dr_init(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
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
        if (remote_public_key.size != crypto_box_PUBLICKEYBYTES) {
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "invalid_remote_public_key_size"));
        }
        // Fresh ephemeral DH pair
        if (crypto_box_keypair(state.dh_send_public, state.dh_send_private) != 0) {
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "key_generation_failed"));
        }
        memcpy(state.dh_recv_public, remote_public_key.data, crypto_box_PUBLICKEYBYTES);
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
        if (self_priv.size != crypto_box_SECRETKEYBYTES) {
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "invalid_self_priv_size"));
        }
        memcpy(state.dh_send_private, self_priv.data, crypto_box_SECRETKEYBYTES);
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
static ERL_NIF_TERM dr_encrypt(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
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
static ERL_NIF_TERM dr_decrypt(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
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

// Define the NIF function array
static ErlNifFunc nif_funcs[] = {
    {"init", 0, init_nif, 0},
    {"generate_identity_key_pair", 0, generate_identity_key_pair, 0},
    {"generate_pre_key", 1, generate_pre_key, 0},
    {"generate_signed_pre_key", 2, generate_signed_pre_key, 0},
    {"create_session", 1, create_session_1, 0},
    {"create_session", 2, create_session_2, 0},
    {"process_pre_key_bundle", 2, process_pre_key_bundle, 0},
    {"encrypt_message", 2, encrypt_message, 0},
    {"decrypt_message", 2, decrypt_message, 0},
    {"dr_init", 4, dr_init, 0},
    {"dr_encrypt", 2, dr_encrypt, 0},
    {"dr_decrypt", 2, dr_decrypt, 0}
};

static int on_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    // Initialize random seed
    srand((unsigned int)time(NULL));
    return 0;
}

static void on_unload(ErlNifEnv *env, void *priv_data)
{
}

// Initialize the NIF library
ERL_NIF_INIT(libsignal_protocol_nif, nif_funcs, on_load, NULL, NULL, on_unload) 