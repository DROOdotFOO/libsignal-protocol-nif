#include <string.h>
#include <limits.h>
#include <stdbool.h>
#include <sodium.h>
#include "dr.h"
#include "dr_chain.h"
#include "dr_crypto.h"

void advance_chain_key(unsigned char *chain_key,
                       const unsigned char *current_key) {
    unsigned char constant = 0x02;  // Signal spec: 0x02 for next chain key
    crypto_auth_hmacsha256(chain_key, &constant, 1, current_key);
}

void derive_message_key(unsigned char *message_key,
                        const unsigned char *chain_key) {
    unsigned char constant = 0x01;
    crypto_auth_hmacsha256(message_key, &constant, 1, chain_key);
}

int mkskipped_find(const double_ratchet_state_t *state,
                   const unsigned char *header_key,
                   unsigned int message_number) {
    for (int i = 0; i < MAX_SKIPPED_KEYS; i++) {
        const skipped_key_t *slot = &state->mkskipped[i];
        if (slot->occupied &&
            slot->message_number == message_number &&
            memcmp(slot->header_key, header_key, DR_HEADER_KEY_SIZE) == 0) {
            return i;
        }
    }
    return -1;
}

// Insert a (header_key, message_number, message_key) entry. If full, evict the
// least-recently-inserted slot (lowest lru_counter among occupied).
static void mkskipped_insert(double_ratchet_state_t *state,
                             const unsigned char *header_key,
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
    memcpy(slot->header_key, header_key, DR_HEADER_KEY_SIZE);
    slot->message_number = message_number;
    memcpy(slot->message_key, message_key, DR_MESSAGE_KEY_SIZE);
    state->mkskipped_lru_clock++;
    slot->lru_counter = state->mkskipped_lru_clock;
    slot->occupied = true;
}

void mkskipped_pop(double_ratchet_state_t *state, int index,
                   unsigned char *out_message_key) {
    skipped_key_t *slot = &state->mkskipped[index];
    memcpy(out_message_key, slot->message_key, DR_MESSAGE_KEY_SIZE);
    sodium_memzero(slot->message_key, DR_MESSAGE_KEY_SIZE);
    slot->occupied = false;
    slot->message_number = 0;
    sodium_memzero(slot->header_key, DR_HEADER_KEY_SIZE);
}

// Skip and store keys in the current recv chain up to `until` (exclusive).
// state->recv_chain_key advances as keys are derived; state->recv_message_number
// is bumped to `until`. Returns 0 on success, -1 if the skip exceeds MAX_SKIP.
// No-op when the recv chain hasn't been established yet (Alice pre-receive).
// Cached entries are keyed on state->header_key_recv at call time (the chain's
// current receiving header key, used to trial-decrypt later late-deliveries).
int skip_message_keys(double_ratchet_state_t *state,
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
        mkskipped_insert(state, state->header_key_recv,
                         state->recv_message_number, message_key);
        state->recv_message_number++;
    }
    sodium_memzero(message_key, sizeof(message_key));
    return 0;
}

// Double Ratchet receive-side ratchet step (per Signal DR spec section 3.5).
// Two KDF passes from the same DH inputs:
//   1. Derive new recv_chain_key from KDF(root, DH(my_current_priv, their_new_pub))
//   2. Generate a fresh keypair and derive new send_chain_key from
//      KDF(new_root, DH(my_new_priv, their_new_pub))
// Alice's initial send ratchet is inlined directly into dr_init (no recv
// chain to derive there); this function covers every later DH step.
int dh_ratchet_recv(double_ratchet_state_t *state,
                    const unsigned char *remote_public_key) {
    unsigned char dh_output[crypto_scalarmult_BYTES];
    unsigned char kdf_output[96];

    // Step 1: receive ratchet using CURRENT dh_send_private.
    // KDF_RK_HE: 96B = root(32) || recv_chain(32) || NHKr(32).
    if (crypto_scalarmult(dh_output, state->dh_send_private, remote_public_key) != 0) {
        return -1;
    }
    if (hkdf_sha256(kdf_output, 96, state->root_key, 32, dh_output, 32,
                    (const unsigned char *)"DR-RK", 5) != 0) {
        sodium_memzero(dh_output, sizeof(dh_output));
        return -1;
    }
    memcpy(state->header_key_recv, state->next_header_key_recv, 32);
    memcpy(state->root_key, kdf_output, 32);
    memcpy(state->recv_chain_key, kdf_output + 32, 32);
    memcpy(state->next_header_key_recv, kdf_output + 64, 32);

    // Step 2: generate new keypair and derive new send chain.
    // KDF_RK_HE: 96B = root(32) || send_chain(32) || NHKs(32).
    if (crypto_box_keypair(state->dh_send_public, state->dh_send_private) != 0) {
        sodium_memzero(dh_output, sizeof(dh_output));
        sodium_memzero(kdf_output, sizeof(kdf_output));
        return -1;
    }
    if (crypto_scalarmult(dh_output, state->dh_send_private, remote_public_key) != 0) {
        sodium_memzero(dh_output, sizeof(dh_output));
        sodium_memzero(kdf_output, sizeof(kdf_output));
        return -1;
    }
    if (hkdf_sha256(kdf_output, 96, state->root_key, 32, dh_output, 32,
                    (const unsigned char *)"DR-RK", 5) != 0) {
        sodium_memzero(dh_output, sizeof(dh_output));
        sodium_memzero(kdf_output, sizeof(kdf_output));
        return -1;
    }
    memcpy(state->header_key_send, state->next_header_key_send, 32);
    memcpy(state->root_key, kdf_output, 32);
    memcpy(state->send_chain_key, kdf_output + 32, 32);
    memcpy(state->next_header_key_send, kdf_output + 64, 32);
    memcpy(state->dh_recv_public, remote_public_key, crypto_box_PUBLICKEYBYTES);

    state->prev_send_length = state->send_message_number;
    state->send_message_number = 0;
    state->recv_message_number = 0;
    state->dh_recv_initialized = true;

    sodium_memzero(dh_output, sizeof(dh_output));
    sodium_memzero(kdf_output, sizeof(kdf_output));
    return 0;
}

// Has any byte set? Used to filter the never-seeded header_key_recv on
// Alice's side before her first receive (it stays at the memset(0) value
// from dr_init). Skipping zero keys avoids spurious "decryption succeeded"
// hits when the wire is malformed.
int hk_is_nonzero(const unsigned char *hk) {
    unsigned char acc = 0;
    for (int i = 0; i < DR_HEADER_KEY_SIZE; i++) acc |= hk[i];
    return acc != 0;
}
