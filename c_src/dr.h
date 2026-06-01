#ifndef LIBSIGNAL_DR_H
#define LIBSIGNAL_DR_H

#include <erl_nif.h>
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

    // Session-bound identity pubs (X25519 form). Both sides must agree on
    // these at init; they are folded into every MAC (Signal-spec scope:
    // sender_id || receiver_id || version || serialized_message). Storing
    // them in state avoids passing them on every encrypt/decrypt.
    unsigned char local_identity_pub[crypto_box_PUBLICKEYBYTES];
    unsigned char remote_identity_pub[crypto_box_PUBLICKEYBYTES];

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


ERL_NIF_TERM dr_init(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM dr_encrypt(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM dr_decrypt(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

// HKDF-SHA-256 (RFC 5869). Shared between DR (KDF_RK) and X3DH (root seed).
int hkdf_sha256(unsigned char *output, size_t output_len,
                const unsigned char *salt, size_t salt_len,
                const unsigned char *ikm, size_t ikm_len,
                const unsigned char *info, size_t info_len);

#endif
