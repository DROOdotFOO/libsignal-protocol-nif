#ifndef LIBSIGNAL_DR_CHAIN_H
#define LIBSIGNAL_DR_CHAIN_H

#include "dr.h"

// Advance chain key per Signal DR spec:
// chain_key' = HMAC-SHA-256(chain_key, 0x02).
void advance_chain_key(unsigned char *chain_key,
                       const unsigned char *current_key);

// Derive message key per Signal DR spec:
// mk = HMAC-SHA-256(chain_key, 0x01).
void derive_message_key(unsigned char *message_key,
                        const unsigned char *chain_key);

// Find MKSKIPPED slot matching (header_key, message_number). Returns slot
// index or -1 if not present.
int mkskipped_find(const double_ratchet_state_t *state,
                   const unsigned char *header_key,
                   unsigned int message_number);

// Copy out the message key from the slot at `index` and free the slot.
void mkskipped_pop(double_ratchet_state_t *state, int index,
                   unsigned char *out_message_key);

// Skip and store keys in the current recv chain up to `until` (exclusive).
// Returns 0 on success, -1 if the skip exceeds MAX_SKIP.
int skip_message_keys(double_ratchet_state_t *state,
                      unsigned int until);

// DH ratchet step. Currently unused at the top level (dr_init inlines
// Alice's initial send ratchet, and dh_ratchet_recv covers receive-side).
// Kept as the canonical "send-side step 2" implementation.
int dh_ratchet(double_ratchet_state_t *state,
               const unsigned char *remote_public_key);

// Double Ratchet receive-side ratchet step (Signal DR spec section 3.5).
// Performs two KDF passes: first deriving new recv_chain_key, then generating
// a fresh keypair and deriving new send_chain_key.
int dh_ratchet_recv(double_ratchet_state_t *state,
                    const unsigned char *remote_public_key);

// True iff any byte of the 32-byte header_key is nonzero. Used to filter
// the never-seeded header_key_recv on Alice's side before her first receive.
int hk_is_nonzero(const unsigned char *hk);

#endif
