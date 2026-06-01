#include <erl_nif.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <time.h>
#include <stdbool.h>
#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include "dr.h"
#include "pksm.h"

// Signal Protocol wire version. Encoded as (v << 4) | v in the leading byte.
#define DR_SIGNAL_VERSION 3
#define DR_VERSION_BYTE ((DR_SIGNAL_VERSION << 4) | DR_SIGNAL_VERSION)  // 0x33
#define DR_MAC_LEN 8

// ============================================================================
// Protobuf encode/decode for the DR wire message.
//
//   message DrMessage {
//     bytes  ratchet_key      = 1;  // 32B sender DH pub
//     uint32 counter          = 2;  // Nm: msg number in current sending chain
//     uint32 previous_counter = 3;  // PN: length of previous sending chain
//     bytes  payload          = 4;  // nonce(12) || ChaCha20-Poly1305 output
//   }
//
// The AEAD AAD is the serialized bytes of fields 1-3 only (deterministic
// from the input values). Field 4 carries the encrypted body.
// ============================================================================

// Encode an unsigned 64-bit value as protobuf varint. Returns bytes written
// (1-10). Buffer must have at least 10 bytes.
static size_t pb_encode_varint(unsigned char *out, uint64_t value) {
    size_t n = 0;
    while (value >= 0x80) {
        out[n++] = (unsigned char)((value & 0x7F) | 0x80);
        value >>= 7;
    }
    out[n++] = (unsigned char)(value & 0x7F);
    return n;
}

// Decode a protobuf varint. Sets *value and *consumed. Returns 0 on success,
// -1 on truncation or overflow (>10 bytes).
static int pb_decode_varint(const unsigned char *in, size_t in_len,
                            uint64_t *value, size_t *consumed) {
    uint64_t v = 0;
    size_t shift = 0;
    for (size_t i = 0; i < in_len; i++) {
        if (i >= 10) return -1;
        v |= ((uint64_t)(in[i] & 0x7F)) << shift;
        if ((in[i] & 0x80) == 0) {
            *value = v;
            *consumed = i + 1;
            return 0;
        }
        shift += 7;
    }
    return -1;
}

// Serialize DrMessage fields 1-3 only (the "header"). Returns bytes written.
// `out` must have capacity >= 1+10 + ratchet_key_len + 1+10 + 1+10 (max 55).
static size_t dr_serialize_header(unsigned char *out,
                                  const unsigned char *ratchet_key,
                                  size_t ratchet_key_len,
                                  uint32_t counter,
                                  uint32_t previous_counter) {
    size_t n = 0;
    out[n++] = 0x0A;  // (1 << 3) | 2: field 1, length-delimited
    n += pb_encode_varint(out + n, ratchet_key_len);
    memcpy(out + n, ratchet_key, ratchet_key_len);
    n += ratchet_key_len;
    out[n++] = 0x10;  // (2 << 3) | 0: field 2, varint
    n += pb_encode_varint(out + n, counter);
    out[n++] = 0x18;  // (3 << 3) | 0: field 3, varint
    n += pb_encode_varint(out + n, previous_counter);
    return n;
}

typedef struct {
    const unsigned char *ratchet_key;
    size_t ratchet_key_len;
    uint32_t counter;
    uint32_t previous_counter;
    const unsigned char *payload;
    size_t payload_len;
    int seen_ratchet_key;
    int seen_counter;
    int seen_previous_counter;
    int seen_payload;
} dr_message_t;

// Parse a serialized DrMessage. Pointers in `out` reference the input buffer
// (no copies). Returns 0 on success, -1 on any malformation (truncation,
// duplicate field, unknown wire type, missing required field).
static int dr_parse_message(const unsigned char *in, size_t in_len,
                            dr_message_t *out) {
    memset(out, 0, sizeof(*out));
    size_t pos = 0;
    while (pos < in_len) {
        uint64_t tag = 0;
        size_t consumed = 0;
        if (pb_decode_varint(in + pos, in_len - pos, &tag, &consumed) != 0)
            return -1;
        pos += consumed;
        uint32_t field_number = (uint32_t)(tag >> 3);
        uint32_t wire_type = (uint32_t)(tag & 0x07);

        if (field_number == 1 && wire_type == 2) {
            if (out->seen_ratchet_key) return -1;
            uint64_t len = 0;
            if (pb_decode_varint(in + pos, in_len - pos, &len, &consumed) != 0)
                return -1;
            pos += consumed;
            if (len > in_len - pos) return -1;
            out->ratchet_key = in + pos;
            out->ratchet_key_len = (size_t)len;
            pos += (size_t)len;
            out->seen_ratchet_key = 1;
        } else if (field_number == 2 && wire_type == 0) {
            if (out->seen_counter) return -1;
            uint64_t v = 0;
            if (pb_decode_varint(in + pos, in_len - pos, &v, &consumed) != 0)
                return -1;
            pos += consumed;
            if (v > UINT32_MAX) return -1;
            out->counter = (uint32_t)v;
            out->seen_counter = 1;
        } else if (field_number == 3 && wire_type == 0) {
            if (out->seen_previous_counter) return -1;
            uint64_t v = 0;
            if (pb_decode_varint(in + pos, in_len - pos, &v, &consumed) != 0)
                return -1;
            pos += consumed;
            if (v > UINT32_MAX) return -1;
            out->previous_counter = (uint32_t)v;
            out->seen_previous_counter = 1;
        } else if (field_number == 4 && wire_type == 2) {
            if (out->seen_payload) return -1;
            uint64_t len = 0;
            if (pb_decode_varint(in + pos, in_len - pos, &len, &consumed) != 0)
                return -1;
            pos += consumed;
            if (len > in_len - pos) return -1;
            out->payload = in + pos;
            out->payload_len = (size_t)len;
            pos += (size_t)len;
            out->seen_payload = 1;
        } else {
            // Unknown field or unexpected wire type -- reject.
            return -1;
        }
    }
    if (!out->seen_ratchet_key || !out->seen_counter ||
        !out->seen_previous_counter || !out->seen_payload) {
        return -1;
    }
    return 0;
}

// HKDF-SHA-256 (RFC 5869). Caller provides salt (use zero-filled 32 bytes if
// none), input keying material (IKM), info, and the desired output length.
// We produce up to N=ceil(L/32) HMAC outputs; with L<=64 this is at most 2.
int hkdf_sha256(unsigned char *output, size_t output_len,
                       const unsigned char *salt, size_t salt_len,
                       const unsigned char *ikm, size_t ikm_len,
                       const unsigned char *info, size_t info_len) {
    if (output_len > 32 * 255) return -1;

    // Extract: PRK = HMAC-SHA-256(salt, IKM). If salt is NULL, use 32 zero bytes.
    unsigned char zero_salt[32] = {0};
    const unsigned char *use_salt = salt ? salt : zero_salt;
    size_t use_salt_len = salt ? salt_len : sizeof(zero_salt);

    unsigned char prk[crypto_auth_hmacsha256_BYTES];  // 32
    crypto_auth_hmacsha256_state st;
    if (crypto_auth_hmacsha256_init(&st, use_salt, use_salt_len) != 0) return -1;
    if (crypto_auth_hmacsha256_update(&st, ikm, ikm_len) != 0) return -1;
    if (crypto_auth_hmacsha256_final(&st, prk) != 0) return -1;

    // Expand: T(i) = HMAC-SHA-256(PRK, T(i-1) || info || i).
    unsigned char t_prev[crypto_auth_hmacsha256_BYTES];
    unsigned char t_curr[crypto_auth_hmacsha256_BYTES];
    size_t produced = 0;
    unsigned char counter = 1;
    size_t t_prev_len = 0;
    while (produced < output_len) {
        if (crypto_auth_hmacsha256_init(&st, prk, sizeof(prk)) != 0) return -1;
        if (t_prev_len > 0 &&
            crypto_auth_hmacsha256_update(&st, t_prev, t_prev_len) != 0)
            return -1;
        if (info_len > 0 &&
            crypto_auth_hmacsha256_update(&st, info, info_len) != 0)
            return -1;
        if (crypto_auth_hmacsha256_update(&st, &counter, 1) != 0) return -1;
        if (crypto_auth_hmacsha256_final(&st, t_curr) != 0) return -1;

        size_t take = output_len - produced;
        if (take > sizeof(t_curr)) take = sizeof(t_curr);
        memcpy(output + produced, t_curr, take);
        produced += take;

        memcpy(t_prev, t_curr, sizeof(t_curr));
        t_prev_len = sizeof(t_curr);
        counter++;
    }

    sodium_memzero(prk, sizeof(prk));
    sodium_memzero(t_prev, sizeof(t_prev));
    sodium_memzero(t_curr, sizeof(t_curr));
    return 0;
}

// ============================================================================
// Signal-spec AEAD primitives: AES-256-CBC + HMAC-SHA-256 (truncated to 8B).
// Used by dr_encrypt/dr_decrypt as a single encrypt-then-MAC unit.
// ============================================================================

// Expand a 32B message key into the per-message Signal triplet
// (cipher_key, mac_key, iv) via HKDF-SHA-256.
//   salt = 32 zero bytes (Signal convention for per-message KDF)
//   info = "WhisperMessageKeys"  (canonical libsignal info string)
//   L    = 80  (32 cipher_key + 32 mac_key + 16 iv)
static int dr_derive_message_keys(unsigned char *cipher_key,
                                  unsigned char *mac_key,
                                  unsigned char *iv,
                                  const unsigned char *message_key) {
    unsigned char salt[32] = {0};
    unsigned char out[80];
    if (hkdf_sha256(out, sizeof(out), salt, sizeof(salt),
                    message_key, DR_MESSAGE_KEY_SIZE,
                    (const unsigned char *)"WhisperMessageKeys",
                    sizeof("WhisperMessageKeys") - 1) != 0) {
        return -1;
    }
    memcpy(cipher_key, out, 32);
    memcpy(mac_key, out + 32, 32);
    memcpy(iv, out + 64, 16);
    sodium_memzero(out, sizeof(out));
    return 0;
}

// AES-256-CBC encrypt with PKCS#7 padding via OpenSSL EVP.
// out_buf must have capacity >= plaintext_len + 16. *out_len receives the
// padded ciphertext length. Returns 0 on success, -1 on any EVP failure.
static int dr_aes_cbc_encrypt(unsigned char *out_buf, size_t *out_len,
                              const unsigned char *plaintext, size_t plaintext_len,
                              const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ok = 0;
    int len1 = 0, len2 = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) goto done;
    if (EVP_EncryptUpdate(ctx, out_buf, &len1,
                          plaintext, (int)plaintext_len) != 1) goto done;
    if (EVP_EncryptFinal_ex(ctx, out_buf + len1, &len2) != 1) goto done;
    *out_len = (size_t)(len1 + len2);
    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

// AES-256-CBC decrypt + PKCS#7 unpad. Caller has already verified the MAC, so
// padding-oracle exposure is closed: a tampered ciphertext fails the MAC and
// never reaches this function.
static int dr_aes_cbc_decrypt(unsigned char *out_buf, size_t *out_len,
                              const unsigned char *ciphertext, size_t ciphertext_len,
                              const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ok = 0;
    int len1 = 0, len2 = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, out_buf, &len1,
                          ciphertext, (int)ciphertext_len) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, out_buf + len1, &len2) != 1) goto done;
    *out_len = (size_t)(len1 + len2);
    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

// Compute the Signal-spec MAC: HMAC-SHA-256(mac_key, sender_id_pub(32) ||
// receiver_id_pub(32) || version(1) || serialized_message), truncated to the
// first 8 bytes (DR_MAC_LEN). Output buffer must be DR_MAC_LEN bytes.
static int dr_compute_mac(unsigned char *out_mac,
                          const unsigned char *mac_key,
                          const unsigned char *sender_id_pub,
                          const unsigned char *receiver_id_pub,
                          unsigned char version,
                          const unsigned char *serialized, size_t serialized_len) {
    unsigned char full_mac[32];
    unsigned int full_mac_len = 0;
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (!ctx) return -1;
    int ok = 0;
    if (HMAC_Init_ex(ctx, mac_key, 32, EVP_sha256(), NULL) != 1) goto done;
    if (HMAC_Update(ctx, sender_id_pub, 32) != 1) goto done;
    if (HMAC_Update(ctx, receiver_id_pub, 32) != 1) goto done;
    if (HMAC_Update(ctx, &version, 1) != 1) goto done;
    if (HMAC_Update(ctx, serialized, serialized_len) != 1) goto done;
    if (HMAC_Final(ctx, full_mac, &full_mac_len) != 1) goto done;
    if (full_mac_len < DR_MAC_LEN) goto done;
    memcpy(out_mac, full_mac, DR_MAC_LEN);
    ok = 1;
done:
    HMAC_CTX_free(ctx);
    sodium_memzero(full_mac, sizeof(full_mac));
    return ok ? 0 : -1;
}

// Advance chain key per Signal DR spec: chain_key' = HMAC-SHA-256(chain_key, 0x01).
static void advance_chain_key(unsigned char *chain_key,
                              const unsigned char *current_key) {
    unsigned char constant = 0x02;  // Signal spec: 0x02 for next chain key
    crypto_auth_hmacsha256(chain_key, &constant, 1, current_key);
}

// Derive message key per Signal DR spec: mk = HMAC-SHA-256(chain_key, 0x02).
// (Signal uses 0x01 for message key, 0x02 for chain advance. We were flipped;
// switching to the spec.)
static void derive_message_key(unsigned char *message_key,
                               const unsigned char *chain_key) {
    unsigned char constant = 0x01;
    crypto_auth_hmacsha256(message_key, &constant, 1, chain_key);
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
    
    // Perform raw X25519 DH with remote public key (Signal DR spec).
    unsigned char dh_output[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(dh_output, state->dh_send_private, remote_public_key) != 0) {
        return -1;
    }
    
    // KDF_RK: (new_root_key, new_chain_key) = HKDF-SHA-256(rk, dh_out, "DR-RK").
    unsigned char kdf_output[64];
    if (hkdf_sha256(kdf_output, 64, state->root_key, 32, dh_output, 32,
                    (const unsigned char *)"DR-RK", 5) != 0) {
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
    unsigned char dh_output[crypto_scalarmult_BYTES];
    unsigned char kdf_output[64];

    // Step 1: receive ratchet using CURRENT dh_send_private.
    if (crypto_scalarmult(dh_output, state->dh_send_private, remote_public_key) != 0) {
        return -1;
    }
    if (hkdf_sha256(kdf_output, 64, state->root_key, 32, dh_output, 32,
                    (const unsigned char *)"DR-RK", 5) != 0) {
        sodium_memzero(dh_output, sizeof(dh_output));
        return -1;
    }
    memcpy(state->root_key, kdf_output, 32);
    memcpy(state->recv_chain_key, kdf_output + 32, 32);

    // Step 2: generate new keypair and derive new send chain.
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
    if (hkdf_sha256(kdf_output, 64, state->root_key, 32, dh_output, 32,
                    (const unsigned char *)"DR-RK", 5) != 0) {
        sodium_memzero(dh_output, sizeof(dh_output));
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
    sodium_memzero(kdf_output, sizeof(kdf_output));
    return 0;
}
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

    if (shared_secret.size != 64) {
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

        // Initial send ratchet: KDF_RK(root, DH(alice_eph_priv, bob_pub))
        unsigned char dh_out[crypto_scalarmult_BYTES];
        if (crypto_scalarmult(dh_out, state.dh_send_private,
                              state.dh_recv_public) != 0) {
            sodium_memzero(&state, sizeof(state));
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "dh_failed"));
        }
        unsigned char kdf_out[64];
        if (hkdf_sha256(kdf_out, 64, state.root_key, 32, dh_out, 32,
                        (const unsigned char *)"DR-RK", 5) != 0) {
            sodium_memzero(dh_out, sizeof(dh_out));
            sodium_memzero(&state, sizeof(state));
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "kdf_failed"));
        }
        memcpy(state.root_key, kdf_out, 32);
        memcpy(state.send_chain_key, kdf_out + 32, 32);
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
    if (!state->initialized) return "session_not_initialized";
    // Bob cannot send before receiving Alice's first message -- his
    // send_chain_key is only derived during the receive ratchet.
    if (!state->dh_recv_initialized) return "must_receive_first";

    // Derive per-message keys: cipher_key(32) || mac_key(32) || iv(16)
    // from messageKey via HKDF (info="WhisperMessageKeys", Signal spec).
    unsigned char message_key[DR_MESSAGE_KEY_SIZE];
    derive_message_key(message_key, state->send_chain_key);
    unsigned char next_chain[DR_CHAIN_KEY_SIZE];
    advance_chain_key(next_chain, state->send_chain_key);

    unsigned char cipher_key[32], mac_key[32], iv[16];
    if (dr_derive_message_keys(cipher_key, mac_key, iv, message_key) != 0) {
        sodium_memzero(message_key, sizeof(message_key));
        sodium_memzero(next_chain, sizeof(next_chain));
        return "kdf_failed";
    }

    // AES-256-CBC + PKCS#7 encrypt. Output is always plaintext_len + 1..16.
    size_t cbc_buf_cap = pt_len + 16;
    unsigned char *cbc_buf = enif_alloc(cbc_buf_cap);
    if (!cbc_buf) {
        sodium_memzero(message_key, sizeof(message_key));
        sodium_memzero(next_chain, sizeof(next_chain));
        sodium_memzero(cipher_key, sizeof(cipher_key));
        sodium_memzero(mac_key, sizeof(mac_key));
        sodium_memzero(iv, sizeof(iv));
        return "memory_allocation_failed";
    }
    size_t cbc_len = 0;
    if (dr_aes_cbc_encrypt(cbc_buf, &cbc_len, pt, pt_len, cipher_key, iv) != 0) {
        enif_free(cbc_buf);
        sodium_memzero(message_key, sizeof(message_key));
        sodium_memzero(next_chain, sizeof(next_chain));
        sodium_memzero(cipher_key, sizeof(cipher_key));
        sodium_memzero(mac_key, sizeof(mac_key));
        sodium_memzero(iv, sizeof(iv));
        return "encryption_failed";
    }

    // Serialize the DrMessage protobuf. Header (fields 1-3) + ciphertext
    // (field 4). Max size: 46 (header) + 1 (tag) + 10 (varint) + cbc_len.
    unsigned char header[64];
    size_t header_len = dr_serialize_header(header, state->dh_send_public, 32,
                                            state->send_message_number,
                                            state->prev_send_length);
    unsigned char ct_len_varint[10];
    size_t ct_len_varint_len = pb_encode_varint(ct_len_varint, cbc_len);
    size_t proto_len = header_len + 1 + ct_len_varint_len + cbc_len;

    unsigned char *proto = enif_alloc(proto_len);
    if (!proto) {
        enif_free(cbc_buf);
        sodium_memzero(message_key, sizeof(message_key));
        sodium_memzero(next_chain, sizeof(next_chain));
        sodium_memzero(cipher_key, sizeof(cipher_key));
        sodium_memzero(mac_key, sizeof(mac_key));
        sodium_memzero(iv, sizeof(iv));
        return "memory_allocation_failed";
    }
    memcpy(proto, header, header_len);
    size_t p = header_len;
    proto[p++] = 0x22;  // (4 << 3) | 2: field 4, length-delimited (ciphertext)
    memcpy(proto + p, ct_len_varint, ct_len_varint_len);
    p += ct_len_varint_len;
    memcpy(proto + p, cbc_buf, cbc_len);
    enif_free(cbc_buf);

    // MAC over local_id_pub || remote_id_pub || version || protobuf.
    unsigned char mac[DR_MAC_LEN];
    if (dr_compute_mac(mac, mac_key,
                       state->local_identity_pub, state->remote_identity_pub,
                       DR_VERSION_BYTE, proto, proto_len) != 0) {
        enif_free(proto);
        sodium_memzero(message_key, sizeof(message_key));
        sodium_memzero(next_chain, sizeof(next_chain));
        sodium_memzero(cipher_key, sizeof(cipher_key));
        sodium_memzero(mac_key, sizeof(mac_key));
        sodium_memzero(iv, sizeof(iv));
        return "mac_failed";
    }

    // Assemble the wire envelope: version(1) || protobuf || mac(8).
    size_t wire_len = 1 + proto_len + DR_MAC_LEN;
    unsigned char *wire = enif_alloc(wire_len);
    if (!wire) {
        enif_free(proto);
        sodium_memzero(message_key, sizeof(message_key));
        sodium_memzero(next_chain, sizeof(next_chain));
        sodium_memzero(cipher_key, sizeof(cipher_key));
        sodium_memzero(mac_key, sizeof(mac_key));
        sodium_memzero(iv, sizeof(iv));
        return "memory_allocation_failed";
    }
    wire[0] = DR_VERSION_BYTE;
    memcpy(wire + 1, proto, proto_len);
    memcpy(wire + 1 + proto_len, mac, DR_MAC_LEN);
    enif_free(proto);

    // Advance state.
    memcpy(state->send_chain_key, next_chain, DR_CHAIN_KEY_SIZE);
    state->send_message_number++;

    sodium_memzero(message_key, sizeof(message_key));
    sodium_memzero(next_chain, sizeof(next_chain));
    sodium_memzero(cipher_key, sizeof(cipher_key));
    sodium_memzero(mac_key, sizeof(mac_key));
    sodium_memzero(iv, sizeof(iv));

    *out_wire = wire;
    *out_wire_len = wire_len;
    return NULL;
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
    
    // Copy state from binary
    double_ratchet_state_t state;
    memcpy(&state, dr_session.data, DR_STATE_SIZE);

    if (!state.initialized) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "session_not_initialized"));
    }

    // Envelope: version(1) || protobuf || mac(8).
    if (ciphertext.size < 1 + DR_MAC_LEN) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "message_too_short"));
    }
    if (ciphertext.data[0] != DR_VERSION_BYTE) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "unsupported_version"));
    }
    size_t proto_len = ciphertext.size - 1 - DR_MAC_LEN;
    const unsigned char *proto = ciphertext.data + 1;
    const unsigned char *received_mac = ciphertext.data + 1 + proto_len;

    // Parse the protobuf DrMessage.
    dr_message_t msg;
    if (dr_parse_message(proto, proto_len, &msg) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "malformed_message"));
    }
    if (msg.ratchet_key_len != crypto_box_PUBLICKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "invalid_ratchet_key"));
    }
    // AES-CBC ciphertext must be a positive multiple of the 16-byte block.
    if (msg.payload_len == 0 || (msg.payload_len % 16) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "message_too_short"));
    }

    const unsigned char *remote_dh_public = msg.ratchet_key;
    unsigned int prev_chain_length = msg.previous_counter;
    unsigned int message_number = msg.counter;

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

    // Derive per-message keys + verify MAC before touching the ciphertext.
    // MAC binding scope (Signal spec): receiver's own identity goes first
    // (it was the *sender's* "local" identity on the wire), then ours.
    unsigned char cipher_key[32], mac_key[32], iv[16];
    if (dr_derive_message_keys(cipher_key, mac_key, iv, message_key) != 0) {
        sodium_memzero(message_key, sizeof(message_key));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "kdf_failed"));
    }
    unsigned char expected_mac[DR_MAC_LEN];
    if (dr_compute_mac(expected_mac, mac_key,
                       state.remote_identity_pub, state.local_identity_pub,
                       DR_VERSION_BYTE, proto, proto_len) != 0) {
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

    // AES-CBC decrypt + PKCS#7 unpad. EVP_DecryptFinal validates padding,
    // but we already verified the MAC so a padding-oracle channel is closed.
    unsigned char *pt_buf = enif_alloc(msg.payload_len);
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
                           msg.payload, msg.payload_len,
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
    sodium_memzero(pt_buf, msg.payload_len);
    enif_free(pt_buf);
    sodium_memzero(cipher_key, sizeof(cipher_key));
    sodium_memzero(mac_key, sizeof(mac_key));
    sodium_memzero(iv, sizeof(iv));
    
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

