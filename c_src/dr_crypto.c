#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <sodium.h>
#include <openssl/evp.h>
#include "dr.h"
#include "dr_crypto.h"
#include "dr_proto.h"

// HKDF-SHA-256 (RFC 5869). Caller provides salt (use zero-filled 32 bytes if
// none), input keying material (IKM), info, and the desired output length.
// Produces N=ceil(L/32) HMAC blocks; callers request up to L=96 (three).
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
int dr_derive_message_keys(unsigned char *cipher_key,
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

// DR-HE header key derivation. One HKDF call yields the header cipher key
// and the header MAC key (info="WhisperHeader", L=64). The IV is NOT
// derived: the same header_key is reused across every message in a chain,
// so a deterministic IV would reveal that two messages share a leading
// plaintext block (the inner header's first 16 bytes are the ratchet_key
// prefix, invariant within a chain). A fresh random IV is generated per
// seal and shipped with the ciphertext.
static int dr_derive_header_keys(unsigned char *cipher_key,
                                 unsigned char *mac_key,
                                 const unsigned char *header_key) {
    unsigned char salt[32] = {0};
    unsigned char out[64];
    if (hkdf_sha256(out, sizeof(out), salt, sizeof(salt),
                    header_key, DR_HEADER_KEY_SIZE,
                    (const unsigned char *)"WhisperHeader",
                    sizeof("WhisperHeader") - 1) != 0) {
        sodium_memzero(out, sizeof(out));
        return -1;
    }
    memcpy(cipher_key, out, 32);
    memcpy(mac_key, out + 32, 32);
    sodium_memzero(out, sizeof(out));
    return 0;
}

// tag = HMAC-SHA-256(mac_key, iv || ct)[0..DR_HEADER_TAG_LEN). `iv_and_ct`
// is the first DR_HEADER_IV_LEN + DR_HEADER_CT_LEN bytes of an enc_header.
static int dr_header_tag(unsigned char *out_tag,
                         const unsigned char *mac_key,
                         const unsigned char *iv_and_ct) {
    unsigned char full[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state st;
    int ok = crypto_auth_hmacsha256_init(&st, mac_key, 32) == 0 &&
             crypto_auth_hmacsha256_update(&st, iv_and_ct,
                                           DR_HEADER_IV_LEN + DR_HEADER_CT_LEN) == 0 &&
             crypto_auth_hmacsha256_final(&st, full) == 0;
    if (ok) memcpy(out_tag, full, DR_HEADER_TAG_LEN);
    sodium_memzero(&st, sizeof(st));
    sodium_memzero(full, sizeof(full));
    return ok ? 0 : -1;
}

int dr_seal_header(unsigned char *out,
                   const unsigned char *header_key,
                   const unsigned char *inner, size_t inner_len) {
    unsigned char hcipher[32], hmac[32];
    size_t ct_len = 0;
    int ok = 0;
    if (inner_len < DR_INNER_HEADER_MIN || inner_len > DR_INNER_HEADER_MAX) return -1;
    if (dr_derive_header_keys(hcipher, hmac, header_key) != 0) goto done;
    randombytes_buf(out, DR_HEADER_IV_LEN);
    if (dr_aes_cbc_encrypt(out + DR_HEADER_IV_LEN, &ct_len, inner, inner_len,
                           hcipher, out) != 0) goto done;
    if (ct_len != DR_HEADER_CT_LEN) goto done;
    if (dr_header_tag(out + DR_HEADER_IV_LEN + DR_HEADER_CT_LEN, hmac, out) != 0) goto done;
    ok = 1;
done:
    sodium_memzero(hcipher, sizeof(hcipher));
    sodium_memzero(hmac, sizeof(hmac));
    return ok ? 0 : -1;
}

// AES-256-CBC encrypt with PKCS#7 padding via OpenSSL EVP.
// out_buf must have capacity >= plaintext_len + 16. *out_len receives the
// padded ciphertext length. Returns 0 on success, -1 on any EVP failure.
int dr_aes_cbc_encrypt(unsigned char *out_buf, size_t *out_len,
                       const unsigned char *plaintext, size_t plaintext_len,
                       const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ok = 0;
    int len1 = 0, len2 = 0;
    if (plaintext_len > INT_MAX) goto done;
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
int dr_aes_cbc_decrypt(unsigned char *out_buf, size_t *out_len,
                       const unsigned char *ciphertext, size_t ciphertext_len,
                       const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ok = 0;
    int len1 = 0, len2 = 0;
    if (ciphertext_len > INT_MAX) goto done;
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

// Trial-open enc_header under a candidate header_key.
//
// enc_header_len is attacker-controlled (it comes straight out of the outer
// envelope protobuf, before the outer MAC is checked), so it is pinned to the
// one length a legitimate sender can produce and additionally bounded by the
// caller's output capacity before any cipher call. The header tag is then
// verified in constant time; only a header that authenticates under this
// key is CBC-decrypted, so a forged or wrong-key header costs one HKDF and
// one HMAC and reveals nothing about padding or structure.
//
// On a valid tag, PKCS#7 unpad, and successful inner-header protobuf parse
// (3 expected fields, 32B ratchet_key), fills *out and returns 0. Returns
// -1 on any failure.
int dr_try_decrypt_header(unsigned char *out_plain,
                          size_t out_plain_cap,
                          size_t *out_plain_len,
                          dr_message_t *out_msg,
                          const unsigned char *enc_header,
                          size_t enc_header_len,
                          const unsigned char *header_key) {
    if (enc_header_len != DR_ENC_HEADER_LEN) return -1;
    if (DR_HEADER_CT_LEN + 16 > out_plain_cap) return -1;
    const unsigned char *iv = enc_header;
    const unsigned char *ciphertext = enc_header + DR_HEADER_IV_LEN;
    const unsigned char *tag = enc_header + DR_HEADER_IV_LEN + DR_HEADER_CT_LEN;

    unsigned char hcipher[32], hmac[32], expected[DR_HEADER_TAG_LEN];
    size_t pt_len = 0;
    int rc = -1;
    if (dr_derive_header_keys(hcipher, hmac, header_key) != 0) goto done;
    if (dr_header_tag(expected, hmac, enc_header) != 0) goto done;
    if (sodium_memcmp(expected, tag, DR_HEADER_TAG_LEN) != 0) goto done;
    rc = dr_aes_cbc_decrypt(out_plain, &pt_len, ciphertext, DR_HEADER_CT_LEN,
                            hcipher, iv);
done:
    sodium_memzero(hcipher, sizeof(hcipher));
    sodium_memzero(hmac, sizeof(hmac));
    sodium_memzero(expected, sizeof(expected));
    if (rc != 0) return -1;

    // Reject false positives: the decrypted bytes must parse as the inner
    // header protobuf (fields 1-3 only; no payload field) with a 32B
    // ratchet_key.
    memset(out_msg, 0, sizeof(*out_msg));
    size_t pos = 0;
    while (pos < pt_len) {
        uint64_t tag = 0;
        size_t consumed = 0;
        if (pb_decode_varint(out_plain + pos, pt_len - pos,
                             &tag, &consumed) != 0) return -1;
        pos += consumed;
        uint32_t field_number = (uint32_t)(tag >> 3);
        uint32_t wire_type = (uint32_t)(tag & 0x07);
        if (field_number == 1 && wire_type == 2) {
            if (out_msg->seen_ratchet_key) return -1;
            uint64_t len = 0;
            if (pb_decode_varint(out_plain + pos, pt_len - pos,
                                 &len, &consumed) != 0) return -1;
            pos += consumed;
            if (len > pt_len - pos) return -1;
            out_msg->ratchet_key = out_plain + pos;
            out_msg->ratchet_key_len = (size_t)len;
            pos += (size_t)len;
            out_msg->seen_ratchet_key = 1;
        } else if (field_number == 2 && wire_type == 0) {
            if (out_msg->seen_counter) return -1;
            uint64_t v = 0;
            if (pb_decode_varint(out_plain + pos, pt_len - pos,
                                 &v, &consumed) != 0) return -1;
            pos += consumed;
            if (v > UINT32_MAX) return -1;
            out_msg->counter = (uint32_t)v;
            out_msg->seen_counter = 1;
        } else if (field_number == 3 && wire_type == 0) {
            if (out_msg->seen_previous_counter) return -1;
            uint64_t v = 0;
            if (pb_decode_varint(out_plain + pos, pt_len - pos,
                                 &v, &consumed) != 0) return -1;
            pos += consumed;
            if (v > UINT32_MAX) return -1;
            out_msg->previous_counter = (uint32_t)v;
            out_msg->seen_previous_counter = 1;
        } else {
            return -1;
        }
    }
    if (!out_msg->seen_ratchet_key || !out_msg->seen_counter ||
        !out_msg->seen_previous_counter) return -1;
    if (out_msg->ratchet_key_len != crypto_box_PUBLICKEYBYTES) return -1;
    *out_plain_len = pt_len;
    return 0;
}

// Compute the Signal-spec MAC: HMAC-SHA-256(mac_key, sender_id_pub(32) ||
// receiver_id_pub(32) || version(1) || serialized_message), truncated to the
// first 8 bytes. libsodium's streaming HMAC is used (same primitive hkdf_sha256
// already relies on); it needs no per-call algorithm fetch or provider lock,
// unlike OpenSSL's EVP_MAC API.
int dr_compute_mac(unsigned char *out_mac,
                   const unsigned char *mac_key,
                   const unsigned char *sender_id_pub,
                   const unsigned char *receiver_id_pub,
                   unsigned char version,
                   const unsigned char *serialized, size_t serialized_len) {
    unsigned char full_mac[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state st;
    int ok = crypto_auth_hmacsha256_init(&st, mac_key, 32) == 0 &&
             crypto_auth_hmacsha256_update(&st, sender_id_pub, 32) == 0 &&
             crypto_auth_hmacsha256_update(&st, receiver_id_pub, 32) == 0 &&
             crypto_auth_hmacsha256_update(&st, &version, 1) == 0 &&
             crypto_auth_hmacsha256_update(&st, serialized, serialized_len) == 0 &&
             crypto_auth_hmacsha256_final(&st, full_mac) == 0;
    if (ok) memcpy(out_mac, full_mac, DR_MAC_LEN);
    sodium_memzero(&st, sizeof(st));
    sodium_memzero(full_mac, sizeof(full_mac));
    return ok ? 0 : -1;
}
