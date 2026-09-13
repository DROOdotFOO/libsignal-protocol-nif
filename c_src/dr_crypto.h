#ifndef LIBSIGNAL_DR_CRYPTO_H
#define LIBSIGNAL_DR_CRYPTO_H

#include <stddef.h>
#include "dr_proto.h"

// Signal-spec MAC truncation: HMAC-SHA-256 output keeps only the first 8 bytes.
#define DR_MAC_LEN 8

// DR-HE enc_header wire layout: iv(16) || AES-256-CBC(inner header).
// The inner header protobuf is tag(1)+len(1)+ratchet_key(32) + tag(1)+
// varint(1..5) + tag(1)+varint(1..5) = 38..46 bytes; PKCS#7 pads every
// length in that range to one 48-byte ciphertext, so enc_header is always
// exactly 64 bytes. The receiver rejects any other length before decrypting
// and the sender refuses to emit one, so a header-format change that breaks
// this arithmetic fails loudly (static assert below) rather than desyncing.
#define DR_INNER_HEADER_MIN 38
#define DR_INNER_HEADER_MAX 46
#define DR_HEADER_IV_LEN 16
#define DR_HEADER_CT_LEN 48
#define DR_ENC_HEADER_LEN (DR_HEADER_IV_LEN + DR_HEADER_CT_LEN)
_Static_assert(DR_INNER_HEADER_MIN >= DR_HEADER_CT_LEN - 16 &&
               DR_INNER_HEADER_MAX < DR_HEADER_CT_LEN,
               "inner header must PKCS#7-pad to exactly DR_HEADER_CT_LEN bytes");
// Output capacity a caller must give dr_try_decrypt_header: OpenSSL documents
// EVP_DecryptUpdate as needing inl + block_size bytes of room.
#define DR_HEADER_PLAIN_CAP (DR_HEADER_CT_LEN + 16)

// HKDF-SHA-256 (RFC 5869). Shared between DR (KDF_RK) and X3DH (root seed).
int hkdf_sha256(unsigned char *output, size_t output_len,
                const unsigned char *salt, size_t salt_len,
                const unsigned char *ikm, size_t ikm_len,
                const unsigned char *info, size_t info_len);

// Expand a 32B message key into the per-message Signal triplet
// (cipher_key, mac_key, iv) via HKDF-SHA-256.
int dr_derive_message_keys(unsigned char *cipher_key,
                           unsigned char *mac_key,
                           unsigned char *iv,
                           const unsigned char *message_key);

// DR-HE header cipher-key derivation (32B output, info="WhisperHeader").
int dr_derive_header_cipher_key(unsigned char *cipher_key,
                                const unsigned char *header_key);

// AES-256-CBC encrypt with PKCS#7 padding via OpenSSL EVP.
// out_buf must have capacity >= plaintext_len + 16.
int dr_aes_cbc_encrypt(unsigned char *out_buf, size_t *out_len,
                       const unsigned char *plaintext, size_t plaintext_len,
                       const unsigned char *key, const unsigned char *iv);

// AES-256-CBC decrypt + PKCS#7 unpad. Caller must have verified the MAC first.
int dr_aes_cbc_decrypt(unsigned char *out_buf, size_t *out_len,
                       const unsigned char *ciphertext, size_t ciphertext_len,
                       const unsigned char *key, const unsigned char *iv);

// Trial-decrypt enc_header (`iv(16) || aes_cbc_ciphertext`) under a candidate
// header_key. Rejects enc_header_len != DR_ENC_HEADER_LEN and any ciphertext
// larger than out_plain_cap before touching the cipher. On valid PKCS#7 unpad
// AND successful inner-header protobuf parse, fills *out_msg and returns 0.
// Returns -1 on any failure.
int dr_try_decrypt_header(unsigned char *out_plain,
                          size_t out_plain_cap,
                          size_t *out_plain_len,
                          dr_message_t *out_msg,
                          const unsigned char *enc_header,
                          size_t enc_header_len,
                          const unsigned char *header_key);

// Compute the Signal-spec MAC: HMAC-SHA-256(mac_key, sender_id_pub(32) ||
// receiver_id_pub(32) || version(1) || serialized), truncated to 8 bytes.
// out_mac must be 8 bytes.
int dr_compute_mac(unsigned char *out_mac,
                   const unsigned char *mac_key,
                   const unsigned char *sender_id_pub,
                   const unsigned char *receiver_id_pub,
                   unsigned char version,
                   const unsigned char *serialized, size_t serialized_len);

#endif
