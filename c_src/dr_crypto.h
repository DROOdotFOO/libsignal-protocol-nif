#ifndef LIBSIGNAL_DR_CRYPTO_H
#define LIBSIGNAL_DR_CRYPTO_H

#include <stddef.h>
#include "dr_proto.h"

// Signal-spec MAC truncation: HMAC-SHA-256 output keeps only the first 8 bytes.
#define DR_MAC_LEN 8

// DR-HE enc_header wire layout: iv(16) || AES-256-CBC(inner header) || tag(16).
// The inner header protobuf is tag(1)+len(1)+ratchet_key(32) + tag(1)+
// varint(1..5) + tag(1)+varint(1..5) = 38..46 bytes; PKCS#7 pads every
// length in that range to one 48-byte ciphertext, so enc_header is always
// exactly 80 bytes. The tag is HMAC-SHA-256(header_mac_key, iv || ct)
// truncated to 16 bytes and is verified before any decryption, so a forged
// header costs the receiver one HMAC per candidate key and nothing else.
// The receiver rejects any other length before touching a key and the
// sender refuses to emit one, so a header-format change that breaks this
// arithmetic fails loudly (static assert below) rather than desyncing.
#define DR_INNER_HEADER_MIN 38
#define DR_INNER_HEADER_MAX 46
#define DR_HEADER_IV_LEN 16
#define DR_HEADER_CT_LEN 48
#define DR_HEADER_TAG_LEN 16
#define DR_ENC_HEADER_LEN (DR_HEADER_IV_LEN + DR_HEADER_CT_LEN + DR_HEADER_TAG_LEN)
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

// Seal an inner header under header_key: out receives exactly
// DR_ENC_HEADER_LEN bytes (`iv(16) || AES-256-CBC(ct) || tag(16)`) with a
// fresh random IV. Returns 0 on success, -1 on KDF/cipher/MAC failure or if
// the padded ciphertext is not DR_HEADER_CT_LEN (inner_len out of range).
int dr_seal_header(unsigned char *out,
                   const unsigned char *header_key,
                   const unsigned char *inner, size_t inner_len);

// AES-256-CBC encrypt with PKCS#7 padding via OpenSSL EVP.
// out_buf must have capacity >= plaintext_len + 16.
int dr_aes_cbc_encrypt(unsigned char *out_buf, size_t *out_len,
                       const unsigned char *plaintext, size_t plaintext_len,
                       const unsigned char *key, const unsigned char *iv);

// AES-256-CBC decrypt + PKCS#7 unpad. Caller must have verified the MAC first.
// out_buf must have capacity >= ciphertext_len + 16: EVP_DecryptUpdate may
// emit up to inl bytes and EVP_DecryptFinal_ex up to one more block before
// the padding is stripped.
int dr_aes_cbc_decrypt(unsigned char *out_buf, size_t *out_len,
                       const unsigned char *ciphertext, size_t ciphertext_len,
                       const unsigned char *key, const unsigned char *iv);

// Trial-open enc_header under a candidate header_key. Rejects
// enc_header_len != DR_ENC_HEADER_LEN and any ciphertext larger than
// out_plain_cap, then verifies the header tag with sodium_memcmp *before*
// running AES-CBC. On a valid tag, PKCS#7 unpad, and successful
// inner-header protobuf parse, fills *out_msg and returns 0. Returns -1 on
// any failure; a wrong key is indistinguishable from a forged header.
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
