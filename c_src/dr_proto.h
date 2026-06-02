#ifndef LIBSIGNAL_DR_PROTO_H
#define LIBSIGNAL_DR_PROTO_H

#include <stddef.h>
#include <stdint.h>

// Inner DrMessage wire form (fields 1-3 are the header; field 4 carries the
// AEAD-encrypted body). See dr_proto.c for the full schema.
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

// Protobuf varint decode. Sets *value and *consumed. Returns 0 on success,
// -1 on truncation or overflow (>10 bytes).
int pb_decode_varint(const unsigned char *in, size_t in_len,
                     uint64_t *value, size_t *consumed);

// Serialize DrMessage fields 1-3 only (the "header"). Returns bytes written.
// `out` must have capacity >= 1+10 + ratchet_key_len + 1+10 + 1+10 (max 55).
size_t dr_serialize_header(unsigned char *out,
                           const unsigned char *ratchet_key,
                           size_t ratchet_key_len,
                           uint32_t counter,
                           uint32_t previous_counter);

// Serialize the outer DrEnvelope: {enc_header=1, ciphertext=2}.
// Returns bytes written.
// out must have capacity >= 2 + 2*10 + enc_header_len + ciphertext_len.
size_t dr_serialize_envelope(unsigned char *out,
                             const unsigned char *enc_header,
                             size_t enc_header_len,
                             const unsigned char *ciphertext,
                             size_t ciphertext_len);

// Parse a serialized DrEnvelope. Output pointers reference the input buffer.
// Returns 0 on success, -1 on any malformation.
int dr_parse_envelope(const unsigned char *in, size_t in_len,
                      const unsigned char **out_enc_header,
                      size_t *out_enc_header_len,
                      const unsigned char **out_ciphertext,
                      size_t *out_ciphertext_len);

#endif
