#include <string.h>
#include <stdint.h>
#include <limits.h>
#include "dr_proto.h"

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

int pb_decode_varint(const unsigned char *in, size_t in_len,
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

size_t dr_serialize_header(unsigned char *out,
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

int dr_parse_message(const unsigned char *in, size_t in_len,
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

// ============================================================================
// DR-HE outer envelope protobuf (wraps the encrypted header + ciphertext).
//
//   message DrEnvelope {
//     bytes enc_header = 1;  // AES-256-CBC over the inner DrMessage header
//                            //  (ratchet_key, counter, previous_counter)
//     bytes ciphertext = 2;  // AES-256-CBC over the message body
//   }
//
// The outer MAC covers `local_id || remote_id || version || serialized DrEnvelope`.
// ============================================================================

size_t dr_serialize_envelope(unsigned char *out,
                             const unsigned char *enc_header,
                             size_t enc_header_len,
                             const unsigned char *ciphertext,
                             size_t ciphertext_len) {
    size_t n = 0;
    out[n++] = 0x0A;  // (1 << 3) | 2: field 1, length-delimited (enc_header)
    n += pb_encode_varint(out + n, enc_header_len);
    memcpy(out + n, enc_header, enc_header_len);
    n += enc_header_len;
    out[n++] = 0x12;  // (2 << 3) | 2: field 2, length-delimited (ciphertext)
    n += pb_encode_varint(out + n, ciphertext_len);
    memcpy(out + n, ciphertext, ciphertext_len);
    n += ciphertext_len;
    return n;
}

int dr_parse_envelope(const unsigned char *in, size_t in_len,
                      const unsigned char **out_enc_header,
                      size_t *out_enc_header_len,
                      const unsigned char **out_ciphertext,
                      size_t *out_ciphertext_len) {
    *out_enc_header = NULL;
    *out_enc_header_len = 0;
    *out_ciphertext = NULL;
    *out_ciphertext_len = 0;
    int seen_eh = 0, seen_ct = 0;
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
            if (seen_eh) return -1;
            uint64_t len = 0;
            if (pb_decode_varint(in + pos, in_len - pos, &len, &consumed) != 0)
                return -1;
            pos += consumed;
            if (len > in_len - pos) return -1;
            *out_enc_header = in + pos;
            *out_enc_header_len = (size_t)len;
            pos += (size_t)len;
            seen_eh = 1;
        } else if (field_number == 2 && wire_type == 2) {
            if (seen_ct) return -1;
            uint64_t len = 0;
            if (pb_decode_varint(in + pos, in_len - pos, &len, &consumed) != 0)
                return -1;
            pos += consumed;
            if (len > in_len - pos) return -1;
            *out_ciphertext = in + pos;
            *out_ciphertext_len = (size_t)len;
            pos += (size_t)len;
            seen_ct = 1;
        } else {
            return -1;
        }
    }
    if (!seen_eh || !seen_ct) return -1;
    return 0;
}
