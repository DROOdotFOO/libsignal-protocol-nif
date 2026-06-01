#include "pksm.h"
#include <string.h>

#define PKSM_VERSION_BYTE 0x33

// Encode an unsigned 64-bit value as protobuf varint. Buffer must have at
// least 10 bytes. Returns bytes written.
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

int pksm_encode(unsigned char *out, size_t out_cap,
                uint32_t registration_id,
                const unsigned char *base_key, size_t base_key_len,
                const unsigned char *identity_key, size_t identity_key_len,
                uint32_t pre_key_id, int has_pre_key_id,
                uint32_t signed_pre_key_id,
                const unsigned char *inner_message, size_t inner_message_len)
{
    size_t n = 0;
    unsigned char vbuf[10];
    size_t vlen;

    // field 1: registration_id (varint)
    if (n + 1 > out_cap) return -1;
    out[n++] = 0x08;  // (1<<3) | 0
    vlen = pb_encode_varint(vbuf, registration_id);
    if (n + vlen > out_cap) return -1;
    memcpy(out + n, vbuf, vlen);
    n += vlen;

    // field 2: base_key (length-delimited)
    if (n + 1 > out_cap) return -1;
    out[n++] = 0x12;  // (2<<3) | 2
    vlen = pb_encode_varint(vbuf, base_key_len);
    if (n + vlen + base_key_len > out_cap) return -1;
    memcpy(out + n, vbuf, vlen);
    n += vlen;
    memcpy(out + n, base_key, base_key_len);
    n += base_key_len;

    // field 3: identity_key (length-delimited)
    if (n + 1 > out_cap) return -1;
    out[n++] = 0x1A;  // (3<<3) | 2
    vlen = pb_encode_varint(vbuf, identity_key_len);
    if (n + vlen + identity_key_len > out_cap) return -1;
    memcpy(out + n, vbuf, vlen);
    n += vlen;
    memcpy(out + n, identity_key, identity_key_len);
    n += identity_key_len;

    // field 4: pre_key_id (varint, optional)
    if (has_pre_key_id) {
        if (n + 1 > out_cap) return -1;
        out[n++] = 0x20;  // (4<<3) | 0
        vlen = pb_encode_varint(vbuf, pre_key_id);
        if (n + vlen > out_cap) return -1;
        memcpy(out + n, vbuf, vlen);
        n += vlen;
    }

    // field 5: signed_pre_key_id (varint)
    if (n + 1 > out_cap) return -1;
    out[n++] = 0x28;  // (5<<3) | 0
    vlen = pb_encode_varint(vbuf, signed_pre_key_id);
    if (n + vlen > out_cap) return -1;
    memcpy(out + n, vbuf, vlen);
    n += vlen;

    // field 6: message (length-delimited)
    if (n + 1 > out_cap) return -1;
    out[n++] = 0x32;  // (6<<3) | 2
    vlen = pb_encode_varint(vbuf, inner_message_len);
    if (n + vlen + inner_message_len > out_cap) return -1;
    memcpy(out + n, vbuf, vlen);
    n += vlen;
    memcpy(out + n, inner_message, inner_message_len);
    n += inner_message_len;

    return (int)n;
}

int pksm_decode(const unsigned char *in, size_t in_len, pksm_t *out)
{
    memset(out, 0, sizeof(*out));
    int seen_reg = 0, seen_base = 0, seen_id = 0, seen_spk = 0, seen_msg = 0;
    size_t pos = 0;

    while (pos < in_len) {
        uint64_t tag = 0;
        size_t consumed = 0;
        if (pb_decode_varint(in + pos, in_len - pos, &tag, &consumed) != 0)
            return -1;
        pos += consumed;
        uint32_t field_number = (uint32_t)(tag >> 3);
        uint32_t wire_type = (uint32_t)(tag & 0x07);

        if (field_number == 1 && wire_type == 0) {
            if (seen_reg) return -1;
            uint64_t v = 0;
            if (pb_decode_varint(in + pos, in_len - pos, &v, &consumed) != 0)
                return -1;
            pos += consumed;
            if (v > UINT32_MAX) return -1;
            out->registration_id = (uint32_t)v;
            seen_reg = 1;
        } else if (field_number == 2 && wire_type == 2) {
            if (seen_base) return -1;
            uint64_t len = 0;
            if (pb_decode_varint(in + pos, in_len - pos, &len, &consumed) != 0)
                return -1;
            pos += consumed;
            if (len > in_len - pos) return -1;
            out->base_key = in + pos;
            out->base_key_len = (size_t)len;
            pos += (size_t)len;
            seen_base = 1;
        } else if (field_number == 3 && wire_type == 2) {
            if (seen_id) return -1;
            uint64_t len = 0;
            if (pb_decode_varint(in + pos, in_len - pos, &len, &consumed) != 0)
                return -1;
            pos += consumed;
            if (len > in_len - pos) return -1;
            out->identity_key = in + pos;
            out->identity_key_len = (size_t)len;
            pos += (size_t)len;
            seen_id = 1;
        } else if (field_number == 4 && wire_type == 0) {
            if (out->has_pre_key_id) return -1;
            uint64_t v = 0;
            if (pb_decode_varint(in + pos, in_len - pos, &v, &consumed) != 0)
                return -1;
            pos += consumed;
            if (v > UINT32_MAX) return -1;
            out->pre_key_id = (uint32_t)v;
            out->has_pre_key_id = 1;
        } else if (field_number == 5 && wire_type == 0) {
            if (seen_spk) return -1;
            uint64_t v = 0;
            if (pb_decode_varint(in + pos, in_len - pos, &v, &consumed) != 0)
                return -1;
            pos += consumed;
            if (v > UINT32_MAX) return -1;
            out->signed_pre_key_id = (uint32_t)v;
            seen_spk = 1;
        } else if (field_number == 6 && wire_type == 2) {
            if (seen_msg) return -1;
            uint64_t len = 0;
            if (pb_decode_varint(in + pos, in_len - pos, &len, &consumed) != 0)
                return -1;
            pos += consumed;
            if (len > in_len - pos) return -1;
            out->message = in + pos;
            out->message_len = (size_t)len;
            pos += (size_t)len;
            seen_msg = 1;
        } else {
            return -1;
        }
    }

    if (!seen_reg || !seen_base || !seen_id || !seen_spk || !seen_msg)
        return -1;
    return 0;
}

ERL_NIF_TERM pksm_decode_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 1) {
        return enif_make_badarg(env);
    }
    ErlNifBinary wire;
    if (!enif_inspect_binary(env, argv[0], &wire)) {
        return enif_make_badarg(env);
    }
    if (wire.size < 1 || wire.data[0] != PKSM_VERSION_BYTE) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "malformed_message"));
    }

    pksm_t msg;
    if (pksm_decode(wire.data + 1, wire.size - 1, &msg) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "malformed_message"));
    }

    ERL_NIF_TERM base_term, id_term, inner_term;
    unsigned char *base_buf = enif_make_new_binary(env, msg.base_key_len, &base_term);
    memcpy(base_buf, msg.base_key, msg.base_key_len);
    unsigned char *id_buf = enif_make_new_binary(env, msg.identity_key_len, &id_term);
    memcpy(id_buf, msg.identity_key, msg.identity_key_len);
    unsigned char *inner_buf = enif_make_new_binary(env, msg.message_len, &inner_term);
    memcpy(inner_buf, msg.message, msg.message_len);

    ERL_NIF_TERM opk_term = msg.has_pre_key_id
        ? enif_make_uint(env, msg.pre_key_id)
        : enif_make_atom(env, "undefined");

    ERL_NIF_TERM result = enif_make_tuple6(env,
        enif_make_uint(env, msg.registration_id),
        base_term,
        id_term,
        opk_term,
        enif_make_uint(env, msg.signed_pre_key_id),
        inner_term);

    return enif_make_tuple2(env, enif_make_atom(env, "ok"), result);
}
