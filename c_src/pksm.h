#ifndef LIBSIGNAL_PKSM_H
#define LIBSIGNAL_PKSM_H

#include <erl_nif.h>
#include <stddef.h>
#include <stdint.h>

// PreKeySignalMessage (Signal protocol). Wire envelope is
// `version_byte(0x33) || protobuf`. The protobuf body schema:
//
//   PreKeySignalMessage {
//       uint32 registration_id    = 1;   // varint
//       bytes  base_key           = 2;   // Alice's X3DH ephemeral pub (32B)
//       bytes  identity_key       = 3;   // Alice's X25519 identity pub (32B)
//       uint32 pre_key_id         = 4;   // optional one-time-prekey id
//       uint32 signed_pre_key_id  = 5;
//       bytes  message            = 6;   // serialized inner SignalMessage
//   }
//
// Encoders/decoders here work on the protobuf body only; the version byte
// is owned by the NIF entry points (dr_encrypt_prekey / pksm_decode).

typedef struct {
    uint32_t registration_id;
    const unsigned char *base_key;
    size_t base_key_len;
    const unsigned char *identity_key;
    size_t identity_key_len;
    uint32_t pre_key_id;
    int has_pre_key_id;
    uint32_t signed_pre_key_id;
    const unsigned char *message;
    size_t message_len;
} pksm_t;

// Serialize the protobuf body. Writes at most out_cap bytes to out and
// returns the number written, or -1 on overflow. Pass has_pre_key_id=0 to
// omit field 4 (Alice didn't use an OPK). All other fields are required.
int pksm_encode(unsigned char *out, size_t out_cap,
                uint32_t registration_id,
                const unsigned char *base_key, size_t base_key_len,
                const unsigned char *identity_key, size_t identity_key_len,
                uint32_t pre_key_id, int has_pre_key_id,
                uint32_t signed_pre_key_id,
                const unsigned char *inner_message, size_t inner_message_len);

// Parse a protobuf body. Pointers in *out reference the input buffer (no
// copies). Returns 0 on success, -1 on any malformation (truncation,
// duplicate field, unknown wire type, missing required field).
int pksm_decode(const unsigned char *in, size_t in_len, pksm_t *out);

// NIF entry: decode wire envelope and return
//   {ok, {RegistrationId, BaseKey, IdentityKey, PreKeyIdOrUndefined,
//         SignedPreKeyId, InnerMessage}}.
// On any malformation returns {error, malformed_message}.
ERL_NIF_TERM pksm_decode_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

#endif
