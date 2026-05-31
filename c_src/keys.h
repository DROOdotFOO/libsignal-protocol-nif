#ifndef LIBSIGNAL_KEYS_H
#define LIBSIGNAL_KEYS_H

#include <erl_nif.h>

ERL_NIF_TERM generate_identity_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM generate_pre_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM generate_signed_pre_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

#endif
