#ifndef LIBSIGNAL_SESSION_H
#define LIBSIGNAL_SESSION_H

#include <erl_nif.h>

ERL_NIF_TERM process_pre_key_bundle(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM process_pre_key_bundle_bob(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

#endif
