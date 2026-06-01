#include <erl_nif.h>
#include <stdlib.h>
#include <time.h>

#include "dr.h"
#include "keys.h"
#include "session.h"

static ERL_NIF_TERM init_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    return enif_make_atom(env, "ok");
}

// Define the NIF function array
static ErlNifFunc nif_funcs[] = {
    {"init", 0, init_nif, 0},
    {"generate_identity_key_pair", 0, generate_identity_key_pair, 0},
    {"generate_pre_key", 1, generate_pre_key, 0},
    {"generate_signed_pre_key", 2, generate_signed_pre_key, 0},
    {"create_session", 2, create_session_2, 0},
    {"process_pre_key_bundle", 2, process_pre_key_bundle, 0},
    {"encrypt_message", 2, encrypt_message, 0},
    {"decrypt_message", 2, decrypt_message, 0},
    {"dr_init", 4, dr_init, 0},
    {"dr_encrypt", 2, dr_encrypt, 0},
    {"dr_decrypt", 2, dr_decrypt, 0}
};

static int on_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    // Initialize random seed
    srand((unsigned int)time(NULL));
    return 0;
}

static void on_unload(ErlNifEnv *env, void *priv_data)
{
}

// Initialize the NIF library
ERL_NIF_INIT(libsignal_protocol_nif, nif_funcs, on_load, NULL, NULL, on_unload) 