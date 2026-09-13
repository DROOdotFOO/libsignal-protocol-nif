#include <erl_nif.h>
#include <sodium.h>

#include "dr.h"
#include "keys.h"
#include "pksm.h"
#include "session.h"

// libsodium is initialised in on_load (below); by the time any NIF in this
// table is callable it has already succeeded, so init/0 is a no-op kept for
// API compatibility. Calling it is harmless and idempotent.
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
    {"process_pre_key_bundle_bob", 5, process_pre_key_bundle_bob, 0},
    {"encrypt_message", 2, encrypt_message, 0},
    {"decrypt_message", 2, decrypt_message, 0},
    {"dr_init", 5, dr_init, 0},
    {"dr_encrypt", 2, dr_encrypt, 0},
    {"dr_encrypt_prekey", 3, dr_encrypt_prekey, 0},
    {"dr_decrypt", 2, dr_decrypt, 0},
    {"pksm_decode", 1, pksm_decode_nif, 0}
};

// This library is loaded independently of signal_nif (the Elixir wrapper
// never loads signal_nif at all), so it must initialise libsodium itself:
// randombytes_buf, crypto_box_keypair and the CPU-feature dispatch all
// depend on it. sodium_init() is idempotent and safe to call from both
// libraries. Returning non-zero makes -on_load fail, so the module refuses
// to load rather than run uninitialised (fail closed).
static int on_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    if (sodium_init() < 0) {
        return -1;
    }
    return 0;
}

static void on_unload(ErlNifEnv *env, void *priv_data)
{
}

// Initialize the NIF library
ERL_NIF_INIT(libsignal_protocol_nif, nif_funcs, on_load, NULL, NULL, on_unload) 