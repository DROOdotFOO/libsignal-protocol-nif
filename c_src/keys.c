#include "keys.h"
#include <sodium.h>
#include <string.h>

// Generate identity key pair using Ed25519 (32B pub, 64B priv).
// The Ed25519 priv lets the holder sign signed-prekeys via crypto_sign_detached.
// For DH operations (X3DH, DR) the keys are converted to X25519 via
// crypto_sign_ed25519_{pk,sk}_to_curve25519.
ERL_NIF_TERM generate_identity_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 0) {
        return enif_make_badarg(env);
    }

    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];   // 32 bytes
    unsigned char private_key[crypto_sign_SECRETKEYBYTES];  // 64 bytes (seed + pub)

    if (crypto_sign_keypair(public_key, private_key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "key_generation_failed"));
    }

    ERL_NIF_TERM public_term, private_term;
    unsigned char *public_data =
        enif_make_new_binary(env, crypto_sign_PUBLICKEYBYTES, &public_term);
    unsigned char *private_data =
        enif_make_new_binary(env, crypto_sign_SECRETKEYBYTES, &private_term);

    memcpy(public_data, public_key, crypto_sign_PUBLICKEYBYTES);
    memcpy(private_data, private_key, crypto_sign_SECRETKEYBYTES);

    sodium_memzero(private_key, sizeof(private_key));

    return enif_make_tuple2(env, enif_make_atom(env, "ok"),
                           enif_make_tuple2(env, public_term, private_term));
}

// Generate pre-key using Curve25519
ERL_NIF_TERM generate_pre_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 1) {
        return enif_make_badarg(env);
    }
    
    int key_id;
    if (!enif_get_int(env, argv[0], &key_id)) {
        return enif_make_badarg(env);
    }
    
    // Generate real Curve25519 pre-key
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char private_key[crypto_box_SECRETKEYBYTES];
    
    if (crypto_box_keypair(public_key, private_key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "key_generation_failed"));
    }
    
    ERL_NIF_TERM pre_key_term;
    unsigned char *pre_key_data = enif_make_new_binary(env, crypto_box_PUBLICKEYBYTES, &pre_key_term);
    memcpy(pre_key_data, public_key, crypto_box_PUBLICKEYBYTES);
    
    // Clear sensitive data
    sodium_memzero(private_key, sizeof(private_key));
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), 
                           enif_make_tuple2(env, enif_make_int(env, key_id), pre_key_term));
}

// Generate a signed pre-key: an X25519 keypair (for DH) whose public key is
// signed with the caller's Ed25519 identity priv. Returns
// {KeyId, SpkPub(32), Signature(64)}.
ERL_NIF_TERM generate_signed_pre_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }

    ErlNifBinary identity_priv;
    int key_id;

    if (!enif_inspect_binary(env, argv[0], &identity_priv) ||
        !enif_get_int(env, argv[1], &key_id)) {
        return enif_make_badarg(env);
    }

    // Identity priv is an Ed25519 secret key (64 bytes).
    if (identity_priv.size != crypto_sign_SECRETKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "invalid_identity_key_size"));
    }

    unsigned char spk_pub[crypto_box_PUBLICKEYBYTES];
    unsigned char spk_priv[crypto_box_SECRETKEYBYTES];

    if (crypto_box_keypair(spk_pub, spk_priv) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "key_generation_failed"));
    }

    // Sign the X25519 prekey pub with Ed25519.
    unsigned char signature[crypto_sign_BYTES];
    unsigned long long siglen = 0;
    if (crypto_sign_detached(signature, &siglen, spk_pub, sizeof(spk_pub),
                             identity_priv.data) != 0) {
        sodium_memzero(spk_priv, sizeof(spk_priv));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "signature_failed"));
    }

    ERL_NIF_TERM pre_key_term, signature_term;
    unsigned char *pre_key_data =
        enif_make_new_binary(env, crypto_box_PUBLICKEYBYTES, &pre_key_term);
    unsigned char *signature_data =
        enif_make_new_binary(env, crypto_sign_BYTES, &signature_term);

    memcpy(pre_key_data, spk_pub, crypto_box_PUBLICKEYBYTES);
    memcpy(signature_data, signature, crypto_sign_BYTES);

    sodium_memzero(spk_priv, sizeof(spk_priv));

    return enif_make_tuple2(
        env, enif_make_atom(env, "ok"),
        enif_make_tuple3(env, enif_make_int(env, key_id), pre_key_term,
                         signature_term));
}

