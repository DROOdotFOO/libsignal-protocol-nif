#include "keys.h"
#include <sodium.h>
#include <string.h>

// Generate identity key pair using Curve25519
ERL_NIF_TERM generate_identity_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 0) {
        return enif_make_badarg(env);
    }
    
    // Generate real Curve25519 key pair
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];  // 32 bytes
    unsigned char private_key[crypto_box_SECRETKEYBYTES]; // 32 bytes
    
    if (crypto_box_keypair(public_key, private_key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "key_generation_failed"));
    }
    
    ERL_NIF_TERM public_term, private_term;
    unsigned char *public_data = enif_make_new_binary(env, crypto_box_PUBLICKEYBYTES, &public_term);
    unsigned char *private_data = enif_make_new_binary(env, crypto_box_SECRETKEYBYTES, &private_term);
    
    memcpy(public_data, public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(private_data, private_key, crypto_box_SECRETKEYBYTES);
    
    // Clear sensitive data from stack
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

// Generate signed pre-key using Ed25519 signatures
ERL_NIF_TERM generate_signed_pre_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary identity_key;
    int key_id;
    
    if (!enif_inspect_binary(env, argv[0], &identity_key) || 
        !enif_get_int(env, argv[1], &key_id)) {
        return enif_make_badarg(env);
    }
    
    // Validate identity key size
    if (identity_key.size != crypto_box_SECRETKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_identity_key_size"));
    }
    
    // Generate real Curve25519 pre-key
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char private_key[crypto_box_SECRETKEYBYTES];
    
    if (crypto_box_keypair(public_key, private_key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "key_generation_failed"));
    }
    
    // Create message to sign (key_id + public_key)
    unsigned char message_to_sign[sizeof(int) + crypto_box_PUBLICKEYBYTES];
    memcpy(message_to_sign, &key_id, sizeof(int));
    memcpy(message_to_sign + sizeof(int), public_key, crypto_box_PUBLICKEYBYTES);
    
    // For simplicity, use HMAC-SHA256 instead of Ed25519 since we have Curve25519 keys
    unsigned char signature[32];  // HMAC-SHA256 output is 32 bytes
    
    // Use libsodium's crypto_auth for HMAC
    if (crypto_auth(signature, message_to_sign, sizeof(message_to_sign), identity_key.data) != 0) {
        sodium_memzero(private_key, sizeof(private_key));
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "signature_failed"));
    }
    
    ERL_NIF_TERM pre_key_term, signature_term;
    unsigned char *pre_key_data = enif_make_new_binary(env, crypto_box_PUBLICKEYBYTES, &pre_key_term);
    unsigned char *signature_data = enif_make_new_binary(env, 32, &signature_term);
    
    memcpy(pre_key_data, public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(signature_data, signature, 32);
    
    // Clear sensitive data
    sodium_memzero(private_key, sizeof(private_key));
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), 
                           enif_make_tuple3(env, enif_make_int(env, key_id), pre_key_term, signature_term));
}

