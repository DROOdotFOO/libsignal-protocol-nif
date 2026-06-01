#include "session.h"
#include <sodium.h>
#include <stdbool.h>
#include <string.h>

// Create session (two argument version) - perform key agreement
ERL_NIF_TERM create_session_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary local_key, remote_key;
    if (!enif_inspect_binary(env, argv[0], &local_key) || 
        !enif_inspect_binary(env, argv[1], &remote_key)) {
        return enif_make_badarg(env);
    }
    
    // Validate key sizes
    if (local_key.size != crypto_box_SECRETKEYBYTES || 
        remote_key.size != crypto_box_PUBLICKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_key_sizes"));
    }
    
    // Create session state with shared secret
    ERL_NIF_TERM session_term;
    unsigned char *session_data = enif_make_new_binary(env, 64, &session_term);
    
    // Perform Curve25519 key agreement
    unsigned char shared_secret[crypto_box_BEFORENMBYTES];
    if (crypto_box_beforenm(shared_secret, remote_key.data, local_key.data) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "key_agreement_failed"));
    }
    
    // Derive session key from shared secret
    crypto_generichash(session_data, 32, shared_secret, sizeof(shared_secret), NULL, 0);
    
    // Add some randomness for the rest of the session state
    randombytes_buf(session_data + 32, 32);
    
    // Clear sensitive data
    sodium_memzero(shared_secret, sizeof(shared_secret));
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), session_term);
}

// Process pre-key bundle - Full X3DH Key Agreement Protocol Implementation
ERL_NIF_TERM process_pre_key_bundle(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary local_identity_priv, bundle;

    if (!enif_inspect_binary(env, argv[0], &local_identity_priv) ||
        !enif_inspect_binary(env, argv[1], &bundle)) {
        return enif_make_badarg(env);
    }

    // Local identity priv is an Ed25519 secret key (64 bytes).
    if (local_identity_priv.size != crypto_sign_SECRETKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "invalid_local_identity_key_size"));
    }

    // Bundle format:
    //   ed_identity_pub(32) ++ signed_prekey_pub(32) ++ signature(64)
    //   ++ [one_time_prekey_pub(32)]
    size_t min_bundle_size = 32 + 32 + crypto_sign_BYTES;  // 128
    if (bundle.size < min_bundle_size) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "invalid_bundle_size"));
    }

    unsigned char *remote_ed_id_pub = bundle.data;
    unsigned char *signed_prekey = bundle.data + 32;
    unsigned char *signature = bundle.data + 64;
    unsigned char *one_time_prekey = NULL;
    bool has_one_time_prekey = (bundle.size >= min_bundle_size + 32);
    if (has_one_time_prekey) {
        one_time_prekey = bundle.data + min_bundle_size;
    }

    // Ed25519 verify the signed prekey signature using the *remote* identity
    // pub as the verification key. Only the holder of the matching identity
    // priv can produce a signature that verifies.
    if (crypto_sign_verify_detached(signature, signed_prekey, 32,
                                    remote_ed_id_pub) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "signature_verification_failed"));
    }

    // For X25519 DH operations we need the curve forms of the identity keys.
    unsigned char local_x_priv[crypto_box_SECRETKEYBYTES];
    unsigned char remote_x_id_pub[crypto_box_PUBLICKEYBYTES];
    if (crypto_sign_ed25519_sk_to_curve25519(local_x_priv,
                                             local_identity_priv.data) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "identity_priv_conversion_failed"));
    }
    if (crypto_sign_ed25519_pk_to_curve25519(remote_x_id_pub,
                                             remote_ed_id_pub) != 0) {
        sodium_memzero(local_x_priv, sizeof(local_x_priv));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "identity_pub_conversion_failed"));
    }

    // Generate ephemeral key pair for this X3DH exchange.
    unsigned char ephemeral_public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char ephemeral_private_key[crypto_box_SECRETKEYBYTES];

    if (crypto_box_keypair(ephemeral_public_key, ephemeral_private_key) != 0) {
        sodium_memzero(local_x_priv, sizeof(local_x_priv));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "ephemeral_key_generation_failed"));
    }

    // X3DH (Signal spec §3.3, Alice's side):
    //   DH1 = DH(IK_A, SPK_B)
    //   DH2 = DH(EK_A, IK_B)
    //   DH3 = DH(EK_A, SPK_B)
    //   DH4 = DH(EK_A, OPK_B)  (if present)
    unsigned char dh1[crypto_box_BEFORENMBYTES];
    unsigned char dh2[crypto_box_BEFORENMBYTES];
    unsigned char dh3[crypto_box_BEFORENMBYTES];
    unsigned char dh4[crypto_box_BEFORENMBYTES];

    if (crypto_box_beforenm(dh1, signed_prekey, local_x_priv) != 0) {
        sodium_memzero(local_x_priv, sizeof(local_x_priv));
        sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "dh1_calculation_failed"));
    }

    if (crypto_box_beforenm(dh2, remote_x_id_pub, ephemeral_private_key) != 0) {
        sodium_memzero(local_x_priv, sizeof(local_x_priv));
        sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
        sodium_memzero(dh1, sizeof(dh1));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "dh2_calculation_failed"));
    }

    if (crypto_box_beforenm(dh3, signed_prekey, ephemeral_private_key) != 0) {
        sodium_memzero(local_x_priv, sizeof(local_x_priv));
        sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
        sodium_memzero(dh1, sizeof(dh1));
        sodium_memzero(dh2, sizeof(dh2));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "dh3_calculation_failed"));
    }

    if (has_one_time_prekey) {
        if (crypto_box_beforenm(dh4, one_time_prekey, ephemeral_private_key) != 0) {
            sodium_memzero(local_x_priv, sizeof(local_x_priv));
            sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
            sodium_memzero(dh1, sizeof(dh1));
            sodium_memzero(dh2, sizeof(dh2));
            sodium_memzero(dh3, sizeof(dh3));
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "dh4_calculation_failed"));
        }
    }
    sodium_memzero(local_x_priv, sizeof(local_x_priv));
    
    // Concatenate DH outputs for KDF input
    // KM = DH1 || DH2 || DH3 || DH4 (if present)
    size_t km_size = has_one_time_prekey ? 128 : 96; // 4*32 or 3*32 bytes
    unsigned char *km = malloc(km_size);
    if (!km) {
        sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
        sodium_memzero(dh1, sizeof(dh1));
        sodium_memzero(dh2, sizeof(dh2));
        sodium_memzero(dh3, sizeof(dh3));
        if (has_one_time_prekey) {
            sodium_memzero(dh4, sizeof(dh4));
        }
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "memory_allocation_failed"));
    }
    
    memcpy(km, dh1, 32);
    memcpy(km + 32, dh2, 32);
    memcpy(km + 64, dh3, 32);
    if (has_one_time_prekey) {
        memcpy(km + 96, dh4, 32);
    }
    
    // Derive session key using HKDF-like construction
    // SK = KDF(F || KM) where F is 32 bytes of 0xFF for X25519
    unsigned char f_bytes[32];
    memset(f_bytes, 0xFF, 32);
    
    size_t hkdf_input_size = 32 + km_size;
    unsigned char *hkdf_input = malloc(hkdf_input_size);
    if (!hkdf_input) {
        free(km);
        sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
        sodium_memzero(dh1, sizeof(dh1));
        sodium_memzero(dh2, sizeof(dh2));
        sodium_memzero(dh3, sizeof(dh3));
        if (has_one_time_prekey) {
            sodium_memzero(dh4, sizeof(dh4));
        }
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "memory_allocation_failed"));
    }
    
    memcpy(hkdf_input, f_bytes, 32);
    memcpy(hkdf_input + 32, km, km_size);
    
    // Use BLAKE2b (available in libsodium) as our KDF to derive 64-byte session key
    unsigned char session_key[64];
    if (crypto_generichash(session_key, 64, hkdf_input, hkdf_input_size, NULL, 0) != 0) {
        free(km);
        free(hkdf_input);
        sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
        sodium_memzero(dh1, sizeof(dh1));
        sodium_memzero(dh2, sizeof(dh2));
        sodium_memzero(dh3, sizeof(dh3));
        if (has_one_time_prekey) {
            sodium_memzero(dh4, sizeof(dh4));
        }
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "kdf_failed"));
    }
    
    // Create return tuple with session key and ephemeral public key
    ERL_NIF_TERM session_term, ephemeral_pub_term;
    unsigned char *session_data = enif_make_new_binary(env, 64, &session_term);
    unsigned char *ephemeral_pub_data = enif_make_new_binary(env, 32, &ephemeral_pub_term);
    
    memcpy(session_data, session_key, 64);
    memcpy(ephemeral_pub_data, ephemeral_public_key, 32);
    
    // Clean up sensitive data
    free(km);
    free(hkdf_input);
    sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
    sodium_memzero(dh1, sizeof(dh1));
    sodium_memzero(dh2, sizeof(dh2));
    sodium_memzero(dh3, sizeof(dh3));
    if (has_one_time_prekey) {
        sodium_memzero(dh4, sizeof(dh4));
    }
    sodium_memzero(session_key, sizeof(session_key));
    
    // Return {ok, {SessionKey, EphemeralPublicKey}}
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), 
                           enif_make_tuple2(env, session_term, ephemeral_pub_term));
}

// Encrypt message using ChaCha20-Poly1305
ERL_NIF_TERM encrypt_message(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary session, message;
    
    if (!enif_inspect_binary(env, argv[0], &session) ||
        !enif_inspect_binary(env, argv[1], &message)) {
        return enif_make_badarg(env);
    }
    
    // Validate session size (should contain at least a 32-byte key)
    if (session.size < 32) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_session"));
    }
    
    // Use first 32 bytes of session as encryption key
    unsigned char key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    memcpy(key, session.data, crypto_aead_chacha20poly1305_ietf_KEYBYTES);
    
    // Generate random nonce
    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    
    // Calculate ciphertext size (plaintext + MAC + nonce)
    size_t ciphertext_len = message.size + crypto_aead_chacha20poly1305_ietf_ABYTES;
    size_t total_size = ciphertext_len + crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    
    ERL_NIF_TERM encrypted_term;
    unsigned char *encrypted_data = enif_make_new_binary(env, total_size, &encrypted_term);
    
    // Store nonce at the beginning
    memcpy(encrypted_data, nonce, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    
    // Encrypt the message
    unsigned long long actual_ciphertext_len;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            encrypted_data + crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
            &actual_ciphertext_len,
            message.data, message.size,
            NULL, 0,  // No additional data
            NULL,     // No secret nonce
            nonce, key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "encryption_failed"));
    }
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), encrypted_term);
}

// Decrypt message using ChaCha20-Poly1305
ERL_NIF_TERM decrypt_message(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary session, encrypted;
    
    if (!enif_inspect_binary(env, argv[0], &session) ||
        !enif_inspect_binary(env, argv[1], &encrypted)) {
        return enif_make_badarg(env);
    }
    
    // Validate session size (should contain at least a 32-byte key)
    if (session.size < 32) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_session"));
    }
    
    // Validate encrypted message size (nonce + ciphertext + MAC)
    size_t min_size = crypto_aead_chacha20poly1305_ietf_NPUBBYTES + 
                     crypto_aead_chacha20poly1305_ietf_ABYTES;
    if (encrypted.size < min_size) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_message"));
    }
    
    // Use first 32 bytes of session as decryption key
    unsigned char key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    memcpy(key, session.data, crypto_aead_chacha20poly1305_ietf_KEYBYTES);
    
    // Extract nonce from the beginning of encrypted data
    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    memcpy(nonce, encrypted.data, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    
    // Calculate plaintext size
    size_t ciphertext_len = encrypted.size - crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    size_t plaintext_len = ciphertext_len - crypto_aead_chacha20poly1305_ietf_ABYTES;
    
    ERL_NIF_TERM decrypted_term;
    unsigned char *decrypted_data = enif_make_new_binary(env, plaintext_len, &decrypted_term);
    
    // Decrypt the message
    unsigned long long actual_plaintext_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            decrypted_data, &actual_plaintext_len,
            NULL,  // No secret nonce
            encrypted.data + crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
            ciphertext_len,
            NULL, 0,  // No additional data
            nonce, key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "decryption_failed"));
    }
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), decrypted_term);
}

