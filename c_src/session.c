#include "session.h"
#include "dr_crypto.h"
#include <sodium.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

// Finish the X3DH key derivation: SK = HKDF(salt=zeros, IKM=F||KM,
// info="X3DH-Signal", L=96). F is 32 bytes of 0xFF (Signal X25519 spec).
// km is DH1||DH2||DH3 (96B) or DH1||DH2||DH3||DH4 (128B).
// Slot map: [0..64) = SK (root seed for dr_init), [64..96) = shared header
// key seed for DR-HE. Returns 0 on success.
static int x3dh_derive_sk(const unsigned char *km, size_t km_size,
                          unsigned char sk_out[96])
{
    unsigned char hkdf_input[32 + 128];  // max km_size is 128
    if (km_size != 96 && km_size != 128) {
        return -1;
    }
    memset(hkdf_input, 0xFF, 32);
    memcpy(hkdf_input + 32, km, km_size);
    int rc = hkdf_sha256(sk_out, 96, NULL, 0,
                         hkdf_input, 32 + km_size,
                         (const unsigned char *)"X3DH-Signal", 11);
    sodium_memzero(hkdf_input, sizeof(hkdf_input));
    return rc;
}

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
    
    // Perform raw X25519 key agreement (Signal spec: no HSalsa20 post-mix).
    unsigned char shared_secret[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared_secret, local_key.data, remote_key.data) != 0) {
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
    // Raw X25519 (crypto_scalarmult) -- Signal spec output, not the
    // HSalsa20-of-X25519 form that crypto_box_beforenm produces.
    unsigned char dh1[crypto_scalarmult_BYTES];
    unsigned char dh2[crypto_scalarmult_BYTES];
    unsigned char dh3[crypto_scalarmult_BYTES];
    unsigned char dh4[crypto_scalarmult_BYTES];

    if (crypto_scalarmult(dh1, local_x_priv, signed_prekey) != 0) {
        sodium_memzero(local_x_priv, sizeof(local_x_priv));
        sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "dh1_calculation_failed"));
    }

    if (crypto_scalarmult(dh2, ephemeral_private_key, remote_x_id_pub) != 0) {
        sodium_memzero(local_x_priv, sizeof(local_x_priv));
        sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
        sodium_memzero(dh1, sizeof(dh1));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "dh2_calculation_failed"));
    }

    if (crypto_scalarmult(dh3, ephemeral_private_key, signed_prekey) != 0) {
        sodium_memzero(local_x_priv, sizeof(local_x_priv));
        sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
        sodium_memzero(dh1, sizeof(dh1));
        sodium_memzero(dh2, sizeof(dh2));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "dh3_calculation_failed"));
    }

    if (has_one_time_prekey) {
        if (crypto_scalarmult(dh4, ephemeral_private_key, one_time_prekey) != 0) {
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
    
    unsigned char session_key[96];
    int kdf_rc = x3dh_derive_sk(km, km_size, session_key);
    free(km);
    sodium_memzero(dh1, sizeof(dh1));
    sodium_memzero(dh2, sizeof(dh2));
    sodium_memzero(dh3, sizeof(dh3));
    if (has_one_time_prekey) {
        sodium_memzero(dh4, sizeof(dh4));
    }
    if (kdf_rc != 0) {
        sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
        sodium_memzero(session_key, sizeof(session_key));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "kdf_failed"));
    }

    // Create return tuple with session key and ephemeral public key.
    // SessionKey is 96B: [0..64)=SK, [64..96)=shared header key for DR-HE.
    ERL_NIF_TERM session_term, ephemeral_pub_term;
    unsigned char *session_data = enif_make_new_binary(env, 96, &session_term);
    unsigned char *ephemeral_pub_data = enif_make_new_binary(env, 32, &ephemeral_pub_term);

    memcpy(session_data, session_key, 96);
    memcpy(ephemeral_pub_data, ephemeral_public_key, 32);

    sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
    sodium_memzero(session_key, sizeof(session_key));

    // Return {ok, {SessionKey, EphemeralPublicKey}}
    return enif_make_tuple2(env, enif_make_atom(env, "ok"),
                           enif_make_tuple2(env, session_term, ephemeral_pub_term));
}

// Bob's side of X3DH. Bob holds: his identity priv (Ed25519, 64B), his SPK
// priv (X25519, 32B), and optionally his OPK priv (X25519, 32B; empty if not
// used). From Alice's first message he extracts: Alice's identity pub (Ed25519,
// 32B) and Alice's ephemeral pub (X25519, 32B). The three (or four) DH outputs
// commute with Alice's by construction:
//   DH1 = DH(SPK_B_priv, IK_A_pub_X)   == DH(IK_A_priv_X, SPK_B_pub)
//   DH2 = DH(IK_B_priv_X, EK_A_pub)    == DH(EK_A_priv, IK_B_pub_X)
//   DH3 = DH(SPK_B_priv, EK_A_pub)     == DH(EK_A_priv, SPK_B_pub)
//   DH4 = DH(OPK_B_priv, EK_A_pub)     == DH(EK_A_priv, OPK_B_pub)
// KM = DH1||DH2||DH3[||DH4]; SK = X3DH KDF(KM). Returns {ok, SK(96B)},
// where SK[0..64) is the X3DH root seed and SK[64..96) is the DR-HE shared
// header key.
ERL_NIF_TERM process_pre_key_bundle_bob(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 5) {
        return enif_make_badarg(env);
    }

    ErlNifBinary id_priv, spk_priv, opk_priv, remote_id_pub, remote_eph_pub;
    if (!enif_inspect_binary(env, argv[0], &id_priv) ||
        !enif_inspect_binary(env, argv[1], &spk_priv) ||
        !enif_inspect_binary(env, argv[2], &opk_priv) ||
        !enif_inspect_binary(env, argv[3], &remote_id_pub) ||
        !enif_inspect_binary(env, argv[4], &remote_eph_pub)) {
        return enif_make_badarg(env);
    }

    if (id_priv.size != crypto_sign_SECRETKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "invalid_identity_priv_size"));
    }
    if (spk_priv.size != crypto_box_SECRETKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "invalid_signed_pre_key_priv_size"));
    }
    bool has_opk = opk_priv.size > 0;
    if (has_opk && opk_priv.size != crypto_box_SECRETKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "invalid_one_time_pre_key_priv_size"));
    }
    if (remote_id_pub.size != crypto_sign_PUBLICKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "invalid_remote_identity_pub_size"));
    }
    if (remote_eph_pub.size != crypto_box_PUBLICKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "invalid_remote_ephemeral_pub_size"));
    }

    // Convert Bob's Ed25519 identity priv and Alice's Ed25519 identity pub
    // to X25519 form for DH.
    unsigned char id_priv_x[crypto_box_SECRETKEYBYTES];
    unsigned char remote_id_pub_x[crypto_box_PUBLICKEYBYTES];
    if (crypto_sign_ed25519_sk_to_curve25519(id_priv_x, id_priv.data) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "identity_priv_conversion_failed"));
    }
    if (crypto_sign_ed25519_pk_to_curve25519(remote_id_pub_x,
                                             remote_id_pub.data) != 0) {
        sodium_memzero(id_priv_x, sizeof(id_priv_x));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "identity_pub_conversion_failed"));
    }

    unsigned char dh1[crypto_scalarmult_BYTES];
    unsigned char dh2[crypto_scalarmult_BYTES];
    unsigned char dh3[crypto_scalarmult_BYTES];
    unsigned char dh4[crypto_scalarmult_BYTES];

    if (crypto_scalarmult(dh1, spk_priv.data, remote_id_pub_x) != 0) {
        sodium_memzero(id_priv_x, sizeof(id_priv_x));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "dh1_calculation_failed"));
    }
    if (crypto_scalarmult(dh2, id_priv_x, remote_eph_pub.data) != 0) {
        sodium_memzero(id_priv_x, sizeof(id_priv_x));
        sodium_memzero(dh1, sizeof(dh1));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "dh2_calculation_failed"));
    }
    if (crypto_scalarmult(dh3, spk_priv.data, remote_eph_pub.data) != 0) {
        sodium_memzero(id_priv_x, sizeof(id_priv_x));
        sodium_memzero(dh1, sizeof(dh1));
        sodium_memzero(dh2, sizeof(dh2));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "dh3_calculation_failed"));
    }
    if (has_opk) {
        if (crypto_scalarmult(dh4, opk_priv.data, remote_eph_pub.data) != 0) {
            sodium_memzero(id_priv_x, sizeof(id_priv_x));
            sodium_memzero(dh1, sizeof(dh1));
            sodium_memzero(dh2, sizeof(dh2));
            sodium_memzero(dh3, sizeof(dh3));
            return enif_make_tuple2(env, enif_make_atom(env, "error"),
                                   enif_make_atom(env, "dh4_calculation_failed"));
        }
    }
    sodium_memzero(id_priv_x, sizeof(id_priv_x));

    size_t km_size = has_opk ? 128 : 96;
    unsigned char km[128];
    memcpy(km,      dh1, 32);
    memcpy(km + 32, dh2, 32);
    memcpy(km + 64, dh3, 32);
    if (has_opk) {
        memcpy(km + 96, dh4, 32);
    }

    unsigned char session_key[96];
    int kdf_rc = x3dh_derive_sk(km, km_size, session_key);
    sodium_memzero(dh1, sizeof(dh1));
    sodium_memzero(dh2, sizeof(dh2));
    sodium_memzero(dh3, sizeof(dh3));
    if (has_opk) {
        sodium_memzero(dh4, sizeof(dh4));
    }
    sodium_memzero(km, sizeof(km));
    if (kdf_rc != 0) {
        sodium_memzero(session_key, sizeof(session_key));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "kdf_failed"));
    }

    // SessionKey is 96B: [0..64)=SK, [64..96)=shared header key for DR-HE.
    ERL_NIF_TERM session_term;
    unsigned char *session_data = enif_make_new_binary(env, 96, &session_term);
    memcpy(session_data, session_key, 96);
    sodium_memzero(session_key, sizeof(session_key));

    return enif_make_tuple2(env, enif_make_atom(env, "ok"), session_term);
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

