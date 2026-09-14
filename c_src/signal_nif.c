#include <erl_nif.h>
#include <string.h>
#include <sodium.h>

static ERL_NIF_TERM sha256(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 1) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary data;
    if (!enif_inspect_binary(env, argv[0], &data)) {
        return enif_make_badarg(env);
    }
    
    // Generate real SHA-256 hash using libsodium
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, data.data, data.size);
    
    ERL_NIF_TERM hash_term;
    unsigned char *bin_data = enif_make_new_binary(env, 32, &hash_term);
    memcpy(bin_data, hash, 32);
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), hash_term);
}

static ERL_NIF_TERM generate_curve25519_keypair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 0) {
        return enif_make_badarg(env);
    }
    
    // Generate real Curve25519 key pair using libsodium
    unsigned char public_key[32];
    unsigned char private_key[32];
    
    // Use libsodium's crypto_box_keypair which generates Curve25519 keys
    if (crypto_box_keypair(public_key, private_key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "key_generation_failed"));
    }
    
    ERL_NIF_TERM private_term, public_term;
    unsigned char *private_data = enif_make_new_binary(env, 32, &private_term);
    unsigned char *public_data = enif_make_new_binary(env, 32, &public_term);
    
    memcpy(private_data, private_key, 32);
    memcpy(public_data, public_key, 32);
    
    // Clear sensitive data from stack
    sodium_memzero(private_key, sizeof(private_key));
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"),
                           enif_make_tuple2(env, public_term, private_term));
}

static ERL_NIF_TERM generate_ed25519_keypair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 0) {
        return enif_make_badarg(env);
    }
    
    // Generate Ed25519 key pair using libsodium
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char private_key[crypto_sign_SECRETKEYBYTES];
    
    if (crypto_sign_keypair(public_key, private_key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "key_generation_failed"));
    }
    
    ERL_NIF_TERM private_term, public_term;
    // Return the full 64-byte libsodium secret key (seed || derived pub).
    // This matches libsignal_protocol_nif:generate_identity_key_pair and the
    // representation expected by sign_data/2 and ed25519_sk_to_curve25519/1.
    unsigned char *private_data =
        enif_make_new_binary(env, crypto_sign_SECRETKEYBYTES, &private_term);
    unsigned char *public_data =
        enif_make_new_binary(env, crypto_sign_PUBLICKEYBYTES, &public_term);

    memcpy(private_data, private_key, crypto_sign_SECRETKEYBYTES);
    memcpy(public_data, public_key, crypto_sign_PUBLICKEYBYTES);
    
    // Clear sensitive data from stack
    sodium_memzero(private_key, sizeof(private_key));
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), 
                           enif_make_tuple2(env, public_term, private_term));
}

static ERL_NIF_TERM sign_data(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary private_key, message;
    if (!enif_inspect_binary(env, argv[0], &private_key) ||
        !enif_inspect_binary(env, argv[1], &message)) {
        return enif_make_badarg(env);
    }
    
    // Validate private key size (64-byte libsodium SK: seed || derived pub).
    if (private_key.size != crypto_sign_SECRETKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "invalid_private_key"));
    }

    unsigned char signature[crypto_sign_BYTES];
    unsigned long long signature_len;

    if (crypto_sign_detached(signature, &signature_len, message.data, message.size, private_key.data) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "signing_failed"));
    }
    
    ERL_NIF_TERM signature_term;
    unsigned char *signature_data = enif_make_new_binary(env, signature_len, &signature_term);
    memcpy(signature_data, signature, signature_len);

    return enif_make_tuple2(env, enif_make_atom(env, "ok"), signature_term);
}

static ERL_NIF_TERM verify_signature(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 3) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary public_key, message, signature;
    if (!enif_inspect_binary(env, argv[0], &public_key) ||
        !enif_inspect_binary(env, argv[1], &message) ||
        !enif_inspect_binary(env, argv[2], &signature)) {
        return enif_make_badarg(env);
    }
    
    // Validate public key size
    if (public_key.size != crypto_sign_PUBLICKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_public_key"));
    }
    
    // Validate signature size
    if (signature.size != crypto_sign_BYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_signature"));
    }
    
    // Verify the signature
    if (crypto_sign_verify_detached(signature.data, message.data, message.size, public_key.data) == 0) {
        return enif_make_atom(env, "ok");
    } else {
        return enif_make_atom(env, "invalid_signature");
    }
}

// Convert an Ed25519 secret key (64B seed||pub form) to its X25519 private
// scalar (32B). Mirrors libsodium's crypto_sign_ed25519_sk_to_curve25519.
static ERL_NIF_TERM ed25519_sk_to_curve25519(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 1) {
        return enif_make_badarg(env);
    }

    ErlNifBinary ed_sk;
    if (!enif_inspect_binary(env, argv[0], &ed_sk)) {
        return enif_make_badarg(env);
    }
    if (ed_sk.size != crypto_sign_SECRETKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "invalid_secret_key_size"));
    }

    unsigned char x_sk[crypto_scalarmult_BYTES];
    if (crypto_sign_ed25519_sk_to_curve25519(x_sk, ed_sk.data) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "conversion_failed"));
    }

    ERL_NIF_TERM out;
    unsigned char *out_data = enif_make_new_binary(env, crypto_scalarmult_BYTES, &out);
    memcpy(out_data, x_sk, crypto_scalarmult_BYTES);
    sodium_memzero(x_sk, sizeof(x_sk));
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), out);
}

// Convert an Ed25519 public key (32B) to its X25519 public key (32B).
// Mirrors libsodium's crypto_sign_ed25519_pk_to_curve25519.
static ERL_NIF_TERM ed25519_pk_to_curve25519(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 1) {
        return enif_make_badarg(env);
    }

    ErlNifBinary ed_pk;
    if (!enif_inspect_binary(env, argv[0], &ed_pk)) {
        return enif_make_badarg(env);
    }
    if (ed_pk.size != crypto_sign_PUBLICKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "invalid_public_key_size"));
    }

    unsigned char x_pk[crypto_scalarmult_BYTES];
    if (crypto_sign_ed25519_pk_to_curve25519(x_pk, ed_pk.data) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "conversion_failed"));
    }

    ERL_NIF_TERM out;
    unsigned char *out_data = enif_make_new_binary(env, crypto_scalarmult_BYTES, &out);
    memcpy(out_data, x_pk, crypto_scalarmult_BYTES);
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), out);
}

static ERL_NIF_TERM sha512(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 1) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary data;
    if (!enif_inspect_binary(env, argv[0], &data)) {
        return enif_make_badarg(env);
    }
    
    // Generate SHA-512 hash using libsodium
    unsigned char hash[crypto_hash_sha512_BYTES];
    crypto_hash_sha512(hash, data.data, data.size);
    
    ERL_NIF_TERM hash_term;
    unsigned char *bin_data = enif_make_new_binary(env, crypto_hash_sha512_BYTES, &hash_term);
    memcpy(bin_data, hash, crypto_hash_sha512_BYTES);
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), hash_term);
}

static ERL_NIF_TERM hmac_sha256(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary key, data;
    if (!enif_inspect_binary(env, argv[0], &key) ||
        !enif_inspect_binary(env, argv[1], &data)) {
        return enif_make_badarg(env);
    }
    
    // HMAC-SHA-256 with an arbitrary-length key (RFC 2104). crypto_auth()
    // reads a fixed 32-byte key and would over-read shorter binaries; the
    // streaming API hashes long keys and pads short ones as the RFC requires.
    unsigned char hmac[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state st;
    if (crypto_auth_hmacsha256_init(&st, key.data, key.size) != 0 ||
        crypto_auth_hmacsha256_update(&st, data.data, data.size) != 0 ||
        crypto_auth_hmacsha256_final(&st, hmac) != 0) {
        sodium_memzero(&st, sizeof(st));
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "hmac_failed"));
    }
    sodium_memzero(&st, sizeof(st));
    
    ERL_NIF_TERM hmac_term;
    unsigned char *hmac_data = enif_make_new_binary(env, sizeof(hmac), &hmac_term);
    memcpy(hmac_data, hmac, sizeof(hmac));
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), hmac_term);
}

static ERL_NIF_TERM aes_gcm_encrypt(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 5) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary key, iv, plaintext, aad;
    int tag_len;
    
    if (!enif_inspect_binary(env, argv[0], &key) ||
        !enif_inspect_binary(env, argv[1], &iv) ||
        !enif_inspect_binary(env, argv[2], &plaintext) ||
        !enif_inspect_binary(env, argv[3], &aad) ||
        !enif_get_int(env, argv[4], &tag_len)) {
        return enif_make_badarg(env);
    }
    
    // Validate key and IV sizes
    if (key.size != crypto_aead_aes256gcm_KEYBYTES || 
        iv.size != crypto_aead_aes256gcm_NPUBBYTES ||
        tag_len != crypto_aead_aes256gcm_ABYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_parameters"));
    }
    
    // Check if AES-GCM is available
    if (!crypto_aead_aes256gcm_is_available()) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "aes_gcm_not_available"));
    }
    
    // Allocate memory for ciphertext + tag
    size_t ciphertext_len = plaintext.size + crypto_aead_aes256gcm_ABYTES;
    ERL_NIF_TERM ciphertext_term, tag_term;
    unsigned char *ciphertext_data = enif_make_new_binary(env, plaintext.size, &ciphertext_term);
    unsigned char *tag_data = enif_make_new_binary(env, crypto_aead_aes256gcm_ABYTES, &tag_term);
    
    // Temporary buffer for ciphertext + tag
    unsigned char *temp_buffer = enif_alloc(ciphertext_len);
    if (!temp_buffer) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "memory_allocation_failed"));
    }
    
    unsigned long long actual_ciphertext_len;
    if (crypto_aead_aes256gcm_encrypt(temp_buffer, &actual_ciphertext_len,
                                      plaintext.data, plaintext.size,
                                      aad.data, aad.size,
                                      NULL, iv.data, key.data) != 0) {
        sodium_memzero(temp_buffer, ciphertext_len);
        enif_free(temp_buffer);
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "encryption_failed"));
    }

    // Split ciphertext and tag
    memcpy(ciphertext_data, temp_buffer, plaintext.size);
    memcpy(tag_data, temp_buffer + plaintext.size, crypto_aead_aes256gcm_ABYTES);

    sodium_memzero(temp_buffer, ciphertext_len);
    enif_free(temp_buffer);
    return enif_make_tuple3(env, enif_make_atom(env, "ok"), ciphertext_term, tag_term);
}

static ERL_NIF_TERM aes_gcm_decrypt(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 6) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary key, iv, ciphertext, aad, tag;
    int expected_plaintext_len;
    
    if (!enif_inspect_binary(env, argv[0], &key) ||
        !enif_inspect_binary(env, argv[1], &iv) ||
        !enif_inspect_binary(env, argv[2], &ciphertext) ||
        !enif_inspect_binary(env, argv[3], &aad) ||
        !enif_inspect_binary(env, argv[4], &tag) ||
        !enif_get_int(env, argv[5], &expected_plaintext_len)) {
        return enif_make_badarg(env);
    }
    
    // Validate parameters
    if (key.size != crypto_aead_aes256gcm_KEYBYTES || 
        iv.size != crypto_aead_aes256gcm_NPUBBYTES ||
        tag.size != crypto_aead_aes256gcm_ABYTES ||
        expected_plaintext_len < 0 ||
        (size_t)expected_plaintext_len != ciphertext.size) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_parameters"));
    }
    
    // Check if AES-GCM is available
    if (!crypto_aead_aes256gcm_is_available()) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "aes_gcm_not_available"));
    }
    
    // Create combined ciphertext + tag buffer
    size_t combined_len = ciphertext.size + tag.size;
    unsigned char *combined_buffer = enif_alloc(combined_len);
    if (!combined_buffer) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "memory_allocation_failed"));
    }
    
    memcpy(combined_buffer, ciphertext.data, ciphertext.size);
    memcpy(combined_buffer + ciphertext.size, tag.data, tag.size);
    
    ERL_NIF_TERM plaintext_term;
    unsigned char *plaintext_data = enif_make_new_binary(env, expected_plaintext_len, &plaintext_term);
    
    unsigned long long actual_plaintext_len;
    if (crypto_aead_aes256gcm_decrypt(plaintext_data, &actual_plaintext_len,
                                      NULL,
                                      combined_buffer, combined_len,
                                      aad.data, aad.size,
                                      iv.data, key.data) != 0) {
        sodium_memzero(combined_buffer, combined_len);
        enif_free(combined_buffer);
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "decryption_failed"));
    }

    sodium_memzero(combined_buffer, combined_len);
    enif_free(combined_buffer);
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), plaintext_term);
}

// Dispatch table. Hashing, HMAC and AES-GCM run over caller-sized binaries
// with no upper bound, so they take a dirty CPU scheduler; key generation
// and signature operations are fixed-size and stay on a normal one.
static ErlNifFunc nif_funcs[] = {
    {"sha256", 1, sha256, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"generate_curve25519_keypair", 0, generate_curve25519_keypair, 0},
    {"generate_ed25519_keypair", 0, generate_ed25519_keypair, 0},
    {"sign_data", 2, sign_data, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"verify_signature", 3, verify_signature, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"ed25519_sk_to_curve25519", 1, ed25519_sk_to_curve25519, 0},
    {"ed25519_pk_to_curve25519", 1, ed25519_pk_to_curve25519, 0},
    {"sha512", 1, sha512, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"hmac_sha256", 2, hmac_sha256, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"aes_gcm_encrypt", 5, aes_gcm_encrypt, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"aes_gcm_decrypt", 6, aes_gcm_decrypt, ERL_NIF_DIRTY_JOB_CPU_BOUND}
};

static int on_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    // Initialize libsodium
    if (sodium_init() < 0) {
        return -1; // Failed to initialize libsodium
    }
    return 0;
}

static void on_unload(ErlNifEnv *env, void *priv_data)
{
}

// Initialize the NIF library
ERL_NIF_INIT(signal_nif, nif_funcs, on_load, NULL, NULL, on_unload)

 