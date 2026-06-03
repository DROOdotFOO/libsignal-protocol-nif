-module(signal_crypto_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, test_basic_crypto/1,
         test_curve25519_keypair/1, test_ed25519_keypair/1, test_ed25519_sign_verify/1,
         test_sha256/1, test_sha512/1, test_hmac_sha256/1, test_aes_gcm_encryption/1]).

all() ->
    [test_basic_crypto,
     test_curve25519_keypair,
     test_ed25519_keypair,
     test_ed25519_sign_verify,
     test_sha256,
     test_sha512,
     test_hmac_sha256,
     test_aes_gcm_encryption].

init_per_suite(Config) ->
    io:format("signal_crypto_SUITE: init_per_suite starting~n", []),
    % Load the signal_nif module
    code:add_patha("../../../erl_src"),
    case signal_nif:test_crypto() of
        crypto_ok ->
            io:format("NIF initialized successfully~n"),
            Config;
        {error, Reason} ->
            io:format("Failed to initialize NIF: ~p~n", [Reason]),
            {skip, "NIF initialization failed"}
    end.

end_per_suite(_Config) ->
    ok.

test_basic_crypto(_Config) ->
    % Test basic crypto functionality
    crypto_ok = signal_nif:test_crypto(),
    ok.

test_curve25519_keypair(_Config) ->
    % Test Curve25519 key pair generation
    {ok, {PublicKey, PrivateKey}} = signal_nif:generate_curve25519_keypair(),
    ?assert(is_binary(PublicKey)),
    ?assert(is_binary(PrivateKey)),
    ?assertEqual(32, byte_size(PublicKey)),
    ?assertEqual(32, byte_size(PrivateKey)),
    ?assertNotEqual(PublicKey, PrivateKey),
    ok.

test_ed25519_keypair(_Config) ->
    % Test Ed25519 key pair generation. Priv is the 64-byte libsodium SK
    % (seed || derived pub).
    {ok, {PublicKey, PrivateKey}} = signal_nif:generate_ed25519_keypair(),
    ?assert(is_binary(PublicKey)),
    ?assert(is_binary(PrivateKey)),
    ?assertEqual(32, byte_size(PublicKey)),
    ?assertEqual(64, byte_size(PrivateKey)),
    ?assertNotEqual(PublicKey, PrivateKey),
    ok.

test_ed25519_sign_verify(_Config) ->
    % Generate Ed25519 key pair
    {ok, {PublicKey, PrivateKey}} = signal_nif:generate_ed25519_keypair(),
    Message = <<"Test message for Ed25519 signing">>,
    % Sign the message
    {ok, Signature} = signal_nif:sign_data(PrivateKey, Message),
    ?assert(is_binary(Signature)),
    ?assertEqual(64, byte_size(Signature)),
    % Verify the signature
    ok = signal_nif:verify_signature(PublicKey, Message, Signature),
    % Negative test: modify the message
    InvalidResult = signal_nif:verify_signature(PublicKey, <<"tampered">>, Signature),
    ?assertEqual(invalid_signature, InvalidResult),
    ok.

test_sha256(_Config) ->
    % Test SHA-256 hashing
    TestData = <<"Hello, Signal Protocol!">>,
    {ok, Hash} = signal_nif:sha256(TestData),
    ?assert(is_binary(Hash)),
    ?assertEqual(32, byte_size(Hash)),
    ok.

test_sha512(_Config) ->
    % Test SHA-512 hashing
    TestData = <<"Hello, Signal Protocol!">>,
    {ok, Hash} = signal_nif:sha512(TestData),
    ?assert(is_binary(Hash)),
    ?assertEqual(64, byte_size(Hash)),
    ok.

test_hmac_sha256(_Config) ->
    % Test HMAC-SHA256
    Key = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32>>,
    Data = <<"Hello, Signal Protocol!">>,
    {ok, Hmac} = signal_nif:hmac_sha256(Key, Data),
    ?assert(is_binary(Hmac)),
    ?assertEqual(32, byte_size(Hmac)),
    ok.

test_aes_gcm_encryption(_Config) ->
    % Test AES-GCM encryption/decryption
    Key = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32>>,
    IV = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12>>,
    Plaintext = <<"Secret message">>,
    AAD = <<"Additional authenticated data">>,

    {ok, Ciphertext, Tag} = signal_nif:aes_gcm_encrypt(Key, IV, Plaintext, AAD, 16),
    ?assert(is_binary(Ciphertext)),
    ?assert(is_binary(Tag)),
    ?assertEqual(16, byte_size(Tag)),

    {ok, Decrypted} =
        signal_nif:aes_gcm_decrypt(Key, IV, Ciphertext, AAD, Tag, byte_size(Plaintext)),
    ?assertEqual(Plaintext, Decrypted),
    ok.
