-module(signal_nif).

-on_load load_nif/0.

-export([sha256/1, generate_curve25519_keypair/0, generate_ed25519_keypair/0, sign_data/2,
         verify_signature/3, ed25519_sk_to_curve25519/1, ed25519_pk_to_curve25519/1, sha512/1,
         hmac_sha256/2, aes_gcm_encrypt/5, aes_gcm_decrypt/6]).

%% See libsignal_nif_loader for the path-resolution strategy. The fun must
%% live in this module so erlang:load_nif/2 attaches the library here.
-spec load_nif() -> ok | {error, term()}.
load_nif() ->
    libsignal_nif_loader:load(?MODULE, fun(Path) -> erlang:load_nif(Path, 0) end).

-spec sha256(Data :: binary()) -> {ok, Hash :: binary()}.
sha256(_Data) ->
    erlang:nif_error(nif_not_loaded).

-spec generate_curve25519_keypair() ->
                                     {ok, {Pub :: binary(), Priv :: binary()}} | {error, atom()}.
generate_curve25519_keypair() ->
    erlang:nif_error(nif_not_loaded).

%% Pub is 32 bytes; Priv is the 64-byte libsodium secret key
%% (seed || derived pub), accepted as-is by sign_data/2 and
%% ed25519_sk_to_curve25519/1.
-spec generate_ed25519_keypair() ->
                                  {ok, {Pub :: binary(), Priv :: binary()}} | {error, atom()}.
generate_ed25519_keypair() ->
    erlang:nif_error(nif_not_loaded).

-spec sign_data(PrivateKey :: binary(), Message :: binary()) ->
                   {ok, Signature :: binary()} | {error, atom()}.
sign_data(_PrivateKey, _Message) ->
    erlang:nif_error(nif_not_loaded).

-spec verify_signature(PublicKey :: binary(),
                       Message :: binary(),
                       Signature :: binary()) ->
                          ok | invalid_signature | {error, atom()}.
verify_signature(_PublicKey, _Message, _Signature) ->
    erlang:nif_error(nif_not_loaded).

-spec ed25519_sk_to_curve25519(EdSecretKey :: binary()) ->
                                  {ok, X25519Priv :: binary()} | {error, atom()}.
ed25519_sk_to_curve25519(_EdSecretKey) ->
    erlang:nif_error(nif_not_loaded).

-spec ed25519_pk_to_curve25519(EdPublicKey :: binary()) ->
                                  {ok, X25519Pub :: binary()} | {error, atom()}.
ed25519_pk_to_curve25519(_EdPublicKey) ->
    erlang:nif_error(nif_not_loaded).

-spec sha512(Data :: binary()) -> {ok, Hash :: binary()}.
sha512(_Data) ->
    erlang:nif_error(nif_not_loaded).

-spec hmac_sha256(Key :: binary(), Data :: binary()) ->
                     {ok, Mac :: binary()} | {error, atom()}.
hmac_sha256(_Key, _Data) ->
    erlang:nif_error(nif_not_loaded).

-spec aes_gcm_encrypt(Key :: binary(),
                      IV :: binary(),
                      Plaintext :: binary(),
                      AAD :: binary(),
                      TagLen :: non_neg_integer()) ->
                         {ok, Ciphertext :: binary(), Tag :: binary()} | {error, atom()}.
aes_gcm_encrypt(_Key, _IV, _Plaintext, _AAD, _TagLen) ->
    erlang:nif_error(nif_not_loaded).

-spec aes_gcm_decrypt(Key :: binary(),
                      IV :: binary(),
                      Ciphertext :: binary(),
                      AAD :: binary(),
                      Tag :: binary(),
                      PlaintextLen :: non_neg_integer()) ->
                         {ok, Plaintext :: binary()} | {error, atom()}.
aes_gcm_decrypt(_Key, _IV, _Ciphertext, _AAD, _Tag, _PlaintextLen) ->
    erlang:nif_error(nif_not_loaded).

