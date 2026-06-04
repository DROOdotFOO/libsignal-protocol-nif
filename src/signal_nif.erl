-module(signal_nif).

-on_load load_nif/0.

-export([test_function/0, test_crypto/0, sha256/1, generate_curve25519_keypair/0,
         generate_ed25519_keypair/0, sign_data/2, verify_signature/3, ed25519_sk_to_curve25519/1,
         ed25519_pk_to_curve25519/1, sha512/1, hmac_sha256/2, aes_gcm_encrypt/5, aes_gcm_decrypt/6,
         load_nif/0]).

-spec test_function() -> ok.
test_function() ->
    erlang:nif_error(nif_not_loaded).

-spec test_crypto() -> crypto_ok.
test_crypto() ->
    erlang:nif_error(nif_not_loaded).

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

-spec load_nif() -> ok | {error, term() | string()}.
load_nif() ->
    % Try multiple possible paths for the NIF library
    % Including paths that work in rebar3 test environments
    Paths =
        [% From project root (development)
         "priv/signal_nif",
         % From current directory
         "./priv/signal_nif",
         % From src (when running from src)
         "../priv/signal_nif",
         % Rebar3 test environment paths
         "../../../../priv/signal_nif",
         "../../../priv/signal_nif",
         "../../priv/signal_nif",
         % Try absolute path using code:priv_dir
         get_priv_path("signal_nif"),
         % Try application priv_dir
         get_app_priv_path("signal_nif")],
    load_nif_from_paths(Paths).

get_priv_path(LibName) ->
    case code:priv_dir(libsignal_protocol_nif) of
        {error, _} ->
            % Fallback to manual path construction
            case code:which(?MODULE) of
                non_existing ->
                    "./priv/" ++ LibName;
                Path ->
                    % Get the directory containing the beam file
                    BeamDir = filename:dirname(Path),
                    % Go up to find priv directory
                    AppDir = filename:dirname(BeamDir),
                    filename:join([AppDir, "priv", LibName])
            end;
        PrivDir ->
            filename:join(PrivDir, LibName)
    end.

get_app_priv_path(LibName) ->
    % Try to find priv directory relative to the application
    case application:get_env(libsignal_protocol_nif, priv_dir) of
        {ok, PrivDir} ->
            filename:join(PrivDir, LibName);
        undefined ->
            % Fallback: try to find it relative to project root
            case file:get_cwd() of
                {ok, Cwd} ->
                    % Look for priv directory in current working directory or parent directories
                    find_priv_dir(Cwd, LibName);
                _ ->
                    "./priv/" ++ LibName
            end
    end.

find_priv_dir(Dir, LibName) ->
    PrivPath = filename:join([Dir, "priv", LibName]),
    case filelib:is_file(PrivPath ++ ".so") of
        true ->
            PrivPath;
        false ->
            Parent = filename:dirname(Dir),
            case Parent of
                Dir -> % Reached root directory
                    "./priv/" ++ LibName;
                _ ->
                    find_priv_dir(Parent, LibName)
            end
    end.

load_nif_from_paths([]) ->
    {error, "Could not load signal_nif from any path"};
load_nif_from_paths([Path | Rest]) ->
    case erlang:load_nif(Path, 0) of
        ok ->
            ok;
        {error, {load_failed, _Reason}} ->
            load_nif_from_paths(Rest);
        {error, {upgrade, _}} ->
            % NIF is already loaded, this is fine
            ok;
        {error, _Reason} ->
            load_nif_from_paths(Rest)
    end.
