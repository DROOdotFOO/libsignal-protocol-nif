-module(signal_nif).

-on_load(load_nif/0).

-export([
    test_function/0,
    test_crypto/0,
    sha256/1,
    generate_curve25519_keypair/0,
    generate_ed25519_keypair/0,
    sign_data/2,
    verify_signature/3,
    ed25519_sk_to_curve25519/1,
    ed25519_pk_to_curve25519/1,
    sha512/1,
    hmac_sha256/2,
    aes_gcm_encrypt/5,
    aes_gcm_decrypt/6,
    load_nif/0
]).

test_function() ->
    erlang:nif_error(nif_not_loaded).

test_crypto() ->
    erlang:nif_error(nif_not_loaded).

sha256(_Data) ->
    erlang:nif_error(nif_not_loaded).

generate_curve25519_keypair() ->
    erlang:nif_error(nif_not_loaded).

generate_ed25519_keypair() ->
    erlang:nif_error(nif_not_loaded).

sign_data(_PrivateKey, _Message) ->
    erlang:nif_error(nif_not_loaded).

verify_signature(_PublicKey, _Message, _Signature) ->
    erlang:nif_error(nif_not_loaded).

ed25519_sk_to_curve25519(_EdSecretKey) ->
    erlang:nif_error(nif_not_loaded).

ed25519_pk_to_curve25519(_EdPublicKey) ->
    erlang:nif_error(nif_not_loaded).

sha512(_Data) ->
    erlang:nif_error(nif_not_loaded).

hmac_sha256(_Key, _Data) ->
    erlang:nif_error(nif_not_loaded).

aes_gcm_encrypt(_Key, _IV, _Plaintext, _AAD, _TagLen) ->
    erlang:nif_error(nif_not_loaded).

aes_gcm_decrypt(_Key, _IV, _Ciphertext, _AAD, _Tag, _PlaintextLen) ->
    erlang:nif_error(nif_not_loaded).

load_nif() ->
    % Try multiple possible paths for the NIF library
    % Including paths that work in rebar3 test environments
    Paths = [
        % From project root (development)
        "priv/signal_nif",
        % From current directory
        "./priv/signal_nif",
        % From erl_src (when running from erl_src)
        "../priv/signal_nif",
        % Rebar3 test environment paths
        "../../../../priv/signal_nif",
        "../../../priv/signal_nif",
        "../../priv/signal_nif",
        % Try absolute path using code:priv_dir
        get_priv_path("signal_nif"),
        % Try application priv_dir
        get_app_priv_path("signal_nif")
    ],
    load_nif_from_paths(Paths).

get_priv_path(LibName) ->
    case code:priv_dir(nif) of
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
    case application:get_env(nif, priv_dir) of
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