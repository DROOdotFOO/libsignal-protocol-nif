-module(libsignal_protocol_nif_v2).

-export([
    init/0,
    generate_identity_key_pair/0,
    generate_pre_key/1,
    generate_signed_pre_key/2,
    process_pre_key_bundle/2,
    init_double_ratchet/3,
    dr_encrypt_message/2,
    dr_decrypt_message/2
]).

-on_load(load_nif/0).

%% NIF loading functions
load_nif() ->
    Paths = ["../priv/libsignal_protocol_nif_v2", "priv/libsignal_protocol_nif_v2", "./priv/libsignal_protocol_nif_v2"],
    load_nif_from_paths(Paths).

load_nif_from_paths([]) ->
    {error, "Could not load libsignal_protocol_nif_v2 from any path"};
load_nif_from_paths([Path | Rest]) ->
    case erlang:load_nif(Path, 0) of
        ok ->
            io:format("libsignal_protocol_nif_v2 C NIF loaded successfully from ~s~n", [Path]),
            ok;
        {error, {reload, _}} ->
            io:format("libsignal_protocol_nif_v2 C NIF already loaded~n"),
            ok;
        {error, Reason} ->
            io:format("Failed to load libsignal_protocol_nif_v2 C NIF from ~s: ~p~n", [Path, Reason]),
            load_nif_from_paths(Rest)
    end.

%% NIF function stubs (replaced by C implementations when NIF loads).
%% If load_nif/0 fails, the module itself fails to load (see -on_load).
%% These bodies only fire if a caller reaches them through a dev hot-reload
%% without the NIF attached -- never in a production load path.

init() ->
    erlang:nif_error(nif_not_loaded).

generate_identity_key_pair() ->
    erlang:nif_error(nif_not_loaded).

generate_pre_key(_KeyId) ->
    erlang:nif_error(nif_not_loaded).

generate_signed_pre_key(_IdentityKey, _KeyId) ->
    erlang:nif_error(nif_not_loaded).

process_pre_key_bundle(_LocalIdentityKey, _Bundle) ->
    erlang:nif_error(nif_not_loaded).

init_double_ratchet(_SharedSecret, _RemotePublicKey, _IsAlice) ->
    erlang:nif_error(nif_not_loaded).

dr_encrypt_message(_DrSession, _Message) ->
    erlang:nif_error(nif_not_loaded).

dr_decrypt_message(_DrSession, _EncryptedMessage) ->
    erlang:nif_error(nif_not_loaded).

