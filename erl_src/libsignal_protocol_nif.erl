-module(libsignal_protocol_nif).

-export([
    init/0,
    generate_identity_key_pair/0,
    generate_pre_key/1,
    generate_signed_pre_key/2,
    create_session/1,
    create_session/2,
    process_pre_key_bundle/2,
    encrypt_message/2,
    decrypt_message/2,
    get_cache_stats/4,
    reset_cache_stats/2,
    set_cache_size/2,
    % Double Ratchet aliases
    init_double_ratchet/4,
    dr_encrypt_message/2,
    dr_decrypt_message/2
]).

-on_load(load_nif/0).

%% NIF loading functions
load_nif() ->
    Paths = ["../priv/libsignal_protocol_nif", "priv/libsignal_protocol_nif", "./priv/libsignal_protocol_nif"],
    load_nif_from_paths(Paths).

load_nif_from_paths([]) ->
    {error, "Could not load libsignal_protocol_nif from any path"};
load_nif_from_paths([Path | Rest]) ->
    case erlang:load_nif(Path, 0) of
        ok ->
            io:format("libsignal_protocol_nif C NIF loaded successfully from ~s~n", [Path]),
            ok;
        {error, {reload, _}} ->
            io:format("libsignal_protocol_nif C NIF already loaded~n"),
            ok;
        {error, Reason} ->
            io:format("Failed to load libsignal_protocol_nif C NIF from ~s: ~p~n", [Path, Reason]),
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

create_session(_PublicKey) ->
    erlang:nif_error(nif_not_loaded).

create_session(_LocalKey, _RemoteKey) ->
    erlang:nif_error(nif_not_loaded).

process_pre_key_bundle(_LocalIdentityKey, _Bundle) ->
    erlang:nif_error(nif_not_loaded).

encrypt_message(_Session, _Message) ->
    erlang:nif_error(nif_not_loaded).

decrypt_message(_Session, _EncryptedMessage) ->
    erlang:nif_error(nif_not_loaded).

% Double Ratchet functions (implemented via cache function name reuse;
% the C side rebinds these names to dr_init / dr_encrypt / dr_decrypt).
% For Alice: SelfIdentityPriv is ignored (she uses a fresh ephemeral);
% RemoteIdentityPub is Bob's identity public key.
% For Bob:   RemoteIdentityPub is ignored; SelfIdentityPriv is his identity
% private key. Bob's encrypt fails until he receives Alice's first message.
get_cache_stats(_SharedSecret, _RemoteIdentityPub, _SelfIdentityPriv, _IsAlice) ->
    erlang:nif_error(nif_not_loaded).

reset_cache_stats(_DrSession, _Message) ->
    erlang:nif_error(nif_not_loaded).

set_cache_size(_DrSession, _EncryptedMessage) ->
    erlang:nif_error(nif_not_loaded).

% Double Ratchet aliases for better API
init_double_ratchet(SharedSecret, RemoteIdentityPub, SelfIdentityPriv, IsAlice) ->
    get_cache_stats(SharedSecret, RemoteIdentityPub, SelfIdentityPriv, IsAlice).

dr_encrypt_message(DrSession, Message) ->
    reset_cache_stats(DrSession, Message).

dr_decrypt_message(DrSession, EncryptedMessage) ->
    set_cache_size(DrSession, EncryptedMessage).

