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

% Suppress Dialyzer warnings for intentionally unused fallback functions
-dialyzer({nowarn_function, [
    init_fallback/0,
    generate_identity_key_pair_fallback/0,
    generate_pre_key_fallback/1,
    generate_signed_pre_key_fallback/2,
    create_session_fallback/1,
    create_session_fallback/2,
    process_pre_key_bundle_fallback/2,
    encrypt_message_fallback/2,
    decrypt_message_fallback/2,
    get_cache_stats_fallback/1,
    reset_cache_stats_fallback/1,
    set_cache_size_fallback/3
]}).

%% NIF loading functions
load_nif() ->
    Paths = ["../priv/libsignal_protocol_nif", "priv/libsignal_protocol_nif", "./priv/libsignal_protocol_nif"],
    load_nif_from_paths(Paths).

load_nif_from_paths([]) ->
    io:format("Warning: libsignal_protocol_nif C NIF not found, using Erlang fallback~n"),
    ok;
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

%% NIF function stubs (will be replaced by C implementations when NIF loads)
%% These serve as fallbacks if the C NIF fails to load

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

%% Erlang fallback implementations (used only if C NIF fails to load)

init_fallback() ->
    ok.

generate_identity_key_pair_fallback() ->
    PublicKey = crypto:strong_rand_bytes(32),
    PrivateKey = crypto:strong_rand_bytes(32),
    {ok, {PublicKey, PrivateKey}}.

generate_pre_key_fallback(KeyId) when is_integer(KeyId) ->
    PreKey = crypto:strong_rand_bytes(32),
    {ok, {KeyId, PreKey}}.

generate_signed_pre_key_fallback(IdentityKey, KeyId) when is_binary(IdentityKey), is_integer(KeyId) ->
    PreKey = crypto:strong_rand_bytes(32),
    Signature = crypto:strong_rand_bytes(64),
    {ok, {KeyId, PreKey, Signature}}.

create_session_fallback(PublicKey) when is_binary(PublicKey) ->
    SessionId = crypto:strong_rand_bytes(32),
    {ok, SessionId}.

create_session_fallback(LocalKey, RemoteKey) when is_binary(LocalKey), is_binary(RemoteKey) ->
    SessionId = crypto:strong_rand_bytes(32),
    {ok, SessionId}.

process_pre_key_bundle_fallback(LocalIdentityKey, Bundle) when is_binary(LocalIdentityKey), is_binary(Bundle) ->
    % Fallback X3DH implementation - returns dummy session key and ephemeral key
    SessionKey = crypto:strong_rand_bytes(64),
    EphemeralKey = crypto:strong_rand_bytes(32),
    {ok, {SessionKey, EphemeralKey}}.

encrypt_message_fallback(Session, Message) when is_binary(Session), is_binary(Message) ->
    % Simple "encryption" - add padding
    Header = <<170,170,170,170,170,170,170,170>>, % 8 bytes of 0xAA
    Footer = <<187,187,187,187,187,187,187,187>>, % 8 bytes of 0xBB
    Encrypted = <<Header/binary, Message/binary, Footer/binary>>,
    {ok, Encrypted}.

decrypt_message_fallback(Session, EncryptedMessage) when is_binary(Session), is_binary(EncryptedMessage) ->
    % Simple "decryption" - remove padding
    case byte_size(EncryptedMessage) of
        Size when Size >= 16 ->
            <<_Header:8/binary, Rest/binary>> = EncryptedMessage,
            MessageSize = Size - 16,
            <<Message:MessageSize/binary, _Footer:8/binary>> = Rest,
            {ok, Message};
        _ ->
            {error, invalid_message}
    end.

get_cache_stats_fallback(_Session) ->
    Stats = #{
        hits => 0,
        misses => 0,
        size => 0
    },
    {ok, Stats}.

reset_cache_stats_fallback(_Session) ->
    ok.

set_cache_size_fallback(_Session, _MaxSize, _TTL) ->
    ok. 