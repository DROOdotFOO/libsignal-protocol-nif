-module(libsignal_protocol_nif).

-export([
    init/0,
    generate_identity_key_pair/0,
    generate_pre_key/1,
    generate_signed_pre_key/2,
    create_session/2,
    process_pre_key_bundle/2,
    process_pre_key_bundle_bob/5,
    encrypt_message/2,
    decrypt_message/2,
    dr_init/5,
    dr_encrypt/2,
    dr_encrypt_prekey/3,
    dr_decrypt/2,
    pksm_decode/1,
    % Double Ratchet aliases
    init_double_ratchet/5,
    dr_encrypt_message/2,
    dr_decrypt_message/2
]).

-on_load(load_nif/0).

%% NIF loading functions
load_nif() ->
    %% Prefer the OTP-app-resolved priv dir (works from anywhere the
    %% libsignal_protocol_nif beam is on the code path -- e.g. when the
    %% Elixir/Gleam wrappers add this project's _build/default/lib/.../ebin
    %% to their own code path for tests). Fall back to relative paths for
    %% the rebar3-direct workflow where CWD is the project root.
    AppPath =
        case code:priv_dir(libsignal_protocol_nif) of
            {error, _} -> [];
            Dir -> [filename:join(Dir, "libsignal_protocol_nif")]
        end,
    Paths = AppPath ++
            ["../priv/libsignal_protocol_nif",
             "priv/libsignal_protocol_nif",
             "./priv/libsignal_protocol_nif"],
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

create_session(_LocalKey, _RemoteKey) ->
    erlang:nif_error(nif_not_loaded).

process_pre_key_bundle(_LocalIdentityKey, _Bundle) ->
    erlang:nif_error(nif_not_loaded).

%% Bob-side X3DH. Inputs are Bob's private material plus the two pubs Alice
%% sends with her first message (her identity pub and her ephemeral pub).
%% IdentityPriv: 64B Ed25519 secret (Bob's identity).
%% SignedPreKeyPriv: 32B X25519 secret (the SPK Alice consumed from his bundle).
%% OneTimePreKeyPriv: 32B X25519 secret or <<>> if no OPK was used.
%% RemoteIdentityPub: 32B Ed25519 (Alice's identity pub).
%% RemoteEphemeralPub: 32B X25519 (Alice's ephemeral, returned by her
%%   process_pre_key_bundle/2). Returns {ok, SharedSecret} with the same 64B
%%   SK Alice derived.
process_pre_key_bundle_bob(_IdentityPriv, _SignedPreKeyPriv, _OneTimePreKeyPriv,
                           _RemoteIdentityPub, _RemoteEphemeralPub) ->
    erlang:nif_error(nif_not_loaded).

encrypt_message(_Session, _Message) ->
    erlang:nif_error(nif_not_loaded).

decrypt_message(_Session, _EncryptedMessage) ->
    erlang:nif_error(nif_not_loaded).

% Double Ratchet functions.
% LocalIdentityPub and RemoteIdentityPub are Ed25519 identity public keys
% (32B each). At init they are converted to X25519 form via
% crypto_sign_ed25519_pk_to_curve25519 and the X25519 form is what gets folded
% into every MAC -- Signal-spec scope:
%   sender_x25519_id || receiver_x25519_id || version || serialized_message
% Callers pass Ed25519 form to keep the public API aligned with how we hand out
% identity keys elsewhere (generate_identity_key_pair returns Ed25519).
% For Alice: SelfIdentityPriv may be <<>> (she uses a fresh ephemeral for DH);
%   RemoteIdentityPub is Bob's Ed25519 identity public key.
% For Bob:   SelfIdentityPriv is his 64B Ed25519 identity private key,
%   converted to X25519 internally for the initial DH ratchet pair. Bob's
%   encrypt fails until he receives Alice's first message.
dr_init(_SharedSecret, _LocalIdentityPub, _RemoteIdentityPub,
        _SelfIdentityPriv, _IsAlice) ->
    erlang:nif_error(nif_not_loaded).

dr_encrypt(_DrSession, _Message) ->
    erlang:nif_error(nif_not_loaded).

%% Encrypt Alice's first message and wrap it in a PreKeySignalMessage envelope
%% so Bob can recover the X3DH SK before decrypting the inner SignalMessage.
%% PreKeyInfo = {RegistrationId, OneTimePreKeyId | undefined, SignedPreKeyId,
%%               AliceX3dhEphemeralPub}. AliceX3dhEphemeralPub is the 32B X25519
%% pub returned by process_pre_key_bundle/2.
%% Returns {ok, {PksmWireBytes, NewSession}} | {error, Atom}.
dr_encrypt_prekey(_DrSession, _Message, _PreKeyInfo) ->
    erlang:nif_error(nif_not_loaded).

dr_decrypt(_DrSession, _EncryptedMessage) ->
    erlang:nif_error(nif_not_loaded).

%% Decode a PreKeySignalMessage wire envelope. Pure parse -- Bob's side then
%% looks up his SPK/OPK by id, runs process_pre_key_bundle_bob/5 to derive SK,
%% calls init_double_ratchet/5, and decrypts the InnerMessage with dr_decrypt/2.
%% Returns
%%   {ok, {RegistrationId, BaseKey, IdentityKey, OneTimePreKeyId | undefined,
%%         SignedPreKeyId, InnerMessage}}
%% | {error, malformed_message}.
pksm_decode(_Wire) ->
    erlang:nif_error(nif_not_loaded).

% Double Ratchet aliases for better API
init_double_ratchet(SharedSecret, LocalIdentityPub, RemoteIdentityPub,
                    SelfIdentityPriv, IsAlice) ->
    dr_init(SharedSecret, LocalIdentityPub, RemoteIdentityPub,
            SelfIdentityPriv, IsAlice).

dr_encrypt_message(DrSession, Message) ->
    dr_encrypt(DrSession, Message).

dr_decrypt_message(DrSession, EncryptedMessage) ->
    dr_decrypt(DrSession, EncryptedMessage).

