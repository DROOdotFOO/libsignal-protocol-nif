-module(dr_he_bootstrap_SUITE).

%% Pins the DR-HE state-layout + KDF-expansion contract change.
%%
%% After dr_init was widened to accept a 96B shared_secret (64B X3DH SK
%% concatenated with a 32B shared header-key seed), the public NIF must:
%%   - reject anything other than 96B with invalid_shared_secret_size,
%%   - accept exactly 96B and return a usable DR state.
%%
%% Internal symmetry (Alice HKs == Bob HKr after the first ratchet step) is
%% not externally observable until DR-HE is on the wire; that invariant gets
%% pinned by the cross-decrypt round-trip in the follow-up wire-format suite.
%% Here we only fix the observable contract.

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([rejects_64_byte_shared_secret/1,
         rejects_95_byte_shared_secret/1,
         rejects_zero_byte_shared_secret/1,
         accepts_96_byte_shared_secret/1,
         dr_state_grows_for_header_keys/1]).

all() ->
    [rejects_64_byte_shared_secret,
     rejects_95_byte_shared_secret,
     rejects_zero_byte_shared_secret,
     accepts_96_byte_shared_secret,
     dr_state_grows_for_header_keys].

init_per_suite(Config) ->
    case signal_nif:test_crypto() of
        crypto_ok -> Config;
        Other -> {skip, {nif_init_failed, Other}}
    end.

end_per_suite(_Config) ->
    ok.

%% ============================================================================
%% Tests
%% ============================================================================

rejects_64_byte_shared_secret(_Config) ->
    {AlicePub, _AlicePriv, BobPub, _BobPriv} = fresh_identities(),
    SS = rand:bytes(64),
    ?assertEqual({error, invalid_shared_secret_size},
                 libsignal_protocol_nif:dr_init(
                   SS, AlicePub, BobPub, <<>>, 1)).

rejects_95_byte_shared_secret(_Config) ->
    {AlicePub, _AlicePriv, BobPub, _BobPriv} = fresh_identities(),
    SS = rand:bytes(95),
    ?assertEqual({error, invalid_shared_secret_size},
                 libsignal_protocol_nif:dr_init(
                   SS, AlicePub, BobPub, <<>>, 1)).

rejects_zero_byte_shared_secret(_Config) ->
    {AlicePub, _AlicePriv, BobPub, _BobPriv} = fresh_identities(),
    ?assertEqual({error, invalid_shared_secret_size},
                 libsignal_protocol_nif:dr_init(
                   <<>>, AlicePub, BobPub, <<>>, 1)).

accepts_96_byte_shared_secret(_Config) ->
    {AlicePub, _AlicePriv, BobPub, BobPriv} = fresh_identities(),
    SS = rand:bytes(96),
    ?assertMatch({ok, _},
                 libsignal_protocol_nif:dr_init(
                   SS, AlicePub, BobPub, <<>>, 1)),
    ?assertMatch({ok, _},
                 libsignal_protocol_nif:dr_init(
                   SS, BobPub, AlicePub, BobPriv, 0)).

%% Pin the DR state binary size on this build target so unintended struct
%% growth (extra fields, padding) is caught at test time. 2836 bytes equals
%% the prior 2708-byte struct plus 4 * 32 = 128 bytes of header-key fields.
%% Padding/alignment is platform-dependent; if this fails on a new target,
%% confirm the delta matches the 128B header-key addition before updating.
dr_state_grows_for_header_keys(_Config) ->
    {AlicePub, _AlicePriv, BobPub, _BobPriv} = fresh_identities(),
    SS = rand:bytes(96),
    {ok, Alice} =
        libsignal_protocol_nif:dr_init(SS, AlicePub, BobPub, <<>>, 1),
    ?assertEqual(2836, byte_size(Alice)).

%% ============================================================================
%% Helpers
%% ============================================================================

fresh_identities() ->
    {ok, {AlicePub, AlicePriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, {BobPub, BobPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {AlicePub, AlicePriv, BobPub, BobPriv}.
