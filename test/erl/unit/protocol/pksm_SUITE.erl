-module(pksm_SUITE).

%% Verifies PreKeySignalMessage encode + decode, the Bob-side X3DH NIF, and
%% the full Alice -> Bob first-message handshake mediated by PKSM.
%%
%% Alice's side:
%%   1. process_pre_key_bundle/2 -> {SK, AliceEphemeralPub}
%%   2. init_double_ratchet/5 (as Alice)
%%   3. dr_encrypt_prekey/3 -> PKSM-wrapped first message
%% Bob's side:
%%   1. pksm_decode/1 -> Alice's identity + ephemeral + spk/opk ids + inner DR
%%   2. process_pre_key_bundle_bob/5 -> SK (same 64B Alice derived)
%%   3. init_double_ratchet/5 (as Bob)
%%   4. dr_decrypt/2 on the inner DR message
%%
%% Tests assume the NIF is loaded; init_per_suite gates on signal_nif:test_crypto/0.

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([handshake_with_opk/1, handshake_without_opk/1,
         decode_malformed/1, decode_truncated/1,
         bob_x3dh_matches_alice/1]).

all() ->
    [handshake_with_opk,
     handshake_without_opk,
     decode_malformed,
     decode_truncated,
     bob_x3dh_matches_alice].

init_per_suite(Config) ->
    rand:seed(exsss, {89, 97, 101}),
    case signal_nif:test_crypto() of
        crypto_ok -> Config;
        Other -> {skip, {nif_init_failed, Other}}
    end.

end_per_suite(_Config) ->
    ok.

%% ============================================================================
%% Helpers
%% ============================================================================

%% Build Bob's keys and a published bundle. Returns everything the test
%% needs to drive both sides of the handshake.
bob_prepare(WithOpk) ->
    {ok, {BobIdPub, BobIdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    %% Mint the SPK keypair ourselves so we retain the SPK priv. The NIF's
    %% generate_signed_pre_key/2 destroys the priv.
    {ok, {SpkPub, SpkPriv}} = signal_nif:generate_curve25519_keypair(),
    BobIdSeed = binary:part(BobIdPriv, 0, 32),
    {ok, Signature} = signal_nif:sign_data(BobIdSeed, SpkPub),
    case WithOpk of
        true ->
            {ok, {OpkPub, OpkPriv}} = signal_nif:generate_curve25519_keypair(),
            Bundle = <<BobIdPub/binary, SpkPub/binary, Signature/binary,
                       OpkPub/binary>>,
            #{bundle => Bundle, id_pub => BobIdPub, id_priv => BobIdPriv,
              spk_priv => SpkPriv, opk_priv => OpkPriv};
        false ->
            Bundle = <<BobIdPub/binary, SpkPub/binary, Signature/binary>>,
            #{bundle => Bundle, id_pub => BobIdPub, id_priv => BobIdPriv,
              spk_priv => SpkPriv, opk_priv => <<>>}
    end.

%% ============================================================================
%% Tests
%% ============================================================================

handshake_with_opk(_Config) ->
    handshake_through_pksm(true, 1234, 42, 7).

handshake_without_opk(_Config) ->
    handshake_through_pksm(false, 5678, 99, undefined).

handshake_through_pksm(WithOpk, RegId, SpkId, OpkIdOrUndef) ->
    {ok, {AliceIdPub, AliceIdPriv}} =
        libsignal_protocol_nif:generate_identity_key_pair(),
    Bob = bob_prepare(WithOpk),

    %% Alice consumes Bob's bundle.
    {ok, {SK, AliceEphPub}} =
        libsignal_protocol_nif:process_pre_key_bundle(AliceIdPriv,
                                                     maps:get(bundle, Bob)),
    {ok, AliceDr} =
        libsignal_protocol_nif:init_double_ratchet(SK, AliceIdPub,
                                                   maps:get(id_pub, Bob),
                                                   <<>>, 1),

    Plaintext = <<"hello bob via PKSM">>,
    Info = {RegId, OpkIdOrUndef, SpkId, AliceEphPub},
    {ok, {Wire, _AliceDr2}} =
        libsignal_protocol_nif:dr_encrypt_prekey(AliceDr, Plaintext, Info),

    %% Bob parses PKSM.
    {ok, {DecReg, BaseKey, IdKey, DecOpkId, DecSpkId, InnerMsg}} =
        libsignal_protocol_nif:pksm_decode(Wire),
    ?assertEqual(RegId, DecReg),
    ?assertEqual(SpkId, DecSpkId),
    ?assertEqual(OpkIdOrUndef, DecOpkId),
    ?assertEqual(AliceEphPub, BaseKey),
    %% IdKey is Alice's X25519 identity pub (the X-form of her Ed25519 pub).
    {ok, AliceIdPubX} = signal_nif:ed25519_pk_to_curve25519(AliceIdPub),
    ?assertEqual(AliceIdPubX, IdKey),

    %% Bob derives SK via the new Bob-side X3DH NIF.
    {ok, BobSK} =
        libsignal_protocol_nif:process_pre_key_bundle_bob(
            maps:get(id_priv, Bob),
            maps:get(spk_priv, Bob),
            maps:get(opk_priv, Bob),
            AliceIdPub,
            AliceEphPub),
    ?assertEqual(SK, BobSK),

    {ok, BobDr} =
        libsignal_protocol_nif:init_double_ratchet(BobSK, maps:get(id_pub, Bob),
                                                   AliceIdPub,
                                                   maps:get(id_priv, Bob), 0),
    {ok, {Decrypted, _BobDr2}} =
        libsignal_protocol_nif:dr_decrypt(BobDr, InnerMsg),
    ?assertEqual(Plaintext, Decrypted).

decode_malformed(_Config) ->
    %% Wrong version byte.
    ?assertEqual({error, malformed_message},
                 libsignal_protocol_nif:pksm_decode(<<16#22, 1, 2, 3>>)),
    %% Random garbage with right version byte.
    ?assertEqual({error, malformed_message},
                 libsignal_protocol_nif:pksm_decode(
                     <<16#33, 16#FF, 16#FF, 16#FF, 16#FF>>)),
    %% Empty.
    ?assertEqual({error, malformed_message},
                 libsignal_protocol_nif:pksm_decode(<<>>)).

decode_truncated(_Config) ->
    %% Build a valid wire then chop the last byte off.
    {ok, {AliceIdPub, AliceIdPriv}} =
        libsignal_protocol_nif:generate_identity_key_pair(),
    Bob = bob_prepare(false),
    {ok, {SK, AliceEphPub}} =
        libsignal_protocol_nif:process_pre_key_bundle(AliceIdPriv,
                                                     maps:get(bundle, Bob)),
    {ok, Dr} =
        libsignal_protocol_nif:init_double_ratchet(SK, AliceIdPub,
                                                   maps:get(id_pub, Bob),
                                                   <<>>, 1),
    {ok, {Wire, _}} =
        libsignal_protocol_nif:dr_encrypt_prekey(Dr, <<"x">>,
                                                 {1, undefined, 2, AliceEphPub}),
    Trunc = binary:part(Wire, 0, byte_size(Wire) - 1),
    ?assertEqual({error, malformed_message},
                 libsignal_protocol_nif:pksm_decode(Trunc)).

bob_x3dh_matches_alice(_Config) ->
    %% Same SK on both sides without going through PKSM. Covers the OPK and
    %% no-OPK code paths of the new NIF.
    [bob_x3dh_check(WithOpk) || WithOpk <- [true, false]],
    ok.

bob_x3dh_check(WithOpk) ->
    {ok, {AliceIdPub, AliceIdPriv}} =
        libsignal_protocol_nif:generate_identity_key_pair(),
    Bob = bob_prepare(WithOpk),
    {ok, {AliceSK, AliceEphPub}} =
        libsignal_protocol_nif:process_pre_key_bundle(AliceIdPriv,
                                                     maps:get(bundle, Bob)),
    {ok, BobSK} =
        libsignal_protocol_nif:process_pre_key_bundle_bob(
            maps:get(id_priv, Bob),
            maps:get(spk_priv, Bob),
            maps:get(opk_priv, Bob),
            AliceIdPub,
            AliceEphPub),
    ?assertEqual(AliceSK, BobSK).
