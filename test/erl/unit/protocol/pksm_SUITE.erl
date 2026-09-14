-module(pksm_SUITE).

%% Verifies PreKeySignalMessage encode + decode, the Bob-side X3DH NIF, and
%% the full Alice -> Bob first-message handshake mediated by PKSM.
%%
%% Alice's side:
%%   1. process_pre_key_bundle/2 -> {SK, AliceEphemeralPub}
%%   2. dr_init/5 (as Alice)
%%   3. dr_encrypt_prekey/3 -> PKSM-wrapped first message
%% Bob's side:
%%   1. pksm_decode/1 -> Alice's identity + ephemeral + spk/opk ids + inner DR
%%   2. process_pre_key_bundle_bob/5 -> SK (same 96B Alice derived)
%%   3. dr_init/5 (as Bob)
%%   4. dr_decrypt/2 on the inner DR message
%%
%% Tests assume the NIF is loaded; init_per_suite gates on dr_test_helpers:nif_or_skip/2.

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([handshake_with_opk/1, handshake_without_opk/1, decode_malformed/1,
         decode_truncated/1, decode_rejects_bad_key_lengths/1, bob_x3dh_matches_alice/1]).

all() ->
    [handshake_with_opk,
     handshake_without_opk,
     decode_malformed,
     decode_truncated,
     decode_rejects_bad_key_lengths,
     bob_x3dh_matches_alice].

init_per_suite(Config) ->
    dr_test_helpers:nif_or_skip(Config, {89, 97, 101}).

end_per_suite(_Config) ->
    ok.

%% ============================================================================
%% Helpers
%% ============================================================================

%% Build Bob's keys and a published bundle using only the documented API:
%% the pre-key generators now return their private halves, so no test-local
%% key minting is needed.
bob_prepare(WithOpk) ->
    {ok, {BobIdPub, BobIdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, {_SpkId, SpkPub, SpkPriv, Signature}} =
        libsignal_protocol_nif:generate_signed_pre_key(BobIdPriv, 1),
    case WithOpk of
        true ->
            {ok, {_OpkId, OpkPub, OpkPriv}} = libsignal_protocol_nif:generate_pre_key(2),
            Bundle = <<BobIdPub/binary, SpkPub/binary, Signature/binary, OpkPub/binary>>,
            #{bundle => Bundle,
              id_pub => BobIdPub,
              id_priv => BobIdPriv,
              spk_priv => SpkPriv,
              opk_priv => OpkPriv};
        false ->
            Bundle = <<BobIdPub/binary, SpkPub/binary, Signature/binary>>,
            #{bundle => Bundle,
              id_pub => BobIdPub,
              id_priv => BobIdPriv,
              spk_priv => SpkPriv,
              opk_priv => <<>>}
    end.

%% ============================================================================
%% Tests
%% ============================================================================

handshake_with_opk(_Config) ->
    handshake_through_pksm(true, 1234, 42, 7).

handshake_without_opk(_Config) ->
    handshake_through_pksm(false, 5678, 99, undefined).

handshake_through_pksm(WithOpk, RegId, SpkId, OpkIdOrUndef) ->
    {ok, {AliceIdPub, AliceIdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    Bob = bob_prepare(WithOpk),

    %% Alice consumes Bob's bundle.
    {ok, {SK, AliceEphPub}} =
        libsignal_protocol_nif:process_pre_key_bundle(AliceIdPriv, maps:get(bundle, Bob)),
    {ok, AliceDr} =
        libsignal_protocol_nif:dr_init(SK, AliceIdPub, maps:get(id_pub, Bob), <<>>, 1),

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
    %% IdKey is Alice's Ed25519 identity pub, exactly what Bob's X3DH and
    %% dr_init need -- he bootstraps from the envelope alone, with no
    %% out-of-band copy of Alice's identity key.
    ?assertEqual(AliceIdPub, IdKey),

    {ok, BobSK} =
        libsignal_protocol_nif:process_pre_key_bundle_bob(
            maps:get(id_priv, Bob),
            maps:get(spk_priv, Bob),
            maps:get(opk_priv, Bob),
            IdKey,
            BaseKey),
    ?assertEqual(SK, BobSK),

    {ok, BobDr} =
        libsignal_protocol_nif:dr_init(BobSK,
                                       maps:get(id_pub, Bob),
                                       IdKey,
                                       maps:get(id_priv, Bob),
                                       0),
    {ok, {Decrypted, _BobDr2}} = libsignal_protocol_nif:dr_decrypt(BobDr, InnerMsg),
    ?assertEqual(Plaintext, Decrypted).

decode_malformed(_Config) ->
    %% Wrong version byte.
    ?assertEqual({error, malformed_message},
                 libsignal_protocol_nif:pksm_decode(<<16#22, 1, 2, 3>>)),
    %% Random garbage with right version byte.
    ?assertEqual({error, malformed_message},
                 libsignal_protocol_nif:pksm_decode(<<16#33, 16#FF, 16#FF, 16#FF, 16#FF>>)),
    %% Empty.
    ?assertEqual({error, malformed_message}, libsignal_protocol_nif:pksm_decode(<<>>)).

decode_truncated(_Config) ->
    %% Build a valid wire then chop the last byte off.
    {ok, {AliceIdPub, AliceIdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    Bob = bob_prepare(false),
    {ok, {SK, AliceEphPub}} =
        libsignal_protocol_nif:process_pre_key_bundle(AliceIdPriv, maps:get(bundle, Bob)),
    {ok, Dr} = libsignal_protocol_nif:dr_init(SK, AliceIdPub, maps:get(id_pub, Bob), <<>>, 1),
    {ok, {Wire, _}} =
        libsignal_protocol_nif:dr_encrypt_prekey(Dr, <<"x">>, {1, undefined, 2, AliceEphPub}),
    Trunc = binary:part(Wire, 0, byte_size(Wire) - 1),
    ?assertEqual({error, malformed_message}, libsignal_protocol_nif:pksm_decode(Trunc)).

%% base_key and identity_key feed straight into process_pre_key_bundle_bob/5
%% and dr_init/5, which require exactly 32 bytes. A decoder that hands back
%% a short or long key just moves the rejection downstream, so pksm_decode
%% enforces the length itself.
decode_rejects_bad_key_lengths(_Config) ->
    Inner = <<"inner">>,
    Good = 32,
    lists:foreach(fun({BaseLen, IdLen}) ->
                     Wire = forged_pksm(BaseLen, IdLen, Inner),
                     ?assertEqual({error, malformed_message},
                                  libsignal_protocol_nif:pksm_decode(Wire),
                                  {BaseLen, IdLen})
                  end,
                  [{0, Good}, {31, Good}, {33, Good}, {64, Good},
                   {Good, 0}, {Good, 31}, {Good, 33}, {Good, 64}]),
    %% Control: the same builder with both keys at 32 bytes decodes.
    ?assertMatch({ok, {7, _, _, undefined, 9, Inner}},
                 libsignal_protocol_nif:pksm_decode(forged_pksm(Good, Good, Inner))).

%% version(0x33) || protobuf{1:reg, 2:base_key, 3:identity_key, 5:spk_id,
%% 6:message} with caller-chosen key lengths. All lengths here are < 128 so
%% each varint is a single byte.
forged_pksm(BaseLen, IdLen, Inner) ->
    <<16#33,
      16#08, 7,
      16#12, BaseLen, (rand:bytes(BaseLen))/binary,
      16#1A, IdLen, (rand:bytes(IdLen))/binary,
      16#28, 9,
      16#32, (byte_size(Inner)), Inner/binary>>.

bob_x3dh_matches_alice(_Config) ->
    %% Same SK on both sides without going through PKSM. Covers the OPK and
    %% no-OPK code paths of the new NIF.
    [bob_x3dh_check(WithOpk) || WithOpk <- [true, false]],
    ok.

bob_x3dh_check(WithOpk) ->
    {ok, {AliceIdPub, AliceIdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    Bob = bob_prepare(WithOpk),
    {ok, {AliceSK, AliceEphPub}} =
        libsignal_protocol_nif:process_pre_key_bundle(AliceIdPriv, maps:get(bundle, Bob)),
    {ok, BobSK} =
        libsignal_protocol_nif:process_pre_key_bundle_bob(
            maps:get(id_priv, Bob),
            maps:get(spk_priv, Bob),
            maps:get(opk_priv, Bob),
            AliceIdPub,
            AliceEphPub),
    ?assertEqual(AliceSK, BobSK).
