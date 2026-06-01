-module(x3dh_dr_compose_SUITE).

%% Verifies that process_pre_key_bundle (X3DH from Alice's side) composes
%% correctly with init_double_ratchet: the 64-byte secret Alice gets from
%% X3DH is a valid root seed for a Double Ratchet session, and Alice + Bob
%% can exchange messages once both initialize DR with that secret.
%%
%% (Bob-side reconstruction of the shared secret is not tested here because
%% libsodium's crypto_box_beforenm applies HSalsa20 on top of X25519, and we
%% don't have HSalsa20 exposed at the Erlang layer. The existing DR suites
%% cover the "given a shared secret, DR works" half; this suite covers the
%% "process_pre_key_bundle output is a valid DR shared secret" half.)
%%
%% Bundle signature is HMAC-SHA512-256(spk_pub, key=id_pub) -- the C uses
%% libsodium's crypto_auth which is HMAC-SHA512-256 (NOT HMAC-SHA256 despite
%% the comment in session.c).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([x3dh_returns_64_byte_secret/1, dr_handshake_after_x3dh/1, random_trials/1]).

all() ->
    [x3dh_returns_64_byte_secret, dr_handshake_after_x3dh, random_trials].

init_per_suite(Config) ->
    rand:seed(exsss, {61, 67, 71}),
    case signal_nif:test_crypto() of
        crypto_ok ->
            Config;
        Other ->
            {skip, {nif_init_failed, Other}}
    end.

end_per_suite(_Config) ->
    ok.

%% ============================================================================
%% Helpers
%% ============================================================================

%% Build Bob's published bundle. Returns {Bundle, BobIdPub, BobIdPriv} so the
%% test can also init Bob's DR side with the matching identity priv.
build_bundle() ->
    {ok, {BobIdPub, BobIdPriv}} = signal_nif:generate_curve25519_keypair(),
    {ok, {SpkPub, _SpkPriv}} = signal_nif:generate_curve25519_keypair(),
    Signature =
        binary:part(
            crypto:mac(hmac, sha512, BobIdPub, SpkPub), 0, 32),
    Bundle = <<BobIdPub/binary, SpkPub/binary, Signature/binary>>,
    {Bundle, BobIdPub, BobIdPriv}.

%% ============================================================================
%% Tests
%% ============================================================================

x3dh_returns_64_byte_secret(_Config) ->
    {ok, {_, AliceIdPriv}} = signal_nif:generate_curve25519_keypair(),
    {Bundle, _BobIdPub, _BobIdPriv} = build_bundle(),
    {ok, {SS, EphPub}} = libsignal_protocol_nif:process_pre_key_bundle(AliceIdPriv, Bundle),
    ?assertEqual(64, byte_size(SS)),
    ?assertEqual(32, byte_size(EphPub)).

dr_handshake_after_x3dh(_Config) ->
    {ok, {_, AliceIdPriv}} = signal_nif:generate_curve25519_keypair(),
    {Bundle, BobIdPub, BobIdPriv} = build_bundle(),
    {ok, {SS, _EphPub}} = libsignal_protocol_nif:process_pre_key_bundle(AliceIdPriv, Bundle),
    {ok, Alice} = libsignal_protocol_nif:init_double_ratchet(SS, BobIdPub, <<>>, 1),
    {ok, Bob} = libsignal_protocol_nif:init_double_ratchet(SS, <<>>, BobIdPriv, 0),
    Msg = <<"x3dh then dr">>,
    {ok, {CT, _}} = libsignal_protocol_nif:dr_encrypt_message(Alice, Msg),
    {ok, {PT, Bob1}} = libsignal_protocol_nif:dr_decrypt_message(Bob, CT),
    ?assertEqual(Msg, PT),
    Reply = <<"reply">>,
    {ok, {CT2, _}} = libsignal_protocol_nif:dr_encrypt_message(Bob1, Reply),
    {ok, {PT2, _}} = libsignal_protocol_nif:dr_decrypt_message(Alice, CT2),
    ?assertEqual(Reply, PT2).

%% Property: any fresh keypair set composes correctly through X3DH + DR.
random_trials(_Config) ->
    [run_trial() || _ <- lists:seq(1, 10)],
    ok.

run_trial() ->
    {ok, {_, AliceIdPriv}} = signal_nif:generate_curve25519_keypair(),
    {Bundle, BobIdPub, BobIdPriv} = build_bundle(),
    {ok, {SS, _EphPub}} = libsignal_protocol_nif:process_pre_key_bundle(AliceIdPriv, Bundle),
    {ok, Alice} = libsignal_protocol_nif:init_double_ratchet(SS, BobIdPub, <<>>, 1),
    {ok, Bob} = libsignal_protocol_nif:init_double_ratchet(SS, <<>>, BobIdPriv, 0),
    Msg = <<"random trial ", (rand:bytes(8))/binary>>,
    {ok, {CT, _}} = libsignal_protocol_nif:dr_encrypt_message(Alice, Msg),
    {ok, {PT, _}} = libsignal_protocol_nif:dr_decrypt_message(Bob, CT),
    ?assertEqual(Msg, PT).
