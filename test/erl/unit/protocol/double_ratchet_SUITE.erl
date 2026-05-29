-module(double_ratchet_SUITE).

%% Double Ratchet roundtrip properties for the libsignal_protocol_nif DR API
%% (exposed as init_double_ratchet / dr_encrypt_message / dr_decrypt_message,
%%  bound in C as get_cache_stats / reset_cache_stats / set_cache_size).
%%
%% Most tests in this suite currently FAIL. They document a bug in
%% c_src/libsignal_protocol_nif.c:dh_ratchet() -- the helper only updates
%% state->send_chain_key, never recv_chain_key, so the decrypt path uses a
%% stale/zero chain key whenever a DH ratchet is triggered on receive.
%%
%% Concretely: only the Bob -> Alice direction works, because the initial
%% chain keys happen to align via shared_secret[32..64]. Every other case
%% returns {error, decryption_failed}.
%%
%% Keeping these tests RED until the C side derives a new recv_chain_key
%% during dh_ratchet (per the Double Ratchet specification).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2]).
-export([
    bob_to_alice_first_message_roundtrips/1,
    bob_to_alice_sequential_messages_roundtrip/1,
    alice_to_bob_first_message_roundtrips/1,
    alice_responds_after_bob_initiates/1,
    bidirectional_handshake/1,
    ciphertext_tamper_rejected/1,
    replay_rejected/1
]).

all() ->
    [
        bob_to_alice_first_message_roundtrips,
        bob_to_alice_sequential_messages_roundtrip,
        alice_to_bob_first_message_roundtrips,
        alice_responds_after_bob_initiates,
        bidirectional_handshake,
        ciphertext_tamper_rejected,
        replay_rejected
    ].

init_per_suite(Config) ->
    rand:seed(exsss, {19, 23, 29}),
    case signal_nif:test_crypto() of
        crypto_ok -> Config;
        Other -> {skip, {nif_init_failed, Other}}
    end.

end_per_suite(_Config) -> ok.

init_per_testcase(_Name, Config) ->
    {ok, {AlicePub, _}} = signal_nif:generate_curve25519_keypair(),
    {ok, {BobPub,   _}} = signal_nif:generate_curve25519_keypair(),
    SS = rand:bytes(64),
    {ok, AliceState} = libsignal_protocol_nif:init_double_ratchet(SS, BobPub, 1),
    {ok, BobState}   = libsignal_protocol_nif:init_double_ratchet(SS, AlicePub, 0),
    [{alice, AliceState}, {bob, BobState} | Config].

%% ============================================================================
%% Known-good direction: Bob -> Alice. These should PASS today.
%% ============================================================================

bob_to_alice_first_message_roundtrips(Config) ->
    {Alice, Bob} = parties(Config),
    Msg = <<"reply from bob">>,
    {ok, {CT, _Bob1}} = libsignal_protocol_nif:dr_encrypt_message(Bob, Msg),
    {ok, {PT, _Alice1}} = libsignal_protocol_nif:dr_decrypt_message(Alice, CT),
    ?assertEqual(Msg, PT).

bob_to_alice_sequential_messages_roundtrip(Config) ->
    {Alice0, Bob0} = parties(Config),
    Msgs = [rand:bytes(N) || N <- [1, 16, 256, 1024]],
    {_, _, Decrypted} = lists:foldl(
        fun(M, {Asend, Bsend, Acc}) ->
            {ok, {CT, Bnext}} = libsignal_protocol_nif:dr_encrypt_message(Bsend, M),
            {ok, {PT, Anext}} = libsignal_protocol_nif:dr_decrypt_message(Asend, CT),
            {Anext, Bnext, [PT | Acc]}
        end,
        {Alice0, Bob0, []},
        Msgs
    ),
    ?assertEqual(Msgs, lists:reverse(Decrypted)).

%% ============================================================================
%% Known-failing directions: every test below documents a real bug.
%% ============================================================================

alice_to_bob_first_message_roundtrips(Config) ->
    {Alice, Bob} = parties(Config),
    Msg = <<"hello from alice">>,
    {ok, {CT, _}} = libsignal_protocol_nif:dr_encrypt_message(Alice, Msg),
    Result = libsignal_protocol_nif:dr_decrypt_message(Bob, CT),
    %% BUG: dh_ratchet() does not update recv_chain_key, so Bob can never
    %% decrypt a first message from Alice. Expected: {ok, {Msg, _BobNext}}.
    ?assertMatch({ok, {Msg, _}}, Result).

alice_responds_after_bob_initiates(Config) ->
    {Alice0, Bob0} = parties(Config),
    %% Establish baseline: Bob -> Alice works.
    {ok, {CT_b2a, _Bob1}} = libsignal_protocol_nif:dr_encrypt_message(Bob0, <<"first from bob">>),
    {ok, {_, Alice1}} = libsignal_protocol_nif:dr_decrypt_message(Alice0, CT_b2a),
    %% Now Alice should be able to respond. Her dr_encrypt_message uses her
    %% post-receive state. Bob decrypts using his post-encrypt state.
    {ok, {CT_a2b, _Alice2}} = libsignal_protocol_nif:dr_encrypt_message(Alice1, <<"alice replies">>),
    Result = libsignal_protocol_nif:dr_decrypt_message(Bob0, CT_a2b),
    %% BUG: same root cause -- Bob would need a fresh recv_chain_key derived
    %% from KDF(root, DH(bob_priv, alice_new_pub)), but dh_ratchet() only
    %% writes send_chain_key.
    ?assertMatch({ok, {<<"alice replies">>, _}}, Result).

bidirectional_handshake(Config) ->
    {Alice0, Bob0} = parties(Config),
    %% Simulate the textbook DR handshake: Alice greets Bob, Bob replies.
    {ok, {CT_hi, Alice1}} =
        libsignal_protocol_nif:dr_encrypt_message(Alice0, <<"hi">>),
    {ok, {<<"hi">>, Bob1}} =
        libsignal_protocol_nif:dr_decrypt_message(Bob0, CT_hi),
    {ok, {CT_re, _}} =
        libsignal_protocol_nif:dr_encrypt_message(Bob1, <<"hi back">>),
    Result = libsignal_protocol_nif:dr_decrypt_message(Alice1, CT_re),
    ?assertMatch({ok, {<<"hi back">>, _}}, Result).

ciphertext_tamper_rejected(Config) ->
    {Alice, Bob} = parties(Config),
    %% Use Bob->Alice direction since that's the only one that decrypts at all.
    {ok, {CT, _}} = libsignal_protocol_nif:dr_encrypt_message(Bob, <<"data">>),
    Tampered = flip_first_byte(CT, 60), %% flip a byte in the ciphertext region
    Result = libsignal_protocol_nif:dr_decrypt_message(Alice, Tampered),
    ?assertMatch({error, _}, Result).

replay_rejected(Config) ->
    {Alice0, Bob} = parties(Config),
    {ok, {CT, _}} = libsignal_protocol_nif:dr_encrypt_message(Bob, <<"once">>),
    {ok, {_, Alice1}} = libsignal_protocol_nif:dr_decrypt_message(Alice0, CT),
    %% Re-submitting the same ciphertext to the advanced state must NOT succeed.
    Result = libsignal_protocol_nif:dr_decrypt_message(Alice1, CT),
    ?assertMatch({error, _}, Result).

%% ============================================================================
%% Helpers
%% ============================================================================

parties(Config) ->
    {?config(alice, Config), ?config(bob, Config)}.

flip_first_byte(Bin, Offset) when Offset < byte_size(Bin) ->
    <<Pre:Offset/binary, B:8, Rest/binary>> = Bin,
    <<Pre/binary, (B bxor 16#01):8, Rest/binary>>.
