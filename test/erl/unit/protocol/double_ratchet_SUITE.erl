-module(double_ratchet_SUITE).

%% Double Ratchet semantics tests for libsignal_protocol_nif. Canonical
%% Signal DR usage: Alice (initiator) sends first using Bob's identity pub.
%% Bob (responder) holds his identity priv and cannot send until Alice's
%% first message arrives and his receive ratchet derives his send chain.
%%
%% Exposed via init_double_ratchet/4 (SS, RemoteIdentityPub, SelfIdentityPriv,
%% IsAlice), dr_encrypt_message/2, dr_decrypt_message/2.

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2]).
-export([
    alice_to_bob_first_message_roundtrips/1,
    alice_to_bob_sequential_roundtrip/1,
    bob_cannot_send_before_receiving/1,
    bob_responds_after_alice_initiates/1,
    bidirectional_handshake/1,
    multi_turn_conversation/1,
    ciphertext_tamper_rejected/1,
    replay_rejected/1
]).

all() ->
    [
        alice_to_bob_first_message_roundtrips,
        alice_to_bob_sequential_roundtrip,
        bob_cannot_send_before_receiving,
        bob_responds_after_alice_initiates,
        bidirectional_handshake,
        multi_turn_conversation,
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
    {ok, {BobPub, BobPriv}} = signal_nif:generate_curve25519_keypair(),
    SS = rand:bytes(64),
    {ok, Alice} = libsignal_protocol_nif:init_double_ratchet(SS, BobPub, <<>>, 1),
    {ok, Bob}   = libsignal_protocol_nif:init_double_ratchet(SS, <<>>, BobPriv, 0),
    [{alice, Alice}, {bob, Bob} | Config].

%% ============================================================================
%% Canonical DR: Alice initiates
%% ============================================================================

alice_to_bob_first_message_roundtrips(Config) ->
    {Alice, Bob} = parties(Config),
    Msg = <<"hello from alice">>,
    {ok, {CT, _}} = libsignal_protocol_nif:dr_encrypt_message(Alice, Msg),
    {ok, {PT, _}} = libsignal_protocol_nif:dr_decrypt_message(Bob, CT),
    ?assertEqual(Msg, PT).

alice_to_bob_sequential_roundtrip(Config) ->
    {Alice0, Bob0} = parties(Config),
    Msgs = [rand:bytes(N) || N <- [1, 16, 256, 1024]],
    {_, _, Decrypted} = lists:foldl(
        fun(M, {Asend, Brecv, Acc}) ->
            {ok, {CT, Anext}} = libsignal_protocol_nif:dr_encrypt_message(Asend, M),
            {ok, {PT, Bnext}} = libsignal_protocol_nif:dr_decrypt_message(Brecv, CT),
            {Anext, Bnext, [PT | Acc]}
        end,
        {Alice0, Bob0, []},
        Msgs
    ),
    ?assertEqual(Msgs, lists:reverse(Decrypted)).

%% ============================================================================
%% Bob is the responder: can't send before receiving
%% ============================================================================

bob_cannot_send_before_receiving(Config) ->
    {_, Bob} = parties(Config),
    %% Bob's send chain isn't derived until Alice's first message triggers
    %% the receive ratchet. Encrypt must fail explicitly.
    Result = libsignal_protocol_nif:dr_encrypt_message(Bob, <<"oops">>),
    ?assertMatch({error, must_receive_first}, Result).

bob_responds_after_alice_initiates(Config) ->
    {Alice0, Bob0} = parties(Config),
    {ok, {CT_a2b, _}} = libsignal_protocol_nif:dr_encrypt_message(Alice0, <<"hi bob">>),
    {ok, {<<"hi bob">>, Bob1}} = libsignal_protocol_nif:dr_decrypt_message(Bob0, CT_a2b),
    %% Bob's send chain is now derived. He can reply.
    Reply = <<"hi alice">>,
    {ok, {CT_b2a, _}} = libsignal_protocol_nif:dr_encrypt_message(Bob1, Reply),
    %% Alice's recv chain isn't set yet (she's only sent so far). Her decrypt
    %% triggers her receive ratchet using Bob's new DH pub from the header.
    {ok, {PT, _}} = libsignal_protocol_nif:dr_decrypt_message(Alice0, CT_b2a),
    ?assertEqual(Reply, PT).

bidirectional_handshake(Config) ->
    {Alice0, Bob0} = parties(Config),
    {ok, {CT_hi, Alice1}} = libsignal_protocol_nif:dr_encrypt_message(Alice0, <<"hi">>),
    {ok, {<<"hi">>, Bob1}} = libsignal_protocol_nif:dr_decrypt_message(Bob0, CT_hi),
    {ok, {CT_re, _}} = libsignal_protocol_nif:dr_encrypt_message(Bob1, <<"hi back">>),
    {ok, {<<"hi back">>, _}} = libsignal_protocol_nif:dr_decrypt_message(Alice1, CT_re),
    ok.

multi_turn_conversation(Config) ->
    {A0, B0} = parties(Config),
    %% A -> B -> A -> B -> A: five turns alternating, each side ratcheting on
    %% receive. Validates send/recv chain rotation across multiple DH steps.
    {ok, {C1, A1}} = libsignal_protocol_nif:dr_encrypt_message(A0, <<"m1">>),
    {ok, {<<"m1">>, B1}} = libsignal_protocol_nif:dr_decrypt_message(B0, C1),
    {ok, {C2, B2}} = libsignal_protocol_nif:dr_encrypt_message(B1, <<"m2">>),
    {ok, {<<"m2">>, A2}} = libsignal_protocol_nif:dr_decrypt_message(A1, C2),
    {ok, {C3, A3}} = libsignal_protocol_nif:dr_encrypt_message(A2, <<"m3">>),
    {ok, {<<"m3">>, B3}} = libsignal_protocol_nif:dr_decrypt_message(B2, C3),
    {ok, {C4, _B4}} = libsignal_protocol_nif:dr_encrypt_message(B3, <<"m4">>),
    {ok, {<<"m4">>, A4}} = libsignal_protocol_nif:dr_decrypt_message(A3, C4),
    {ok, {C5, _A5}} = libsignal_protocol_nif:dr_encrypt_message(A4, <<"m5">>),
    {ok, {<<"m5">>, _}} = libsignal_protocol_nif:dr_decrypt_message(B3, C5),
    ok.

%% ============================================================================
%% AEAD integrity properties
%% ============================================================================

ciphertext_tamper_rejected(Config) ->
    {Alice, Bob} = parties(Config),
    {ok, {CT, _}} = libsignal_protocol_nif:dr_encrypt_message(Alice, <<"data">>),
    %% Flip a byte in the ciphertext region (past 40B header + 12B nonce).
    Tampered = flip_byte_at(CT, 60),
    Result = libsignal_protocol_nif:dr_decrypt_message(Bob, Tampered),
    ?assertMatch({error, _}, Result).

replay_rejected(Config) ->
    {Alice, Bob0} = parties(Config),
    {ok, {CT, _}} = libsignal_protocol_nif:dr_encrypt_message(Alice, <<"once">>),
    {ok, {_, Bob1}} = libsignal_protocol_nif:dr_decrypt_message(Bob0, CT),
    %% Replaying the same ciphertext to the advanced state must fail.
    Result = libsignal_protocol_nif:dr_decrypt_message(Bob1, CT),
    ?assertMatch({error, _}, Result).

%% ============================================================================
%% Helpers
%% ============================================================================

parties(Config) ->
    {?config(alice, Config), ?config(bob, Config)}.

flip_byte_at(Bin, Offset) when Offset < byte_size(Bin) ->
    <<Pre:Offset/binary, B:8, Rest/binary>> = Bin,
    <<Pre/binary, (B bxor 16#01):8, Rest/binary>>.
