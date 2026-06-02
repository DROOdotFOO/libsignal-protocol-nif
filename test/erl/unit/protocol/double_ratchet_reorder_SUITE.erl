-module(double_ratchet_reorder_SUITE).

%% Out-of-order delivery tests. MKSKIPPED caches keys for messages that arrive
%% later than their successors, so any permutation within MAX_SKIP decrypts.

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2]).
-export([reorder_two_messages/1, reorder_five_messages/1, reorder_across_dh_ratchet/1,
         skip_bound_rejected/1, random_permutations_property/1]).

-define(MAX_SKIP, 32).

all() ->
    [reorder_two_messages,
     reorder_five_messages,
     reorder_across_dh_ratchet,
     skip_bound_rejected,
     random_permutations_property].

init_per_suite(Config) ->
    dr_test_helpers:nif_or_skip(Config, {41, 43, 47}).

end_per_suite(_Config) ->
    ok.

init_per_testcase(_Name, Config) ->
    dr_test_helpers:fresh_dr_parties_to_config(Config).

parties(Config) ->
    {?config(alice, Config), ?config(bob, Config)}.

%% Alice sends N messages; returns her advanced state plus [{Plaintext, CT}, ...]
%% in send order.
alice_sends(Alice0, N) ->
    {AliceN, Rev} =
        lists:foldl(fun(I, {AAcc, Acc}) ->
                       Msg = <<"msg-", (integer_to_binary(I))/binary>>,
                       {ok, {CT, ANext}} = libsignal_protocol_nif:dr_encrypt(AAcc, Msg),
                       {ANext, [{Msg, CT} | Acc]}
                    end,
                    {Alice0, []},
                    lists:seq(0, N - 1)),
    {AliceN, lists:reverse(Rev)}.

bob_receives(Bob0, Items) ->
    lists:foldl(fun({Expected, CT}, BAcc) ->
                   {ok, {PT, BNext}} = libsignal_protocol_nif:dr_decrypt(BAcc, CT),
                   ?assertEqual(Expected, PT),
                   BNext
                end,
                Bob0,
                Items).

%% ============================================================================
%% Out-of-order within a single chain
%% ============================================================================

reorder_two_messages(Config) ->
    {Alice0, Bob0} = parties(Config),
    {_AliceN, [M0, M1]} = alice_sends(Alice0, 2),
    bob_receives(Bob0, [M1, M0]).

reorder_five_messages(Config) ->
    {Alice0, Bob0} = parties(Config),
    {_AliceN, [M0, M1, M2, M3, M4]} = alice_sends(Alice0, 5),
    bob_receives(Bob0, [M3, M1, M4, M0, M2]).

%% ============================================================================
%% Out-of-order across a DH ratchet
%% ============================================================================

%% Alice sends A0,A1,A2 on initial chain. Bob receives A0,A1 in order (holds A2).
%% Bob replies, Alice receives reply (triggering her DH ratchet), Alice sends A3
%% on new chain. Bob receives A3 first (triggering his ratchet -- which should
%% bank the A2 key in MKSKIPPED via prev_chain_length=3). Then Bob receives A2
%% late: must decrypt from MKSKIPPED keyed by the OLD dh_pub.
reorder_across_dh_ratchet(Config) ->
    {Alice0, Bob0} = parties(Config),
    {Alice1, [A0, A1, A2]} = alice_sends(Alice0, 3),
    Bob1 = bob_receives(Bob0, [A0, A1]),
    %% Bob can send now (his recv ratchet established his send chain on A0).
    {ok, {ReplyCT, Bob2}} = libsignal_protocol_nif:dr_encrypt(Bob1, <<"reply">>),
    %% Alice receives reply -- triggers her DH ratchet.
    {ok, {<<"reply">>, Alice2}} = libsignal_protocol_nif:dr_decrypt(Alice1, ReplyCT),
    %% Alice sends A3 on her new chain.
    {ok, {A3CT, _Alice3}} = libsignal_protocol_nif:dr_encrypt(Alice2, <<"post-ratchet">>),
    %% Bob receives A3 first -- his ratchet should bank key for A2.
    {ok, {<<"post-ratchet">>, Bob3}} = libsignal_protocol_nif:dr_decrypt(Bob2, A3CT),
    %% Late A2 must still decrypt via MKSKIPPED.
    {_A2Msg, A2CT} = A2,
    {ok, {<<"msg-2">>, _Bob4}} = libsignal_protocol_nif:dr_decrypt(Bob3, A2CT).

%% ============================================================================
%% MAX_SKIP guard
%% ============================================================================

skip_bound_rejected(Config) ->
    {Alice0, Bob0} = parties(Config),
    {_AliceN, Items} = alice_sends(Alice0, ?MAX_SKIP + 2),
    {_LastMsg, LastCT} = lists:last(Items),
    {error, too_many_skipped} = libsignal_protocol_nif:dr_decrypt(Bob0, LastCT).

%% ============================================================================
%% Property: random permutations of up to MAX_SKIP messages all decrypt
%% ============================================================================

random_permutations_property(_Config) ->
    Trials = 20,
    N = 16,
    [run_perm_trial(N) || _ <- lists:seq(1, Trials)],
    ok.

run_perm_trial(N) ->
    {ok, {AlicePub, _AlicePriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, {BobPub, BobPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    SS = rand:bytes(96),
    {ok, Alice} = libsignal_protocol_nif:dr_init(SS, AlicePub, BobPub, <<>>, 1),
    {ok, Bob} = libsignal_protocol_nif:dr_init(SS, BobPub, AlicePub, BobPriv, 0),
    {_AliceN, Items} = alice_sends(Alice, N),
    bob_receives(Bob, shuffle(Items)).

shuffle(L) ->
    [V || {_, V} <- lists:sort([{rand:uniform(), X} || X <- L])].
