-module(double_ratchet_reorder_SUITE).

%% Out-of-order delivery tests. MKSKIPPED caches keys for messages that arrive
%% later than their successors, so any permutation within MAX_SKIP decrypts.

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2]).
-export([reorder_two_messages/1, reorder_five_messages/1, reorder_across_dh_ratchet/1,
         skip_bound_rejected/1, skip_budget_is_per_chain/1,
         previous_receive_keys_survive_ratchet_skip/1, random_permutations_property/1]).

-define(MAX_SKIP, 32).

all() ->
    [reorder_two_messages,
     reorder_five_messages,
     reorder_across_dh_ratchet,
     skip_bound_rejected,
     skip_budget_is_per_chain,
     previous_receive_keys_survive_ratchet_skip,
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

%% MAX_SKIP is a per-chain bound (Signal spec), so one receive that crosses a
%% DH ratchet may skip up to MAX_SKIP on the old chain *and* MAX_SKIP on the
%% new one, and every key it banks must later drain. 0.3.0 briefly charged
%% both sides against a single shared budget, which rejected ordinary
%% reorders that 0.2 accepted -- e.g. PN=30 with 1 received plus N=10 is 39
%% against a 32 budget, while each chain is individually well inside the cap.
skip_budget_is_per_chain(Config) ->
    %% 29 skipped on the old chain + 10 on the new: over a shared budget,
    %% inside the per-chain one.
    {Bob, OldTail, NewPrefix, {LastMsg, LastCT}} =
        ratchet_with_skips(parties(Config), 30, 11),
    {ok, {LastMsg, Bob1}} = libsignal_protocol_nif:dr_decrypt(Bob, LastCT),
    _ = bob_receives(Bob1, shuffle(OldTail ++ NewPrefix)),

    %% Both chains at exactly MAX_SKIP still decrypt and drain.
    {BobB, OldTailB, NewPrefixB, {LastMsgB, LastCTB}} =
        ratchet_with_skips(parties(Config), ?MAX_SKIP + 1, ?MAX_SKIP + 1),
    {ok, {LastMsgB, BobB1}} = libsignal_protocol_nif:dr_decrypt(BobB, LastCTB),
    _ = bob_receives(BobB1, shuffle(OldTailB ++ NewPrefixB)),

    %% One past MAX_SKIP on the new chain is rejected.
    {BobC, _, _, {_, OverCT}} =
        ratchet_with_skips(parties(Config), 2, ?MAX_SKIP + 2),
    ?assertEqual({error, too_many_skipped}, libsignal_protocol_nif:dr_decrypt(BobC, OverCT)),

    %% One past MAX_SKIP on the old chain is rejected.
    {BobD, _, _, {_, OverCT2}} =
        ratchet_with_skips(parties(Config), ?MAX_SKIP + 3, 2),
    ?assertEqual({error, too_many_skipped}, libsignal_protocol_nif:dr_decrypt(BobD, OverCT2)).

%% Keys cached by an earlier receive must survive a later receive that banks
%% a full two-chain skip. MKSKIPPED is sized at 3 * MAX_SKIP so the worst
%% single receive (2 * MAX_SKIP) still leaves a chain's worth resident.
previous_receive_keys_survive_ratchet_skip(Config) ->
    {Alice0, Bob0} = parties(Config),
    %% Chain P: Alice sends 6, Bob receives only the last -> 5 keys cached.
    {Alice1, PItems} = alice_sends(Alice0, 6),
    {PEarly, [PLast]} = lists:split(5, PItems),
    Bob1 = bob_receives(Bob0, [PLast]),
    %% Bob replies so Alice ratchets; then a full-budget ratchet receive.
    {ok, {ReplyCT, Bob2}} = libsignal_protocol_nif:dr_encrypt(Bob1, <<"r">>),
    {ok, {<<"r">>, Alice2}} = libsignal_protocol_nif:dr_decrypt(Alice1, ReplyCT),
    Half = ?MAX_SKIP div 2,
    {Bob3, OldTail, NewPrefix, {LastMsg, LastCT}} =
        ratchet_with_skips({Alice2, Bob2}, Half + 1, Half + 1),
    {ok, {LastMsg, Bob4}} = libsignal_protocol_nif:dr_decrypt(Bob3, LastCT),
    %% Everything -- including the 5 keys from chain P -- must still drain.
    _ = bob_receives(Bob4, shuffle(PEarly ++ OldTail ++ NewPrefix)).

%% Alice sends OldN on her current chain; Bob receives only the first. Bob
%% replies, Alice ratchets and sends NewN on the new chain. Returns Bob's
%% state before receiving any new-chain message, the OldN-1 unreceived
%% old-chain items, the first NewN-1 new-chain items, and the last new-chain
%% item (whose header claims PN=OldN, N=NewN-1).
ratchet_with_skips({Alice0, Bob0}, OldN, NewN) ->
    {Alice1, [First | OldTail]} = alice_sends(Alice0, OldN),
    Bob1 = bob_receives(Bob0, [First]),
    {ok, {ReplyCT, Bob2}} = libsignal_protocol_nif:dr_encrypt(Bob1, <<"reply">>),
    {ok, {<<"reply">>, Alice2}} = libsignal_protocol_nif:dr_decrypt(Alice1, ReplyCT),
    {_Alice3, NewItems} = alice_sends(Alice2, NewN),
    {NewPrefix, [Last]} = lists:split(NewN - 1, NewItems),
    {Bob2, OldTail, NewPrefix, Last}.

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
