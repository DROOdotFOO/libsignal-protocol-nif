-module(dr_he_cross_decrypt_SUITE).

%% Property-style tests for the DR-HE cross-decrypt invariants.
%%
%% These extend the existing example-based suites (dr_he_envelope_SUITE,
%% double_ratchet_reorder_SUITE) with randomised trials over the public NIF
%% surface. The RNG seed is fixed at init_per_suite so CI is deterministic
%% but local re-runs with a different seed remain easy: bump the seed tuple,
%% rerun, get a different sample of the input space.
%%
%% No PropEr or quickcheck dependency; trials are hand-rolled with rand/
%% lists primitives and the seed is logged on failure via CT's standard
%% error reporting (the failing inputs print out as part of the
%% ?assertEqual diagnostic).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([roundtrip_random_plaintexts/1, bidirectional_pingpong_random_rounds/1,
         random_reorder_within_chain/1, cross_session_isolation/1]).

-define(SEED, {11, 13, 17}).
-define(ROUNDTRIP_TRIALS, 50).
-define(PINGPONG_TRIALS, 30).
-define(PINGPONG_MAX_ROUNDS, 10).
-define(REORDER_TRIALS, 30).
-define(REORDER_MIN_CHAIN, 2).
-define(REORDER_MAX_CHAIN, 16).
-define(ISOLATION_TRIALS, 50).
-define(MAX_PLAINTEXT_BYTES, 1024).

all() ->
    [roundtrip_random_plaintexts,
     bidirectional_pingpong_random_rounds,
     random_reorder_within_chain,
     cross_session_isolation].

init_per_suite(Config) ->
    rand:seed(exsss, ?SEED),
    case signal_nif:test_crypto() of
        crypto_ok ->
            Config;
        Other ->
            {skip, {nif_init_failed, Other}}
    end.

end_per_suite(_Config) ->
    ok.

%% ============================================================================
%% Properties
%% ============================================================================

%% Property: for any random 96B shared secret and any random plaintext of
%% size 0..MAX_PLAINTEXT_BYTES, Bob's dr_decrypt of Alice's dr_encrypt
%% recovers the original plaintext.
roundtrip_random_plaintexts(_Config) ->
    [run_roundtrip_trial(N) || N <- lists:seq(1, ?ROUNDTRIP_TRIALS)],
    ok.

run_roundtrip_trial(N) ->
    {Alice, Bob} = fresh_pair(),
    PT = random_plaintext(),
    {ok, {CT, _Alice1}} = libsignal_protocol_nif:dr_encrypt(Alice, PT),
    {ok, {Got, _Bob1}} = libsignal_protocol_nif:dr_decrypt(Bob, CT),
    ?assertEqual({N, PT}, {N, Got}).

%% Property: any K alternating sends (Alice->Bob, then Bob->Alice, ...)
%% recover each plaintext exactly. Catches header-key rotation desync on
%% Alice's first receive (her HKr is zero at init and must rotate to the
%% X3DH-seeded NHKr to match Bob's HKs).
bidirectional_pingpong_random_rounds(_Config) ->
    [run_pingpong_trial(N) || N <- lists:seq(1, ?PINGPONG_TRIALS)],
    ok.

run_pingpong_trial(N) ->
    {Alice0, Bob0} = fresh_pair(),
    K = rand:uniform(?PINGPONG_MAX_ROUNDS),
    %% Each round: Alice -> Bob, then Bob -> Alice. K rounds total.
    Final =
        lists:foldl(fun(Round, {A0, B0}) ->
                       PtAB = random_plaintext(),
                       {ok, {CtAB, A1}} = libsignal_protocol_nif:dr_encrypt(A0, PtAB),
                       {ok, {RxAB, B1}} = libsignal_protocol_nif:dr_decrypt(B0, CtAB),
                       ?assertEqual({N, Round, ab, PtAB}, {N, Round, ab, RxAB}),
                       PtBA = random_plaintext(),
                       {ok, {CtBA, B2}} = libsignal_protocol_nif:dr_encrypt(B1, PtBA),
                       {ok, {RxBA, A2}} = libsignal_protocol_nif:dr_decrypt(A1, CtBA),
                       ?assertEqual({N, Round, ba, PtBA}, {N, Round, ba, RxBA}),
                       {A2, B2}
                    end,
                    {Alice0, Bob0},
                    lists:seq(1, K)),
    {_, _} = Final,
    ok.

%% Property: Alice sends K messages in a single chain (no Bob->Alice between).
%% Bob receives them in a uniformly-random permutation. Every plaintext
%% recovers to its original; the permutation order does not matter.
%% Stresses PATH_CURRENT (in-order delivery), PATH_CURRENT + counter <
%% recv_message_number (late delivery routed to MKSKIPPED), and the
%% MAX_SKIPPED_KEYS LRU under heavy reorder.
random_reorder_within_chain(_Config) ->
    [run_reorder_trial(N) || N <- lists:seq(1, ?REORDER_TRIALS)],
    ok.

run_reorder_trial(N) ->
    {Alice0, Bob0} = fresh_pair(),
    KSpan = ?REORDER_MAX_CHAIN - ?REORDER_MIN_CHAIN + 1,
    K = ?REORDER_MIN_CHAIN + rand:uniform(KSpan) - 1,
    %% Alice sends K messages, all in the same chain.
    {_AliceN, Sent} =
        lists:foldl(fun(I, {AAcc, Acc}) ->
                       PT = <<"trial-",
                              (integer_to_binary(N))/binary,
                              "-msg-",
                              (integer_to_binary(I))/binary,
                              "-",
                              (rand:bytes(8))/binary>>,
                       {ok, {CT, ANext}} = libsignal_protocol_nif:dr_encrypt(AAcc, PT),
                       {ANext, [{PT, CT} | Acc]}
                    end,
                    {Alice0, []},
                    lists:seq(0, K - 1)),
    Pairs = lists:reverse(Sent),
    Shuffled = shuffle(Pairs),
    %% Bob decrypts in shuffled order; every plaintext must match.
    lists:foldl(fun({Expected, CT}, BAcc) ->
                   {ok, {Got, BNext}} = libsignal_protocol_nif:dr_decrypt(BAcc, CT),
                   ?assertEqual({N, K, Expected}, {N, K, Got}),
                   BNext
                end,
                Bob0,
                Shuffled),
    ok.

%% Property: a wire ciphertext from session A cannot be decrypted by any
%% participant of an unrelated session B (different SS, different identities).
%% Every candidate header_key in B's state must fail trial-decrypt, surfacing
%% the {error, bad_mac} sentinel rather than ok or a wrong-key plaintext.
%% Locks the core DR-HE confidentiality boundary.
%%
%% Half the trials warm up B's session by exchanging a random number of
%% messages within it before the isolation check, so HKr/NHKr/MKSKIPPED in
%% B's state hold real chain-derived values rather than just the X3DH seed.
cross_session_isolation(_Config) ->
    [run_isolation_trial(N) || N <- lists:seq(1, ?ISOLATION_TRIALS)],
    ok.

run_isolation_trial(N) ->
    {AliceA, _BobA} = fresh_pair(),
    {AliceB, BobB} = fresh_pair(),
    BobBWarm = warm_up(AliceB, BobB, N),
    PT = random_plaintext(),
    {ok, {CT, _AliceA1}} = libsignal_protocol_nif:dr_encrypt(AliceA, PT),
    Result = libsignal_protocol_nif:dr_decrypt(BobBWarm, CT),
    ?assertEqual({N, {error, bad_mac}}, {N, Result}).

%% Run 0..R rounds of A->B then B->A within session B so Bob's HKr/NHKr
%% hold chain-derived keys (not just the X3DH seed). Returns the evolved
%% Bob state for the cross-session check.
warm_up(AliceB, BobB, N) when N rem 2 =:= 0 ->
    BobB;
warm_up(AliceB, BobB, _N) ->
    Rounds = rand:uniform(4),
    {_, B} =
        lists:foldl(fun(_, {A0, B0}) ->
                       {ok, {Ct1, A1}} = libsignal_protocol_nif:dr_encrypt(A0, <<"warm-ab">>),
                       {ok, {_, B1}} = libsignal_protocol_nif:dr_decrypt(B0, Ct1),
                       {ok, {Ct2, B2}} = libsignal_protocol_nif:dr_encrypt(B1, <<"warm-ba">>),
                       {ok, {_, A2}} = libsignal_protocol_nif:dr_decrypt(A1, Ct2),
                       {A2, B2}
                    end,
                    {AliceB, BobB},
                    lists:seq(1, Rounds)),
    B.

%% ============================================================================
%% Helpers
%% ============================================================================

%% Fisher-Yates-ish shuffle backed by `rand`. Deterministic given the suite
%% seed.
shuffle(List) ->
    Tagged = [{rand:uniform(), X} || X <- List],
    [X || {_, X} <- lists:sort(Tagged)].

fresh_pair() ->
    {ok, {AlicePub, _}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, {BobPub, BobPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    SS = rand:bytes(96),
    {ok, Alice} = libsignal_protocol_nif:dr_init(SS, AlicePub, BobPub, <<>>, 1),
    {ok, Bob} = libsignal_protocol_nif:dr_init(SS, BobPub, AlicePub, BobPriv, 0),
    {Alice, Bob}.

random_plaintext() ->
    rand:bytes(rand:uniform(?MAX_PLAINTEXT_BYTES + 1) - 1).
