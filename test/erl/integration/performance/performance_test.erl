%% Performance benchmarks for libsignal_protocol_nif.
%%
%% Entry points:
%%   run/0       full suite, compared against baseline.term
%%   quick/0     smoke run at low N, no baseline diff
%%   baseline/0  full run, rewrite the checked-in baseline
%%
%% Each benchmark is `{Name, Speed, Setup, Iter}`. Setup runs once before the
%% timed loop and receives the iteration count so it can pre-generate inputs
%% (the DR decrypt bench needs a list of ciphertexts, one per iteration).
%% Iter takes the carried context and returns a new context. Warmup runs
%% `?WARMUP` iterations before timing starts.

-module(performance_test).

-export([run/0, quick/0, baseline/0]).
%% Retained for the existing Makefile target name.
-export([run_benchmarks/0]).

-define(REPORT_PATH, "tmp/performance_report.txt").
-define(BASELINE_PATH, "test/erl/integration/performance/baseline.term").
-define(WARMUP, 10).
-define(WARN_PCT, 10).
-define(REGRESSION_PCT, 20).

%% ---------------------------------------------------------------------------
%% Entry points
%% ---------------------------------------------------------------------------

run() ->
    init_lib(),
    Results = run_all(full_counts()),
    Baseline = load_baseline(),
    report(Results, Baseline),
    write_text_report(Results),
    ok.

run_benchmarks() ->
    run().

quick() ->
    init_lib(),
    Results = run_all(quick_counts()),
    report(Results, undefined),
    ok.

baseline() ->
    init_lib(),
    Results = run_all(full_counts()),
    write_baseline(Results),
    io:format("Baseline written to ~s~n", [?BASELINE_PATH]),
    ok.

%% ---------------------------------------------------------------------------
%% Bench table
%% ---------------------------------------------------------------------------

bench_list() ->
    [%% Primitives -- fast (< 50us)
     {ed25519_keygen, fast, fun noop_setup/1, fun ed25519_keygen_iter/1},
     {curve25519_keygen, fast, fun noop_setup/1, fun curve25519_keygen_iter/1},
     {sha256_1k, fast, fun sha_setup/1, fun sha256_iter/1},
     {sha512_1k, fast, fun sha_setup/1, fun sha512_iter/1},
     {hmac_sha256_1k, fast, fun hmac_setup/1, fun hmac_iter/1},
     %% Primitives -- med (50us - 500us)
     {ed25519_sign, med, fun ed25519_sign_setup/1, fun ed25519_sign_iter/1},
     {ed25519_verify, med, fun ed25519_verify_setup/1, fun ed25519_verify_iter/1},
     {aes_gcm_encrypt_64, med, fun(_) -> aes_setup(64) end, fun aes_encrypt_iter/1},
     {aes_gcm_encrypt_1k, med, fun(_) -> aes_setup(1024) end, fun aes_encrypt_iter/1},
     {aes_gcm_encrypt_16k, med, fun(_) -> aes_setup(16384) end, fun aes_encrypt_iter/1},
     {aes_gcm_decrypt_1k, med, fun(_) -> aes_dec_setup(1024) end, fun aes_decrypt_iter/1},
     %% Protocol -- slow (> 500us)
     {x3dh_process_bundle, slow, fun(_) -> x3dh_setup() end, fun x3dh_iter/1},
     {dr_init, slow, fun(_) -> dr_init_setup() end, fun dr_init_iter/1},
     {dr_encrypt, slow, fun dr_encrypt_setup/1, fun dr_encrypt_iter/1},
     {dr_decrypt, slow, fun dr_decrypt_setup/1, fun dr_decrypt_iter/1},
     {pksm_roundtrip, slow, fun(_) -> pksm_setup() end, fun pksm_iter/1}].

full_counts() ->
    #{fast => 10000,
      med => 1000,
      slow => 200}.

quick_counts() ->
    #{fast => 100,
      med => 50,
      slow => 20}.

%% ---------------------------------------------------------------------------
%% Driver
%% ---------------------------------------------------------------------------

run_all(Counts) ->
    [run_bench(Name, Speed, Setup, Iter, Counts)
     || {Name, Speed, Setup, Iter} <- bench_list()].

run_bench(Name, Speed, SetupFun, IterFun, Counts) ->
    N = maps:get(Speed, Counts),
    Ctx0 = SetupFun(N + ?WARMUP),
    Ctx1 = run_iters(IterFun, Ctx0, ?WARMUP),
    {Samples, _} = measure_iters(IterFun, Ctx1, N, []),
    {Name, stats(Samples, N)}.

run_iters(_Fun, Ctx, 0) ->
    Ctx;
run_iters(Fun, Ctx, N) ->
    Ctx2 = Fun(Ctx),
    run_iters(Fun, Ctx2, N - 1).

measure_iters(_Fun, Ctx, 0, Acc) ->
    {Acc, Ctx};
measure_iters(Fun, Ctx, N, Acc) ->
    T0 = os:system_time(microsecond),
    Ctx2 = Fun(Ctx),
    T1 = os:system_time(microsecond),
    measure_iters(Fun, Ctx2, N - 1, [T1 - T0 | Acc]).

%% ---------------------------------------------------------------------------
%% Stats
%% ---------------------------------------------------------------------------

stats(Samples, N) ->
    Sorted = lists:sort(Samples),
    Total = lists:sum(Samples),
    #{n => N,
      min => hd(Sorted),
      p50 => percentile(Sorted, 50),
      p95 => percentile(Sorted, 95),
      p99 => percentile(Sorted, 99),
      mean => Total div max(1, N),
      throughput => throughput(N, Total)}.

percentile(Sorted, P) ->
    Len = length(Sorted),
    Idx = max(1, min(Len, (P * Len + 99) div 100)),
    lists:nth(Idx, Sorted).

throughput(_N, 0) ->
    0;
throughput(N, TotalUs) ->
    N * 1000000 div TotalUs.

%% ---------------------------------------------------------------------------
%% Reporting
%% ---------------------------------------------------------------------------

report(Results, Baseline) ->
    io:format("~n=== Performance benchmarks ===~n~n"),
    lists:foreach(fun(R) -> report_one(R, Baseline) end, Results),
    io:nl().

report_one({Name, Stats}, Baseline) ->
    #{min := Mn,
      p50 := P50,
      p95 := P95,
      p99 := P99,
      throughput := T} =
        Stats,
    Tag = delta_tag(Name, Stats, Baseline),
    io:format("  ~-22s  min ~6w us  p50 ~6w us  p95 ~6w us  p99 ~6w us  thr ~10w/s  ~s~n",
              [Name, Mn, P50, P95, P99, T, Tag]).

delta_tag(_, _, undefined) ->
    "";
delta_tag(Name, #{throughput := T}, Baseline) ->
    case maps:find(Name, Baseline) of
        error ->
            "[new]";
        {ok, #{throughput := T0}} when T0 > 0 ->
            DeltaPct = (T - T0) * 100 div T0,
            format_delta(DeltaPct);
        _ ->
            ""
    end.

format_delta(D) when D >= -?WARN_PCT ->
    io_lib:format("[~s~w%]", [sign(D), D]);
format_delta(D) when D >= -?REGRESSION_PCT ->
    io_lib:format("[WARN ~s~w%]", [sign(D), D]);
format_delta(D) ->
    io_lib:format("[REGRESSION ~s~w%]", [sign(D), D]).

sign(D) when D > 0 ->
    "+";
sign(_) ->
    "".

write_text_report(Results) ->
    filelib:ensure_dir(?REPORT_PATH),
    {ok, F} = file:open(?REPORT_PATH, [write]),
    io:format(F, "Signal Protocol performance benchmarks~n", []),
    io:format(F,
              "Generated: ~s~n~n",
              [calendar:system_time_to_rfc3339(
                   erlang:system_time(second))]),
    lists:foreach(fun({Name, S}) ->
                     #{min := Mn,
                       p50 := P50,
                       p95 := P95,
                       p99 := P99,
                       throughput := T} =
                         S,
                     io:format(F,
                               "~-24s  min=~wus  p50=~wus  p95=~wus  p99=~wus  thr=~w/s~n",
                               [Name, Mn, P50, P95, P99, T])
                  end,
                  Results),
    file:close(F),
    io:format("Report written to ~s~n", [?REPORT_PATH]).

%% ---------------------------------------------------------------------------
%% Baseline I/O
%% ---------------------------------------------------------------------------

load_baseline() ->
    case file:consult(?BASELINE_PATH) of
        {ok, [Baseline]} when is_map(Baseline) ->
            Baseline;
        _ ->
            undefined
    end.

write_baseline(Results) ->
    Map = maps:from_list(Results),
    Body =
        io_lib:format("%% Performance baseline. Regenerate with `make perf-baseline`.~n~p.~n",
                      [Map]),
    filelib:ensure_dir(?BASELINE_PATH),
    file:write_file(?BASELINE_PATH, iolist_to_binary(Body)).

%% ---------------------------------------------------------------------------
%% Init
%% ---------------------------------------------------------------------------

init_lib() ->
    ok = libsignal_protocol_nif:init().

%% ---------------------------------------------------------------------------
%% Benchmarks: primitives
%% ---------------------------------------------------------------------------

noop_setup(_) ->
    undefined.

ed25519_keygen_iter(_) ->
    {ok, _} = signal_nif:generate_ed25519_keypair(),
    undefined.

curve25519_keygen_iter(_) ->
    {ok, _} = signal_nif:generate_curve25519_keypair(),
    undefined.

sha_setup(_) ->
    crypto:strong_rand_bytes(1024).

sha256_iter(D) ->
    {ok, _} = signal_nif:sha256(D),
    D.

sha512_iter(D) ->
    {ok, _} = signal_nif:sha512(D),
    D.

hmac_setup(_) ->
    {crypto:strong_rand_bytes(32), crypto:strong_rand_bytes(1024)}.

hmac_iter({K, D} = Ctx) ->
    {ok, _} = signal_nif:hmac_sha256(K, D),
    Ctx.

ed25519_sign_setup(_) ->
    {ok, {_Pub, Priv}} = signal_nif:generate_ed25519_keypair(),
    Msg = crypto:strong_rand_bytes(64),
    {Priv, Msg}.

ed25519_sign_iter({Priv, Msg} = Ctx) ->
    {ok, _} = signal_nif:sign_data(Priv, Msg),
    Ctx.

ed25519_verify_setup(_) ->
    {ok, {Pub, Priv}} = signal_nif:generate_ed25519_keypair(),
    Msg = crypto:strong_rand_bytes(64),
    {ok, Sig} = signal_nif:sign_data(Priv, Msg),
    {Pub, Msg, Sig}.

ed25519_verify_iter({Pub, Msg, Sig} = Ctx) ->
    ok = signal_nif:verify_signature(Pub, Msg, Sig),
    Ctx.

aes_setup(Size) ->
    {crypto:strong_rand_bytes(32),
     crypto:strong_rand_bytes(12),
     crypto:strong_rand_bytes(Size)}.

aes_encrypt_iter({K, IV, Pt} = Ctx) ->
    {ok, _Ct, _Tag} = signal_nif:aes_gcm_encrypt(K, IV, Pt, <<>>, 16),
    Ctx.

aes_dec_setup(Size) ->
    K = crypto:strong_rand_bytes(32),
    IV = crypto:strong_rand_bytes(12),
    Pt = crypto:strong_rand_bytes(Size),
    {ok, Ct, Tag} = signal_nif:aes_gcm_encrypt(K, IV, Pt, <<>>, 16),
    {K, IV, Ct, Tag, byte_size(Pt)}.

aes_decrypt_iter({K, IV, Ct, Tag, Len} = Ctx) ->
    {ok, _Pt} = signal_nif:aes_gcm_decrypt(K, IV, Ct, <<>>, Tag, Len),
    Ctx.

%% ---------------------------------------------------------------------------
%% Benchmarks: protocol
%%
%% derive_x3dh/0 builds Alice + Bob identities, a signed prekey, an OPK,
%% assembles a valid bundle, and runs the X3DH so we have a 96-byte SK and
%% Alice's ephemeral pub for downstream benches.
%% ---------------------------------------------------------------------------

derive_x3dh() ->
    {ok, {AlicePub, AlicePriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, {BobPub, BobPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, {SpkPub, _}} = signal_nif:generate_curve25519_keypair(),
    {ok, Sig} = signal_nif:sign_data(BobPriv, SpkPub),
    {ok, {OpkPub, _}} = signal_nif:generate_curve25519_keypair(),
    Bundle = <<BobPub/binary, SpkPub/binary, Sig/binary, OpkPub/binary>>,
    {ok, {SK, Eph}} = libsignal_protocol_nif:process_pre_key_bundle(AlicePriv, Bundle),
    {SK, AlicePub, BobPub, BobPriv, Eph}.

x3dh_setup() ->
    {ok, {_AlicePub, AlicePriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, {BobPub, BobPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, {SpkPub, _}} = signal_nif:generate_curve25519_keypair(),
    {ok, Sig} = signal_nif:sign_data(BobPriv, SpkPub),
    {ok, {OpkPub, _}} = signal_nif:generate_curve25519_keypair(),
    Bundle = <<BobPub/binary, SpkPub/binary, Sig/binary, OpkPub/binary>>,
    {AlicePriv, Bundle}.

x3dh_iter({AlicePriv, Bundle} = Ctx) ->
    {ok, _} = libsignal_protocol_nif:process_pre_key_bundle(AlicePriv, Bundle),
    Ctx.

dr_init_setup() ->
    {SK, A, B, _, _} = derive_x3dh(),
    {SK, A, B}.

dr_init_iter({SK, A, B} = Ctx) ->
    {ok, _} = libsignal_protocol_nif:dr_init(SK, A, B, <<>>, 1),
    Ctx.

dr_encrypt_setup(_N) ->
    {SK, A, B, _, _} = derive_x3dh(),
    {ok, S} = libsignal_protocol_nif:dr_init(SK, A, B, <<>>, 1),
    S.

dr_encrypt_iter(S) ->
    {ok, {_Ct, S2}} = libsignal_protocol_nif:dr_encrypt(S, <<"benchmark message">>),
    S2.

dr_decrypt_setup(N) ->
    {SK, A, B, BobPriv, _} = derive_x3dh(),
    {ok, AliceS} = libsignal_protocol_nif:dr_init(SK, A, B, <<>>, 1),
    {ok, BobS} = libsignal_protocol_nif:dr_init(SK, B, A, BobPriv, 0),
    %% Establish: Alice -> Bob, in order.
    {ok, {Ct1, AliceS1}} = libsignal_protocol_nif:dr_encrypt(AliceS, <<"first">>),
    {ok, {_, BobS1}} = libsignal_protocol_nif:dr_decrypt(BobS, Ct1),
    %% Pre-generate one ciphertext per (warmup + measured) iteration so the
    %% iter loop only times the decrypt call.
    Total = N + ?WARMUP,
    {Cts, _} =
        lists:mapfoldl(fun(_, S) ->
                          {ok, {C, S2}} = libsignal_protocol_nif:dr_encrypt(S, <<"benchmark">>),
                          {C, S2}
                       end,
                       AliceS1,
                       lists:seq(1, Total)),
    {BobS1, Cts}.

dr_decrypt_iter({BobS, [Ct | Rest]}) ->
    {ok, {_, BobS2}} = libsignal_protocol_nif:dr_decrypt(BobS, Ct),
    {BobS2, Rest}.

pksm_setup() ->
    {SK, A, B, _, AliceEph} = derive_x3dh(),
    {ok, AliceS} = libsignal_protocol_nif:dr_init(SK, A, B, <<>>, 1),
    PreKeyInfo = {1, 1, 2, AliceEph},
    {AliceS, PreKeyInfo}.

pksm_iter({AliceS, PreKeyInfo}) ->
    {ok, {Wire, AliceS2}} =
        libsignal_protocol_nif:dr_encrypt_prekey(AliceS, <<"hi">>, PreKeyInfo),
    {ok, _} = libsignal_protocol_nif:pksm_decode(Wire),
    {AliceS2, PreKeyInfo}.
