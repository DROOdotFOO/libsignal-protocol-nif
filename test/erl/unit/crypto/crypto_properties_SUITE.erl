-module(crypto_properties_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([prop_sha256_size/1, prop_sha256_determinism/1, prop_sha512_size/1,
         prop_hmac_sha256_size/1, prop_hmac_sha256_key_sensitivity/1, prop_ed25519_roundtrip/1,
         prop_ed25519_wrong_key/1, prop_ed25519_tampered_message/1, prop_aes_gcm_roundtrip/1,
         prop_aes_gcm_tag_tamper/1, prop_aes_gcm_ct_tamper/1, prop_aes_gcm_wrong_aad/1,
         prop_aes_gcm_wrong_key/1, prop_curve25519_keypair_unique/1]).

-define(ITERATIONS, 100).
-define(SEED, {1, 2, 3}).

all() ->
    [prop_sha256_size,
     prop_sha256_determinism,
     prop_sha512_size,
     prop_hmac_sha256_size,
     prop_hmac_sha256_key_sensitivity,
     prop_ed25519_roundtrip,
     prop_ed25519_wrong_key,
     prop_ed25519_tampered_message,
     prop_aes_gcm_roundtrip,
     prop_aes_gcm_tag_tamper,
     prop_aes_gcm_ct_tamper,
     prop_aes_gcm_wrong_aad,
     prop_aes_gcm_wrong_key,
     prop_curve25519_keypair_unique].

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
%% Properties: SHA
%% ============================================================================

prop_sha256_size(_) ->
    forall(fun() ->
              Data = rand_bytes(0, 8192),
              {ok, Hash} = signal_nif:sha256(Data),
              case byte_size(Hash) of
                  32 ->
                      ok;
                  N ->
                      {fail, {input_size, byte_size(Data), output_size, N}}
              end
           end).

prop_sha256_determinism(_) ->
    forall(fun() ->
              Data = rand_bytes(0, 8192),
              {ok, H1} = signal_nif:sha256(Data),
              {ok, H2} = signal_nif:sha256(Data),
              case H1 =:= H2 of
                  true ->
                      ok;
                  false ->
                      {fail, {nondeterministic, Data, H1, H2}}
              end
           end).

prop_sha512_size(_) ->
    forall(fun() ->
              Data = rand_bytes(0, 8192),
              {ok, Hash} = signal_nif:sha512(Data),
              case byte_size(Hash) of
                  64 ->
                      ok;
                  N ->
                      {fail, {input_size, byte_size(Data), output_size, N}}
              end
           end).

%% ============================================================================
%% Properties: HMAC-SHA256
%% ============================================================================

prop_hmac_sha256_size(_) ->
    forall(fun() ->
              Key = rand_bytes(1, 128),
              Data = rand_bytes(0, 4096),
              {ok, Mac} = signal_nif:hmac_sha256(Key, Data),
              case byte_size(Mac) of
                  32 ->
                      ok;
                  N ->
                      {fail, {output_size, N}}
              end
           end).

prop_hmac_sha256_key_sensitivity(_) ->
    forall(fun() ->
              K1 = rand_bytes(32, 32),
              K2 = flip_random_bit(K1),
              Data = rand_bytes(1, 1024),
              {ok, M1} = signal_nif:hmac_sha256(K1, Data),
              {ok, M2} = signal_nif:hmac_sha256(K2, Data),
              case M1 =/= M2 of
                  true ->
                      ok;
                  false ->
                      {fail, {hmac_key_collision, K1, K2, M1}}
              end
           end).

%% ============================================================================
%% Properties: Ed25519 sign/verify
%% ============================================================================

prop_ed25519_roundtrip(_) ->
    forall(fun() ->
              {ok, {Pub, Priv}} = signal_nif:generate_ed25519_keypair(),
              Msg = rand_bytes(0, 4096),
              {ok, Sig} = signal_nif:sign_data(Priv, Msg),
              case signal_nif:verify_signature(Pub, Msg, Sig) of
                  ok ->
                      ok;
                  Other ->
                      {fail, {verify_failed_on_valid_sig, Other, Msg, Sig}}
              end
           end).

prop_ed25519_wrong_key(_) ->
    forall(fun() ->
              {ok, {_Pub1, Priv1}} = signal_nif:generate_ed25519_keypair(),
              {ok, {Pub2, _Priv2}} = signal_nif:generate_ed25519_keypair(),
              Msg = rand_bytes(1, 1024),
              {ok, Sig} = signal_nif:sign_data(Priv1, Msg),
              case signal_nif:verify_signature(Pub2, Msg, Sig) of
                  invalid_signature ->
                      ok;
                  {error, _} ->
                      ok;
                  Other ->
                      {fail, {wrong_key_accepted, Other, Msg}}
              end
           end).

prop_ed25519_tampered_message(_) ->
    forall(fun() ->
              {ok, {Pub, Priv}} = signal_nif:generate_ed25519_keypair(),
              Msg = rand_bytes(1, 1024),
              Tampered = flip_random_bit(Msg),
              {ok, Sig} = signal_nif:sign_data(Priv, Msg),
              case signal_nif:verify_signature(Pub, Tampered, Sig) of
                  invalid_signature ->
                      ok;
                  {error, _} ->
                      ok;
                  Other ->
                      {fail, {tampered_msg_accepted, Other, Msg, Tampered}}
              end
           end).

%% ============================================================================
%% Properties: AES-GCM
%% ============================================================================

prop_aes_gcm_roundtrip(_) ->
    forall(fun() ->
              K = rand:bytes(32),
              IV = rand:bytes(12),
              PT = rand_bytes(0, 4096),
              AAD = rand_bytes(0, 256),
              {ok, CT, Tag} = signal_nif:aes_gcm_encrypt(K, IV, PT, AAD, 16),
              case signal_nif:aes_gcm_decrypt(K, IV, CT, AAD, Tag, byte_size(PT)) of
                  {ok, PT} ->
                      ok;
                  {ok, Other} ->
                      {fail, {plaintext_mismatch, PT, Other}};
                  Err ->
                      {fail, {decrypt_failed_on_valid_ct, Err, PT}}
              end
           end).

prop_aes_gcm_tag_tamper(_) ->
    forall(fun() ->
              K = rand:bytes(32),
              IV = rand:bytes(12),
              PT = rand_bytes(1, 1024),
              AAD = rand_bytes(0, 64),
              {ok, CT, Tag} = signal_nif:aes_gcm_encrypt(K, IV, PT, AAD, 16),
              BadTag = flip_random_bit(Tag),
              case signal_nif:aes_gcm_decrypt(K, IV, CT, AAD, BadTag, byte_size(PT)) of
                  {ok, _} ->
                      {fail, {tampered_tag_accepted, PT, Tag, BadTag}};
                  _ ->
                      ok
              end
           end).

prop_aes_gcm_ct_tamper(_) ->
    forall(fun() ->
              K = rand:bytes(32),
              IV = rand:bytes(12),
              PT = rand_bytes(1, 1024),
              AAD = rand_bytes(0, 64),
              {ok, CT, Tag} = signal_nif:aes_gcm_encrypt(K, IV, PT, AAD, 16),
              BadCT = flip_random_bit(CT),
              case signal_nif:aes_gcm_decrypt(K, IV, BadCT, AAD, Tag, byte_size(PT)) of
                  {ok, _} ->
                      {fail, {tampered_ct_accepted, PT, CT, BadCT}};
                  _ ->
                      ok
              end
           end).

prop_aes_gcm_wrong_aad(_) ->
    forall(fun() ->
              K = rand:bytes(32),
              IV = rand:bytes(12),
              PT = rand_bytes(1, 512),
              AAD1 = rand_bytes(1, 64),
              AAD2 = flip_random_bit(AAD1),
              {ok, CT, Tag} = signal_nif:aes_gcm_encrypt(K, IV, PT, AAD1, 16),
              case signal_nif:aes_gcm_decrypt(K, IV, CT, AAD2, Tag, byte_size(PT)) of
                  {ok, _} ->
                      {fail, {wrong_aad_accepted, AAD1, AAD2}};
                  _ ->
                      ok
              end
           end).

prop_aes_gcm_wrong_key(_) ->
    forall(fun() ->
              K1 = rand:bytes(32),
              K2 = flip_random_bit(K1),
              IV = rand:bytes(12),
              PT = rand_bytes(1, 512),
              AAD = rand_bytes(0, 32),
              {ok, CT, Tag} = signal_nif:aes_gcm_encrypt(K1, IV, PT, AAD, 16),
              case signal_nif:aes_gcm_decrypt(K2, IV, CT, AAD, Tag, byte_size(PT)) of
                  {ok, _} ->
                      {fail, {wrong_key_accepted, K1, K2}};
                  _ ->
                      ok
              end
           end).

%% ============================================================================
%% Properties: Curve25519
%% ============================================================================

prop_curve25519_keypair_unique(_) ->
    {Pubs, Privs} =
        lists:foldl(fun(_, {AccP, AccS}) ->
                       {ok, {P, S}} = signal_nif:generate_curve25519_keypair(),
                       32 = byte_size(P),
                       32 = byte_size(S),
                       {[P | AccP], [S | AccS]}
                    end,
                    {[], []},
                    lists:seq(1, ?ITERATIONS)),
    ?assertEqual(?ITERATIONS, length(lists:usort(Pubs))),
    ?assertEqual(?ITERATIONS, length(lists:usort(Privs))),
    ok.

%% ============================================================================
%% Property runner: executes Fun ITERATIONS times, fails on first counterexample
%% ============================================================================

forall(Fun) ->
    forall(Fun, ?ITERATIONS, 1).

forall(_Fun, 0, _N) ->
    ok;
forall(Fun, Remaining, N) ->
    case Fun() of
        ok ->
            forall(Fun, Remaining - 1, N + 1);
        {fail, Why} ->
            ct:pal("Property failed on iteration ~p with seed ~p: ~p", [N, ?SEED, Why]),
            ?assertEqual(ok, {fail, Why})
    end.

rand_bytes(0, Max) ->
    N = rand:uniform(Max + 1) - 1,
    case N of
        0 ->
            <<>>;
        _ ->
            rand:bytes(N)
    end;
rand_bytes(Min, Max) ->
    N = Min + rand:uniform(Max - Min + 1) - 1,
    rand:bytes(N).

flip_random_bit(<<>>) ->
    <<0>>;
flip_random_bit(Bin) ->
    Size = byte_size(Bin),
    Idx = rand:uniform(Size) - 1,
    <<Prefix:Idx/binary, Byte:8, Suffix/binary>> = Bin,
    BitPos = rand:uniform(8) - 1,
    Flipped = Byte bxor (1 bsl BitPos),
    <<Prefix/binary, Flipped:8, Suffix/binary>>.
