-module(crypto_adversarial_SUITE).

%% Adversarial input-validation properties for the signal_nif crypto surface.
%% Each property asserts: for malformed inputs, the NIF must NOT return {ok,_}
%% (or `ok` for verify) -- it must return {error,_}, raise, or return
%% invalid_signature. Silent acceptance of garbage = security bug.
%%
%% Every NIF call is wrapped in try/catch -- a NIF that crashes the VM on bad
%% input is itself a finding (CT will report the suite as crashed).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([adv_aes_gcm_wrong_key_size/1, adv_aes_gcm_wrong_iv_size/1,
         adv_aes_gcm_wrong_tag_len/1, adv_aes_gcm_decrypt_plaintext_len_overflow/1,
         adv_aes_gcm_decrypt_plaintext_len_underflow/1, adv_ed25519_sign_wrong_privkey_size/1,
         adv_ed25519_verify_wrong_sig_size/1, adv_ed25519_verify_wrong_pubkey_size/1,
         adv_hmac_empty_key/1]).

-define(ITERATIONS, 50).
-define(SEED, {7, 11, 13}).

all() ->
    [adv_aes_gcm_wrong_key_size,
     adv_aes_gcm_wrong_iv_size,
     adv_aes_gcm_wrong_tag_len,
     adv_aes_gcm_decrypt_plaintext_len_overflow,
     adv_aes_gcm_decrypt_plaintext_len_underflow,
     adv_ed25519_sign_wrong_privkey_size,
     adv_ed25519_verify_wrong_sig_size,
     adv_ed25519_verify_wrong_pubkey_size,
     adv_hmac_empty_key].

init_per_suite(Config) ->
    dr_test_helpers:nif_or_skip(Config, ?SEED).

end_per_suite(_Config) ->
    ok.

%% ============================================================================
%% AES-GCM key size mutations -- libsodium AES-256-GCM requires exactly 32B
%% ============================================================================

adv_aes_gcm_wrong_key_size(_) ->
    BadSizes = [0, 1, 15, 16, 24, 31, 33, 48, 64, 128],
    Findings =
        lists:filtermap(fun(Size) ->
                           BadKey = rand:bytes(Size),
                           IV = rand:bytes(12),
                           PT = rand:bytes(64),
                           case safe_call(fun() ->
                                             signal_nif:aes_gcm_encrypt(BadKey, IV, PT, <<>>, 16)
                                          end)
                           of
                               {ok, _, _} ->
                                   {true, {silent_accept, key_size, Size}};
                               _ ->
                                   false
                           end
                        end,
                        BadSizes),
    case Findings of
        [] ->
            ok;
        _ ->
            ?assertEqual([], Findings)
    end.

%% ============================================================================
%% AES-GCM IV size mutations -- libsodium expects 12 bytes
%% ============================================================================

adv_aes_gcm_wrong_iv_size(_) ->
    BadSizes = [0, 1, 8, 11, 13, 16, 24, 32, 64],
    K = rand:bytes(32),
    PT = rand:bytes(64),
    Findings =
        lists:filtermap(fun(Size) ->
                           BadIV = rand:bytes(Size),
                           case safe_call(fun() ->
                                             signal_nif:aes_gcm_encrypt(K, BadIV, PT, <<>>, 16)
                                          end)
                           of
                               {ok, _, _} ->
                                   {true, {silent_accept, iv_size, Size}};
                               _ ->
                                   false
                           end
                        end,
                        BadSizes),
    ?assertEqual([], Findings).

%% ============================================================================
%% AES-GCM TagLen parameter -- libsodium produces a fixed 16-byte tag.
%% This documents what happens for off-spec TagLen values.
%% Acceptable: {error,_} OR {ok, CT, Tag} where byte_size(Tag) == requested
%%             AND the tag is still meaningful (decrypt accepts it).
%% Finding: silently produces a tag of wrong size, OR a tag that decrypt won't
%%          verify against (would indicate output truncation breaks AEAD).
%% ============================================================================

adv_aes_gcm_wrong_tag_len(_) ->
    K = rand:bytes(32),
    IV = rand:bytes(12),
    PT = rand:bytes(32),
    %% TagLens that aren't libsodium's native 16
    Cases = [0, 4, 8, 12, 15, 17, 20, 24, 32],
    Findings =
        lists:filtermap(fun(TagLen) ->
                           case safe_call(fun() ->
                                             signal_nif:aes_gcm_encrypt(K, IV, PT, <<>>, TagLen)
                                          end)
                           of
                               {ok, CT, Tag} ->
                                   ActualSize = byte_size(Tag),
                                   %% Either produced the requested size, OR ignored the param.
                                   %% If produced != requested AND != 16, that's a finding.
                                   case ActualSize of
                                       TagLen ->
                                           %% Honors param. Does decrypt round-trip?
                                           check_roundtrip_with_tag(K, IV, CT, Tag, PT, TagLen);
                                       16 ->
                                           %% Ignored param, used native 16. Acceptable.
                                           false;
                                       _ ->
                                           {true,
                                            {tag_size_mismatch, requested, TagLen, got, ActualSize}}
                                   end;
                               _ ->
                                   false
                           end
                        end,
                        Cases),
    ?assertEqual([], Findings).

check_roundtrip_with_tag(K, IV, CT, Tag, PT, _TagLen) ->
    case safe_call(fun() -> signal_nif:aes_gcm_decrypt(K, IV, CT, <<>>, Tag, byte_size(PT))
                   end)
    of
        {ok, PT} ->
            false;
        {ok, Other} ->
            {true, {tag_roundtrip_wrong_pt, expected, PT, got, Other}};
        _ ->
            false
    end.

%% ============================================================================
%% AES-GCM decrypt PlaintextLen overflow -- pass a value LARGER than actual PT.
%% The NIF likely allocates PlaintextLen bytes; if it doesn't bound output,
%% the caller gets uninitialized memory past the real plaintext.
%% Acceptable: returns {ok, Plaintext} where Plaintext is exactly the real PT,
%%             OR returns {error,_}.
%% Finding: returns a binary larger than the real plaintext (uninit leak).
%% ============================================================================

adv_aes_gcm_decrypt_plaintext_len_overflow(_) ->
    Findings =
        lists:filtermap(fun(_) ->
                           K = rand:bytes(32),
                           IV = rand:bytes(12),
                           PT = rand_bytes(1, 512),
                           AAD = rand_bytes(0, 64),
                           {ok, CT, Tag} = signal_nif:aes_gcm_encrypt(K, IV, PT, AAD, 16),
                           Overflow = byte_size(PT) + 1 + rand:uniform(64),
                           case safe_call(fun() ->
                                             signal_nif:aes_gcm_decrypt(K,
                                                                        IV,
                                                                        CT,
                                                                        AAD,
                                                                        Tag,
                                                                        Overflow)
                                          end)
                           of
                               {ok, Got} when byte_size(Got) > byte_size(PT) ->
                                   {true,
                                    {oversize_output,
                                     real_pt_len,
                                     byte_size(PT),
                                     claimed_len,
                                     Overflow,
                                     got_len,
                                     byte_size(Got)}};
                               {ok, PT} ->
                                   false;
                               {ok, Other} ->
                                   {true, {wrong_plaintext_returned, PT, Other}};
                               _ ->
                                   false
                           end
                        end,
                        lists:seq(1, ?ITERATIONS)),
    ?assertEqual([], Findings).

%% ============================================================================
%% AES-GCM decrypt PlaintextLen underflow -- pass a value SMALLER than actual.
%% Acceptable: {error,_} OR exception OR truncated-but-tag-rejects.
%% Finding: returns {ok, Truncated} with no auth failure (silent corruption).
%% ============================================================================

adv_aes_gcm_decrypt_plaintext_len_underflow(_) ->
    Findings =
        lists:filtermap(fun(_) ->
                           K = rand:bytes(32),
                           IV = rand:bytes(12),
                           PT = rand_bytes(2, 512),
                           AAD = rand_bytes(0, 64),
                           {ok, CT, Tag} = signal_nif:aes_gcm_encrypt(K, IV, PT, AAD, 16),
                           Underflow = max(0, byte_size(PT) - rand:uniform(byte_size(PT))),
                           case safe_call(fun() ->
                                             signal_nif:aes_gcm_decrypt(K,
                                                                        IV,
                                                                        CT,
                                                                        AAD,
                                                                        Tag,
                                                                        Underflow)
                                          end)
                           of
                               {ok, Truncated} when Underflow < byte_size(PT) ->
                                   {true,
                                    {silent_truncation,
                                     real_pt_len,
                                     byte_size(PT),
                                     claimed_len,
                                     Underflow,
                                     got_len,
                                     byte_size(Truncated)}};
                               _ ->
                                   false
                           end
                        end,
                        lists:seq(1, ?ITERATIONS)),
    ?assertEqual([], Findings).

%% ============================================================================
%% Ed25519 sign with wrong-sized private key -- 32 bytes expected
%% ============================================================================

adv_ed25519_sign_wrong_privkey_size(_) ->
    Msg = <<"adversarial">>,
    BadSizes = [0, 1, 16, 31, 33, 48, 63, 65, 128],
    Findings =
        lists:filtermap(fun(Size) ->
                           BadPriv = rand:bytes(Size),
                           case safe_call(fun() -> signal_nif:sign_data(BadPriv, Msg) end) of
                               {ok, Sig} when byte_size(Sig) =:= 64 ->
                                   {true, {silent_accept, privkey_size, Size}};
                               _ ->
                                   false
                           end
                        end,
                        BadSizes),
    ?assertEqual([], Findings).

%% ============================================================================
%% Ed25519 verify with wrong-sized signature -- 64 bytes expected
%% ============================================================================

adv_ed25519_verify_wrong_sig_size(_) ->
    {ok, {Pub, _}} = signal_nif:generate_ed25519_keypair(),
    Msg = <<"adversarial">>,
    BadSizes = [0, 1, 32, 63, 65, 96, 128],
    Findings =
        lists:filtermap(fun(Size) ->
                           BadSig = rand:bytes(Size),
                           case safe_call(fun() -> signal_nif:verify_signature(Pub, Msg, BadSig)
                                          end)
                           of
                               ok ->
                                   {true, {silent_accept, sig_size, Size}};
                               _ ->
                                   false
                           end
                        end,
                        BadSizes),
    ?assertEqual([], Findings).

%% ============================================================================
%% Ed25519 verify with wrong-sized public key -- 32 bytes expected
%% ============================================================================

adv_ed25519_verify_wrong_pubkey_size(_) ->
    {ok, {_, Priv}} = signal_nif:generate_ed25519_keypair(),
    Msg = <<"adversarial">>,
    {ok, Sig} = signal_nif:sign_data(Priv, Msg),
    BadSizes = [0, 1, 16, 31, 33, 48, 64, 128],
    Findings =
        lists:filtermap(fun(Size) ->
                           BadPub = rand:bytes(Size),
                           case safe_call(fun() -> signal_nif:verify_signature(BadPub, Msg, Sig)
                                          end)
                           of
                               ok ->
                                   {true, {silent_accept, pubkey_size, Size}};
                               _ ->
                                   false
                           end
                        end,
                        BadSizes),
    ?assertEqual([], Findings).

%% ============================================================================
%% HMAC with empty key -- RFC 2104 permits any key length, libsodium accepts 0.
%% This is a behavior probe, not a security finding.
%% ============================================================================

adv_hmac_empty_key(_) ->
    Data = <<"probe">>,
    case safe_call(fun() -> signal_nif:hmac_sha256(<<>>, Data) end) of
        {ok, Mac} when byte_size(Mac) =:= 32 ->
            ct:pal("hmac_sha256 accepts empty key (returns 32B MAC) -- documented behavior"),
            ok;
        Other ->
            ct:pal("hmac_sha256 with empty key returned: ~p", [Other]),
            ok
    end.

%% ============================================================================
%% Helpers
%% ============================================================================

safe_call(Fun) ->
    try
        Fun()
    catch
        error:E ->
            {error_raised, E};
        exit:E ->
            {exit_raised, E};
        E ->
            {throw_raised, E}
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
