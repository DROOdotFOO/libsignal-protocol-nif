-module(x3dh_forgery_SUITE).

%% Regression: the C NIF's process_pre_key_bundle uses HMAC-SHA512-256 with the
%% identity *public* key as the MAC key to authenticate the signed prekey.
%% Because the "secret" key is published, anyone who has the identity pub can
%% forge a signed-prekey "signature" -- there is no actual authentication.
%%
%% This suite currently asserts that forgery SUCCEEDS (proving the bug). After
%% the Ed25519 switch, the assertion will flip to `signature_verification_failed`.

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([forged_bundle_currently_accepted/1]).

all() ->
    [forged_bundle_currently_accepted].

init_per_suite(Config) ->
    rand:seed(exsss, {73, 79, 83}),
    case signal_nif:test_crypto() of
        crypto_ok ->
            Config;
        Other ->
            {skip, {nif_init_failed, Other}}
    end.

end_per_suite(_Config) ->
    ok.

forged_bundle_currently_accepted(_Config) ->
    %% Bob publishes his identity pub. That's the entire premise of bundles --
    %% identity pubs are public.
    {ok, {BobIdPub, _BobIdPriv}} = signal_nif:generate_curve25519_keypair(),

    %% Attacker knows ONLY BobIdPub. Builds an entirely separate signed prekey
    %% and forges the "signature" by HMAC'ing under Bob's published key.
    {ok, {AttackerSpkPub, _AttackerSpkPriv}} =
        signal_nif:generate_curve25519_keypair(),
    ForgedSig =
        binary:part(crypto:mac(hmac, sha512, BobIdPub, AttackerSpkPub), 0, 32),
    ForgedBundle = <<BobIdPub/binary, AttackerSpkPub/binary, ForgedSig/binary>>,

    %% Alice processes the forged bundle. The NIF accepts it -- the
    %% "signature verification" check passes because the HMAC key is public.
    {ok, {_, AliceIdPriv}} = signal_nif:generate_curve25519_keypair(),
    ?assertMatch({ok, {_SharedSecret, _EphemeralPub}},
                 libsignal_protocol_nif:process_pre_key_bundle(
                   AliceIdPriv, ForgedBundle)).
