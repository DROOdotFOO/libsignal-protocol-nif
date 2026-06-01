-module(x3dh_forgery_SUITE).

%% Asserts that bundle signatures from non-identity-priv-holders are rejected.
%% Before the Ed25519 switch the C NIF used HMAC-SHA512-256 with the *public*
%% identity key as the MAC "secret", which let any attacker who saw the
%% published bundle forge a signature on any signed prekey of their choosing
%% -- the attack succeeded and Alice would establish a session against the
%% attacker's prekey. With Ed25519 the signature can only be produced by the
%% holder of the identity priv, so forgery attempts now fail with
%% `signature_verification_failed`.

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([hmac_forgery_rejected/1, garbage_signature_rejected/1]).

all() ->
    [hmac_forgery_rejected, garbage_signature_rejected].

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

%% Reproduce the pre-Ed25519 attack: attacker uses Bob's published identity
%% pub as an HMAC key to "sign" an arbitrary signed prekey.
hmac_forgery_rejected(_Config) ->
    {ok, {BobIdPub, _BobIdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, {AttackerSpkPub, _AttackerSpkPriv}} =
        signal_nif:generate_curve25519_keypair(),
    %% Old attack: HMAC-SHA512-256(spk_pub, key=id_pub). Identity pub is public
    %% so anyone can compute this. Pad to 64 bytes to match Ed25519 signature
    %% length (the new bundle format).
    HmacShort = binary:part(crypto:mac(hmac, sha512, BobIdPub, AttackerSpkPub), 0, 32),
    ForgedSig = <<HmacShort/binary, HmacShort/binary>>,
    ForgedBundle =
        <<BobIdPub/binary, AttackerSpkPub/binary, ForgedSig/binary>>,

    {ok, {_, AliceIdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    ?assertEqual({error, signature_verification_failed},
                 libsignal_protocol_nif:process_pre_key_bundle(
                   AliceIdPriv, ForgedBundle)).

%% Random 64-byte "signature" must also be rejected.
garbage_signature_rejected(_Config) ->
    {ok, {BobIdPub, _BobIdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, {SpkPub, _SpkPriv}} = signal_nif:generate_curve25519_keypair(),
    GarbageSig = rand:bytes(64),
    Bundle = <<BobIdPub/binary, SpkPub/binary, GarbageSig/binary>>,

    {ok, {_, AliceIdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    ?assertEqual({error, signature_verification_failed},
                 libsignal_protocol_nif:process_pre_key_bundle(
                   AliceIdPriv, Bundle)).
