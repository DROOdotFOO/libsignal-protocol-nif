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
-export([hmac_forgery_rejected/1, garbage_signature_rejected/1,
         bundle_length_is_pinned/1]).

all() ->
    [hmac_forgery_rejected, garbage_signature_rejected, bundle_length_is_pinned].

init_per_suite(Config) ->
    dr_test_helpers:nif_or_skip(Config, {73, 79, 83}).

end_per_suite(_Config) ->
    ok.

%% Reproduce the pre-Ed25519 attack: attacker uses Bob's published identity
%% pub as an HMAC key to "sign" an arbitrary signed prekey.
hmac_forgery_rejected(_Config) ->
    {ok, {BobIdPub, _BobIdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, {AttackerSpkPub, _AttackerSpkPriv}} = signal_nif:generate_curve25519_keypair(),
    %% Old attack: HMAC-SHA512-256(spk_pub, key=id_pub). Identity pub is public
    %% so anyone can compute this. Pad to 64 bytes to match Ed25519 signature
    %% length (the new bundle format).
    HmacShort =
        binary:part(
            crypto:mac(hmac, sha512, BobIdPub, AttackerSpkPub), 0, 32),
    ForgedSig = <<HmacShort/binary, HmacShort/binary>>,
    ForgedBundle = <<BobIdPub/binary, AttackerSpkPub/binary, ForgedSig/binary>>,

    {ok, {_, AliceIdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    ?assertEqual({error, signature_verification_failed},
                 libsignal_protocol_nif:process_pre_key_bundle(AliceIdPriv, ForgedBundle)).

%% A bundle is exactly 128 bytes, or 160 with a one-time pre-key. Accepting
%% anything >= 160 as "has an OPK" lets a padded bundle through with its
%% trailing bytes read as a key, and accepting 129..159 silently drops them.
%% Only the SPK is covered by the signature, so length is the only handle the
%% NIF has on the optional field. (Removing the OPK from a real bundle still
%% yields a valid 128-byte bundle -- that downgrade is the embedder's to
%% detect; see docs/SECURITY.md.)
bundle_length_is_pinned(_Config) ->
    {ok, {AliceIdPub, AliceIdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, {BobIdPub, BobIdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, {_Id, SpkPub, _SpkPriv, Sig}} =
        libsignal_protocol_nif:generate_signed_pre_key(BobIdPriv, 1),
    {ok, {_Id2, OpkPub, _OpkPriv}} = libsignal_protocol_nif:generate_pre_key(2),
    B128 = <<BobIdPub/binary, SpkPub/binary, Sig/binary>>,
    B160 = <<B128/binary, OpkPub/binary>>,
    128 = byte_size(B128),
    160 = byte_size(B160),
    %% Both legal lengths are accepted.
    ?assertMatch({ok, {_, _}}, libsignal_protocol_nif:process_pre_key_bundle(AliceIdPriv, B128)),
    ?assertMatch({ok, {_, _}}, libsignal_protocol_nif:process_pre_key_bundle(AliceIdPriv, B160)),
    %% Everything else is rejected on length alone, before any DH.
    lists:foreach(fun(Bad) ->
                     ?assertEqual({error, invalid_bundle_size},
                                  libsignal_protocol_nif:process_pre_key_bundle(AliceIdPriv, Bad),
                                  byte_size(Bad))
                  end,
                  [<<>>,
                   binary:part(B128, 0, 127),
                   <<B128/binary, 0>>,
                   binary:part(B160, 0, 159),
                   <<B160/binary, 0>>,
                   <<B160/binary, AliceIdPub/binary>>]).

%% Random 64-byte "signature" must also be rejected.
garbage_signature_rejected(_Config) ->
    {ok, {BobIdPub, _BobIdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, {SpkPub, _SpkPriv}} = signal_nif:generate_curve25519_keypair(),
    GarbageSig = rand:bytes(64),
    Bundle = <<BobIdPub/binary, SpkPub/binary, GarbageSig/binary>>,

    {ok, {_, AliceIdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    ?assertEqual({error, signature_verification_failed},
                 libsignal_protocol_nif:process_pre_key_bundle(AliceIdPriv, Bundle)).
