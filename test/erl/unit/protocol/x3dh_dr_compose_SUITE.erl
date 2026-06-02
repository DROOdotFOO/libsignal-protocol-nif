-module(x3dh_dr_compose_SUITE).

%% Verifies that process_pre_key_bundle (X3DH from Alice's side) composes
%% correctly with dr_init: the 96-byte secret Alice gets from
%% X3DH (64B SK || 32B shared header key for DR-HE) is a valid root seed
%% for a Double Ratchet session, and Alice + Bob can exchange messages
%% once both initialize DR with that secret.
%%
%% Now that the NIF uses raw X25519 (crypto_scalarmult, no HSalsa20 post-mix),
%% Bob-side reconstruction is testable in Erlang via crypto:compute_key/4.
%% bob_side_x3dh_matches/1 reproduces Alice's SK by computing the same three
%% DH outputs from Bob's keys and Alice's published EK + IK.
%%
%% The bundle signed-prekey signature is Ed25519 (libsodium crypto_sign).
%% Identity keypairs are Ed25519 (32B pub, 64B priv); the NIF converts to
%% X25519 internally for DH operations.

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([x3dh_returns_96_byte_secret/1, dr_handshake_after_x3dh/1,
         bob_side_x3dh_matches/1, random_trials/1]).

all() ->
    [x3dh_returns_96_byte_secret,
     dr_handshake_after_x3dh,
     bob_side_x3dh_matches,
     random_trials].

init_per_suite(Config) ->
    rand:seed(exsss, {61, 67, 71}),
    case signal_nif:test_crypto() of
        crypto_ok ->
            Config;
        Other ->
            {skip, {nif_init_failed, Other}}
    end.

end_per_suite(_Config) ->
    ok.

%% ============================================================================
%% Helpers
%% ============================================================================

%% Build Bob's published bundle. Returns {Bundle, BobIdPub, BobIdPriv} so the
%% test can also init Bob's DR side with the matching identity priv.
build_bundle() ->
    {ok, {BobIdPub, BobIdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    %% Use the NIF's own helper to mint a properly-signed prekey.
    {ok, {_KeyId, SpkPub, Signature}} =
        libsignal_protocol_nif:generate_signed_pre_key(BobIdPriv, 1),
    Bundle = <<BobIdPub/binary, SpkPub/binary, Signature/binary>>,
    {Bundle, BobIdPub, BobIdPriv}.

%% Same as build_bundle/0 but also returns the SPK private key, so the test
%% can reconstruct Bob's side of X3DH. The NIF's generate_signed_pre_key/2
%% destroys the SPK priv, so we mint the SPK keypair ourselves and sign with
%% signal_nif:sign_data/2 (which takes the 32B Ed25519 seed).
build_bundle_with_spk_priv() ->
    {ok, {BobIdPub, BobIdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, {SpkPub, SpkPriv}} = signal_nif:generate_curve25519_keypair(),
    BobIdSeed = binary:part(BobIdPriv, 0, 32),
    {ok, Signature} = signal_nif:sign_data(BobIdSeed, SpkPub),
    Bundle = <<BobIdPub/binary, SpkPub/binary, Signature/binary>>,
    {Bundle, BobIdPub, BobIdPriv, SpkPub, SpkPriv}.

%% HKDF-SHA-256 (RFC 5869), matching the C impl in c_src/dr.c. Empty salt
%% means "use 32 zero bytes" (Extract step), matching what the NIF passes for
%% X3DH (salt=NULL).
hkdf_sha256(IKM, Salt, Info, Length) ->
    UseSalt =
        case Salt of
            <<>> ->
                binary:copy(<<0>>, 32);
            _ ->
                Salt
        end,
    PRK = crypto:mac(hmac, sha256, UseSalt, IKM),
    hkdf_expand(PRK, Info, Length, 1, <<>>, <<>>).

hkdf_expand(_PRK, _Info, Length, _Counter, _TPrev, Acc) when byte_size(Acc) >= Length ->
    binary:part(Acc, 0, Length);
hkdf_expand(PRK, Info, Length, Counter, TPrev, Acc) ->
    T = crypto:mac(hmac, sha256, PRK, <<TPrev/binary, Info/binary, Counter:8>>),
    hkdf_expand(PRK, Info, Length, Counter + 1, T, <<Acc/binary, T/binary>>).

%% ============================================================================
%% Tests
%% ============================================================================

x3dh_returns_96_byte_secret(_Config) ->
    {ok, {_, AliceIdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {Bundle, _BobIdPub, _BobIdPriv} = build_bundle(),
    {ok, {SS, EphPub}} = libsignal_protocol_nif:process_pre_key_bundle(AliceIdPriv, Bundle),
    ?assertEqual(96, byte_size(SS)),
    ?assertEqual(32, byte_size(EphPub)).

dr_handshake_after_x3dh(_Config) ->
    {ok, {AliceIdPub, AliceIdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {Bundle, BobIdPub, BobIdPriv} = build_bundle(),
    {ok, {SS, _EphPub}} = libsignal_protocol_nif:process_pre_key_bundle(AliceIdPriv, Bundle),
    {ok, Alice} =
        libsignal_protocol_nif:dr_init(SS, AliceIdPub, BobIdPub, <<>>, 1),
    {ok, Bob} =
        libsignal_protocol_nif:dr_init(SS, BobIdPub, AliceIdPub, BobIdPriv, 0),
    Msg = <<"x3dh then dr">>,
    {ok, {CT, _}} = libsignal_protocol_nif:dr_encrypt(Alice, Msg),
    {ok, {PT, Bob1}} = libsignal_protocol_nif:dr_decrypt(Bob, CT),
    ?assertEqual(Msg, PT),
    Reply = <<"reply">>,
    {ok, {CT2, _}} = libsignal_protocol_nif:dr_encrypt(Bob1, Reply),
    {ok, {PT2, _}} = libsignal_protocol_nif:dr_decrypt(Alice, CT2),
    ?assertEqual(Reply, PT2).

%% Reconstruct the X3DH shared secret from Bob's side and check it matches
%% what Alice derived. Bob has: his identity priv (Ed25519 → X25519), his
%% SPK priv (X25519). He receives: Alice's identity pub (Ed25519 → X25519)
%% and Alice's ephemeral pub (X25519). The three DH outputs commute with
%% Alice's, so the same KM and the same HKDF should yield the same SK.
bob_side_x3dh_matches(_Config) ->
    {ok, {AliceIdPub, AliceIdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {Bundle, _BobIdPub, BobIdPriv, _SpkPub, SpkPriv} = build_bundle_with_spk_priv(),
    {ok, {AliceSK, AliceEphPub}} =
        libsignal_protocol_nif:process_pre_key_bundle(AliceIdPriv, Bundle),

    {ok, BobIdPrivX} = signal_nif:ed25519_sk_to_curve25519(BobIdPriv),
    {ok, AliceIdPubX} = signal_nif:ed25519_pk_to_curve25519(AliceIdPub),

    DH1 = crypto:compute_key(ecdh, AliceIdPubX, SpkPriv, x25519),
    DH2 = crypto:compute_key(ecdh, AliceEphPub, BobIdPrivX, x25519),
    DH3 = crypto:compute_key(ecdh, AliceEphPub, SpkPriv, x25519),

    F = binary:copy(<<16#FF>>, 32),
    IKM = <<F/binary, DH1/binary, DH2/binary, DH3/binary>>,
    BobSK = hkdf_sha256(IKM, <<>>, <<"X3DH-Signal">>, 96),

    ?assertEqual(AliceSK, BobSK).

%% Property: any fresh keypair set composes correctly through X3DH + DR.
random_trials(_Config) ->
    [run_trial() || _ <- lists:seq(1, 10)],
    ok.

run_trial() ->
    {ok, {AliceIdPub, AliceIdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {Bundle, BobIdPub, BobIdPriv} = build_bundle(),
    {ok, {SS, _EphPub}} = libsignal_protocol_nif:process_pre_key_bundle(AliceIdPriv, Bundle),
    {ok, Alice} =
        libsignal_protocol_nif:dr_init(SS, AliceIdPub, BobIdPub, <<>>, 1),
    {ok, Bob} =
        libsignal_protocol_nif:dr_init(SS, BobIdPub, AliceIdPub, BobIdPriv, 0),
    Msg = <<"random trial ", (rand:bytes(8))/binary>>,
    {ok, {CT, _}} = libsignal_protocol_nif:dr_encrypt(Alice, Msg),
    {ok, {PT, _}} = libsignal_protocol_nif:dr_decrypt(Bob, CT),
    ?assertEqual(Msg, PT).
