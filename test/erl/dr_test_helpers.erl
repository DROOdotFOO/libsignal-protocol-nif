-module(dr_test_helpers).

-export([nif_or_skip/2, fresh_dr_parties/0, fresh_dr_parties_to_config/1]).

%% Verifies the NIF is loaded and seeds the PRNG. Use from init_per_suite/1
%% in any suite that exercises the NIF. Returns the Config tuple if the NIF
%% is ready, {skip, {nif_init_failed, Reason}} otherwise.
-spec nif_or_skip(Config :: list(), Seed :: term()) ->
                     list() | {skip, {nif_init_failed, term()}}.
nif_or_skip(Config, Seed) ->
    rand:seed(exsss, Seed),
    case signal_nif:test_crypto() of
        crypto_ok ->
            Config;
        Other ->
            {skip, {nif_init_failed, Other}}
    end.

%% Generates two fresh Ed25519 identity pairs and bootstraps a DR session
%% pair (Alice initiator, Bob responder) seeded with a 96-byte random shared
%% secret. Returns {AliceSession, BobSession} -- both ready to encrypt and
%% decrypt the Signal DR wire format.
-spec fresh_dr_parties() -> {binary(), binary()}.
fresh_dr_parties() ->
    {ok, {AlicePub, _AlicePriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, {BobPub, BobPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    SS = rand:bytes(96),
    {ok, Alice} = libsignal_protocol_nif:dr_init(SS, AlicePub, BobPub, <<>>, 1),
    {ok, Bob} = libsignal_protocol_nif:dr_init(SS, BobPub, AlicePub, BobPriv, 0),
    {Alice, Bob}.

%% init_per_testcase convenience: bootstraps a fresh DR pair and injects it
%% into Config under the keys {alice, _} and {bob, _}.
-spec fresh_dr_parties_to_config(Config :: list()) -> list().
fresh_dr_parties_to_config(Config) ->
    {Alice, Bob} = fresh_dr_parties(),
    [{alice, Alice}, {bob, Bob} | Config].
