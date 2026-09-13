-module(dr_test_helpers).

-export([nif_or_skip/2, nifs_loaded/0, fresh_dr_parties/0, fresh_dr_parties_to_config/1]).

%% Verifies both NIF stub modules loaded (their -on_load attached the .so)
%% and seeds the PRNG. Use from init_per_suite/1 in any suite that exercises
%% the NIF. Returns the Config tuple if the NIFs are ready,
%% {skip, {nif_init_failed, Reason}} otherwise.
-spec nif_or_skip(Config :: list(), Seed :: term()) ->
                     list() | {skip, {nif_init_failed, term()}}.
nif_or_skip(Config, Seed) ->
    rand:seed(exsss, Seed),
    case nifs_loaded() of
        ok ->
            Config;
        {error, Reason} ->
            {skip, {nif_init_failed, Reason}}
    end.

%% ok once every stub module is loaded; {error, {Module, Why}} for the first
%% one whose -on_load failed (Why is on_load_failure when the .so is missing).
-spec nifs_loaded() -> ok | {error, {module(), term()}}.
nifs_loaded() ->
    lists:foldl(fun(Mod, ok) ->
                       case code:ensure_loaded(Mod) of
                           {module, Mod} ->
                               ok;
                           {error, Why} ->
                               {error, {Mod, Why}}
                       end;
                   (_Mod, Err) ->
                       Err
                end,
                ok,
                [signal_nif, libsignal_protocol_nif]).

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
