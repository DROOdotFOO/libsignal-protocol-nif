-module(libsignal_nif_loader).

%% Shared NIF-loading strategy for the two stub modules in this app.
%%
%% erlang:load_nif/2 attaches the library to the module of the *calling*
%% function, so it cannot be called from here; each stub passes a fun that
%% wraps the call and this module only decides which paths to try and how to
%% interpret the result.
%%
%% Resolution order:
%%   1. code:priv_dir(libsignal_protocol_nif) -- the OTP-resolved priv dir.
%%      Works wherever this app is on the code path: rebar3 profiles (rebar3
%%      symlinks _build/<profile>/lib/libsignal_protocol_nif/priv to priv/),
%%      releases, and the wrappers' test setups that add
%%      _build/default/lib/libsignal_protocol_nif/ebin.
%%   2. priv/<Lib> relative to CWD -- the bare `erl -pa` workflow from the
%%      project root, where the app is not on the code path.
%%
%% A candidate is only skipped when the .so is absent there. The first
%% candidate that exists is loaded and its result is final: a dlopen or
%% on_load failure (e.g. sodium_init() returning an error) is reported as
%% such rather than masked by "not found anywhere" after retrying the other
%% paths. Only .so is produced on every supported platform (see
%% c_src/CMakeLists.txt), so that is the only extension probed.
%%
%% Nothing is logged here: a failed -on_load already produces a warning
%% report from the code server carrying the returned error term.

-export([load/2]).

-type load_fun() :: fun((file:filename()) -> ok | {error, term()}).

-spec load(atom(), load_fun()) -> ok | {error, term()}.
load(Lib, LoadFun) ->
    Name = atom_to_list(Lib),
    try_paths(Lib, candidates(Name), LoadFun, []).

candidates(Name) ->
    AppPriv =
        case code:priv_dir(libsignal_protocol_nif) of
            {error, _} ->
                [];
            Dir ->
                [filename:join(Dir, Name)]
        end,
    AppPriv ++ [filename:join("priv", Name)].

try_paths(Lib, [], _LoadFun, Tried) ->
    {error, {nif_not_found, Lib, lists:reverse(Tried)}};
try_paths(Lib, [Path | Rest], LoadFun, Tried) ->
    case filelib:is_regular(Path ++ ".so") of
        false ->
            try_paths(Lib, Rest, LoadFun, [{Path, enoent} | Tried]);
        true ->
            case LoadFun(Path) of
                ok ->
                    ok;
                %% Library already attached to this module instance
                %% (load_nif called twice on the same code); NIFs are live.
                {error, {reload, _}} ->
                    ok;
                %% {upgrade, _} means the new module instance did NOT get the
                %% library (no upgrade callback in ERL_NIF_INIT). Returning ok
                %% would leave stub bodies live; fail so the old code stays.
                {error, Reason} ->
                    {error, {nif_load_failed, Lib, Path, Reason}}
            end
    end.
