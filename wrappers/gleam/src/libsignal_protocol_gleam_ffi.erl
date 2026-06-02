%% Adapter shims that bridge Gleam's `Option(Int)` encoding
%% (`none` atom or `{some, N}` tuple) to the underlying NIF's idiomatic
%% Erlang form (`undefined` atom or a bare integer).
%%
%% Used only by the Gleam wrapper; not part of the public NIF surface.
-module(libsignal_protocol_gleam_ffi).

-export([dr_encrypt_prekey/3, pksm_decode/1, process_pre_key_bundle_bob/5,
         test_setup/0]).

%% Make the parent project's compiled Erlang modules + NIF priv dir
%% available to gleeunit. The Gleam test runner spins up a fresh BEAM that
%% knows nothing about the libsignal_protocol_nif app, so we add it to the
%% code path here and force-load the NIF stub modules. Callers should
%% invoke this once from their top-level test main before gleeunit.main().
test_setup() ->
    %% Locate the project root by walking up from the running test's CWD
    %% until we hit a directory containing `_build/default/lib/...`.
    Root = find_project_root(filename:absname(".")),
    EbinDir = filename:join([Root, "_build", "default", "lib",
                             "libsignal_protocol_nif", "ebin"]),
    case filelib:is_dir(EbinDir) of
        true ->
            code:add_pathz(EbinDir),
            {module, libsignal_protocol_nif} =
                code:ensure_loaded(libsignal_protocol_nif),
            {module, signal_nif} = code:ensure_loaded(signal_nif),
            ok;
        false ->
            erlang:error({libsignal_protocol_nif_ebin_missing, EbinDir,
                          "run `make build` in the project root"})
    end.

find_project_root(Dir) ->
    Candidate = filename:join([Dir, "_build", "default", "lib",
                               "libsignal_protocol_nif"]),
    case filelib:is_dir(Candidate) of
        true ->
            Dir;
        false ->
            Parent = filename:dirname(Dir),
            case Parent of
                Dir ->
                    erlang:error(project_root_not_found);
                _ ->
                    find_project_root(Parent)
            end
    end.

%% Encode side: convert Gleam's Option(Int) for the one-time-prekey id into
%% the NIF's `Int | undefined` shape.
dr_encrypt_prekey(Session, Plaintext,
                  {RegId, OpkOpt, SpkId, BaseKey}) ->
    OpkTerm =
        case OpkOpt of
            none -> undefined;
            {some, N} when is_integer(N) -> N
        end,
    libsignal_protocol_nif:dr_encrypt_prekey(
        Session, Plaintext, {RegId, OpkTerm, SpkId, BaseKey}).

%% Decode side: normalize the OPK id position in the NIF return into Gleam's
%% Option(Int) encoding.
pksm_decode(Wire) ->
    case libsignal_protocol_nif:pksm_decode(Wire) of
        {ok, {RegId, BaseKey, IdKey, OpkRaw, SpkId, Inner}} ->
            OpkOpt =
                case OpkRaw of
                    undefined -> none;
                    N when is_integer(N) -> {some, N}
                end,
            {ok, {RegId, BaseKey, IdKey, OpkOpt, SpkId, Inner}};
        Err ->
            Err
    end.

%% Pass-through. Exposed here so the Gleam wrapper has a stable single
%% adapter module to FFI against.
process_pre_key_bundle_bob(IdPriv, SpkPriv, OpkPriv, RemoteIdPub, RemoteEphPub) ->
    libsignal_protocol_nif:process_pre_key_bundle_bob(
        IdPriv, SpkPriv, OpkPriv, RemoteIdPub, RemoteEphPub).
