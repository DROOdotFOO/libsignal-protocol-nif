%% Adapter between the Erlang NIF and the Gleam wrapper's types.
%%
%% Two jobs:
%%   1. Errors. The NIF returns `{error, Atom}`, but Gleam's declared type is
%%      `Result(_, String)`; an atom leaking through makes `Error("bad_mac")`
%%      unmatchable and crashes any `string` function applied to it. Every
%%      call goes through wrap/1, which converts the atom to a binary.
%%   2. Option(Int). Gleam encodes `Option` as the `none` atom or a
%%      `{some, N}` tuple; the NIF uses `undefined` or a bare integer.
%%
%% Every function the Gleam wrapper calls is listed here -- signal_protocol
%% has no direct @external to libsignal_protocol_nif, so the conversion
%% cannot be bypassed by accident.
-module(libsignal_protocol_gleam_ffi).

-export([generate_identity_key_pair/0, generate_pre_key/1, generate_signed_pre_key/2,
         process_pre_key_bundle/2, process_pre_key_bundle_bob/5,
         dr_init/5, dr_encrypt/2, dr_decrypt/2,
         dr_encrypt_prekey/3, pksm_decode/1,
         test_setup/0]).

%% {error, Atom} -> {error, Binary}. Everything else passes through.
wrap({error, Reason}) when is_atom(Reason) ->
    {error, atom_to_binary(Reason, utf8)};
wrap(Other) ->
    Other.

generate_identity_key_pair() ->
    wrap(libsignal_protocol_nif:generate_identity_key_pair()).

generate_pre_key(KeyId) ->
    wrap(libsignal_protocol_nif:generate_pre_key(KeyId)).

generate_signed_pre_key(IdentityPriv, KeyId) ->
    wrap(libsignal_protocol_nif:generate_signed_pre_key(IdentityPriv, KeyId)).

process_pre_key_bundle(LocalIdentityPriv, Bundle) ->
    wrap(libsignal_protocol_nif:process_pre_key_bundle(LocalIdentityPriv, Bundle)).

process_pre_key_bundle_bob(IdPriv, SpkPriv, OpkPriv, RemoteIdPub, RemoteEphPub) ->
    wrap(libsignal_protocol_nif:process_pre_key_bundle_bob(
             IdPriv, SpkPriv, OpkPriv, RemoteIdPub, RemoteEphPub)).

dr_init(SharedSecret, LocalIdPub, RemoteIdPub, SelfIdPriv, IsAlice) ->
    wrap(libsignal_protocol_nif:dr_init(
             SharedSecret, LocalIdPub, RemoteIdPub, SelfIdPriv, IsAlice)).

dr_encrypt(Session, Plaintext) ->
    wrap(libsignal_protocol_nif:dr_encrypt(Session, Plaintext)).

dr_decrypt(Session, Ciphertext) ->
    wrap(libsignal_protocol_nif:dr_decrypt(Session, Ciphertext)).

%% Encode side: convert Gleam's Option(Int) for the one-time-prekey id into
%% the NIF's `Int | undefined` shape.
dr_encrypt_prekey(Session, Plaintext, {RegId, OpkOpt, SpkId, BaseKey}) ->
    OpkTerm =
        case OpkOpt of
            none -> undefined;
            {some, N} when is_integer(N) -> N
        end,
    wrap(libsignal_protocol_nif:dr_encrypt_prekey(
             Session, Plaintext, {RegId, OpkTerm, SpkId, BaseKey})).

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
            wrap(Err)
    end.

%% Point gleeunit at the working tree's NIF instead of the Hex-resolved
%% copy of libsignal_protocol_nif that the dependency pulls in. Without
%% this, `gleam test` in this repo would exercise the last published
%% release rather than the code being changed.
%%
%% add_patha puts the local ebin ahead of the dependency's, and the two stub
%% modules are purged first in case the dependency copy is already loaded.
%% If there is no working tree (a consumer running these tests from a Hex
%% checkout), this is a no-op and the dependency's copy is used.
test_setup() ->
    case local_ebin_dir() of
        {ok, EbinDir} ->
            code:add_patha(EbinDir),
            lists:foreach(fun(M) ->
                              code:purge(M),
                              code:delete(M),
                              code:purge(M),
                              {module, M} = code:ensure_loaded(M)
                          end,
                          [libsignal_protocol_nif, signal_nif]),
            ok;
        error ->
            ok
    end.

local_ebin_dir() ->
    case find_project_root(filename:absname(".")) of
        {ok, Root} ->
            EbinDir = filename:join([Root, "_build", "default", "lib",
                                     "libsignal_protocol_nif", "ebin"]),
            case filelib:is_dir(EbinDir) of
                true -> {ok, EbinDir};
                false -> error
            end;
        error ->
            error
    end.

find_project_root(Dir) ->
    Candidate = filename:join([Dir, "_build", "default", "lib",
                               "libsignal_protocol_nif"]),
    case filelib:is_dir(Candidate) of
        true ->
            {ok, Dir};
        false ->
            Parent = filename:dirname(Dir),
            case Parent of
                Dir -> error;
                _ -> find_project_root(Parent)
            end
    end.
