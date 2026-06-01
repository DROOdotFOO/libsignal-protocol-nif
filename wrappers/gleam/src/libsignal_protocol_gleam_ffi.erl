%% Adapter shims that bridge Gleam's `Option(Int)` encoding
%% (`none` atom or `{some, N}` tuple) to the underlying NIF's idiomatic
%% Erlang form (`undefined` atom or a bare integer).
%%
%% Used only by the Gleam wrapper; not part of the public NIF surface.
-module(libsignal_protocol_gleam_ffi).

-export([dr_encrypt_prekey/3, pksm_decode/1, process_pre_key_bundle_bob/5]).

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
