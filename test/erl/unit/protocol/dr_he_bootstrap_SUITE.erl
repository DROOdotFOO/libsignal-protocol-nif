-module(dr_he_bootstrap_SUITE).

%% Pins the DR-HE state-layout + KDF-expansion contract change.
%%
%% After dr_init was widened to accept a 96B shared_secret (64B X3DH SK
%% concatenated with a 32B shared header-key seed), the public NIF must:
%%   - reject anything other than 96B with invalid_shared_secret_size,
%%   - accept exactly 96B and return a usable DR state.
%%
%% Internal symmetry (Alice HKs == Bob HKr after the first ratchet step) is
%% not externally observable until DR-HE is on the wire; that invariant gets
%% pinned by the cross-decrypt round-trip in the follow-up wire-format suite.
%% Here we only fix the observable contract.

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([rejects_64_byte_shared_secret/1, rejects_95_byte_shared_secret/1,
         rejects_zero_byte_shared_secret/1, accepts_96_byte_shared_secret/1,
         dr_state_size_pinned/1, untagged_session_blob_rejected/1,
         wrong_size_session_blob_rejected/1, corrupt_blob_never_crashes/1]).

all() ->
    [rejects_64_byte_shared_secret,
     rejects_95_byte_shared_secret,
     rejects_zero_byte_shared_secret,
     accepts_96_byte_shared_secret,
     dr_state_size_pinned,
     untagged_session_blob_rejected,
     wrong_size_session_blob_rejected,
     corrupt_blob_never_crashes].

init_per_suite(Config) ->
    dr_test_helpers:nif_or_skip(Config, {17, 19, 23}).

end_per_suite(_Config) ->
    ok.

%% ============================================================================
%% Tests
%% ============================================================================

rejects_64_byte_shared_secret(_Config) ->
    {AlicePub, _AlicePriv, BobPub, _BobPriv} = fresh_identities(),
    SS = rand:bytes(64),
    ?assertEqual({error, invalid_shared_secret_size},
                 libsignal_protocol_nif:dr_init(SS, AlicePub, BobPub, <<>>, 1)).

rejects_95_byte_shared_secret(_Config) ->
    {AlicePub, _AlicePriv, BobPub, _BobPriv} = fresh_identities(),
    SS = rand:bytes(95),
    ?assertEqual({error, invalid_shared_secret_size},
                 libsignal_protocol_nif:dr_init(SS, AlicePub, BobPub, <<>>, 1)).

rejects_zero_byte_shared_secret(_Config) ->
    {AlicePub, _AlicePriv, BobPub, _BobPriv} = fresh_identities(),
    ?assertEqual({error, invalid_shared_secret_size},
                 libsignal_protocol_nif:dr_init(<<>>, AlicePub, BobPub, <<>>, 1)).

accepts_96_byte_shared_secret(_Config) ->
    {AlicePub, _AlicePriv, BobPub, BobPriv} = fresh_identities(),
    SS = rand:bytes(96),
    ?assertMatch({ok, _}, libsignal_protocol_nif:dr_init(SS, AlicePub, BobPub, <<>>, 1)),
    ?assertMatch({ok, _}, libsignal_protocol_nif:dr_init(SS, BobPub, AlicePub, BobPriv, 0)).

%% Pin the DR state binary size on this build target so unintended struct
%% growth (extra fields, padding) is caught at test time. The blob is a
%% verbatim copy of double_ratchet_state_t, so its size is:
%%
%%   8  magic || version || size tag
%%   32 root key + 2 * 32 chain keys + 2 * 4 message numbers
%%   32 dh_send_private + 2 * 32 dh public keys
%%   2 * 32 identity pubs (X25519) + 32 identity pub (Ed25519, for PKSM)
%%   4 * 32 header keys (current and next, per direction)
%%   4 prev_send_length + 2 bools + padding
%%   96 MKSKIPPED slots of 76 bytes (3 * MAX_SKIP) + 4 LRU clock
%%
%% Padding and alignment are platform-dependent; if this fails on a new
%% target, confirm the delta matches a known struct change before updating.
dr_state_size_pinned(_Config) ->
    {AlicePub, _AlicePriv, BobPub, _BobPriv} = fresh_identities(),
    SS = rand:bytes(96),
    {ok, Alice} = libsignal_protocol_nif:dr_init(SS, AlicePub, BobPub, <<>>, 1),
    ?assertEqual(7740, byte_size(Alice)).

%% A blob of the right length that does not carry this build's magic/version
%% tag is rejected outright rather than reinterpreted as key material. Covers
%% blobs from another release, all-zero buffers, and random garbage.
untagged_session_blob_rejected(_Config) ->
    Session = fresh_session(),
    Size = byte_size(Session),
    Blobs =
        [{zeros, <<0:Size/unit:8>>},
         {garbage, rand:bytes(Size)},
         %% Valid blob with one bit flipped inside the 8-byte tag.
         {flipped_tag, flip_bit(Session, 0)},
         {flipped_version, flip_bit(Session, 4)}],
    lists:foreach(fun({Name, Blob}) ->
                     ?assertEqual({error, invalid_session},
                                  libsignal_protocol_nif:dr_encrypt(Blob, <<"x">>),
                                  Name),
                     ?assertEqual({error, invalid_session},
                                  libsignal_protocol_nif:dr_decrypt(Blob, <<16#33, 0:64>>),
                                  Name)
                  end,
                  Blobs).

%% Length mismatch is reported separately from a bad tag: a blob built by a
%% different struct layout cannot even be measured against this one.
wrong_size_session_blob_rejected(_Config) ->
    Session = fresh_session(),
    Short = binary:part(Session, 0, byte_size(Session) - 1),
    Long = <<Session/binary, 0>>,
    lists:foreach(fun(Blob) ->
                     ?assertEqual({error, invalid_session_size},
                                  libsignal_protocol_nif:dr_encrypt(Blob, <<"x">>)),
                     ?assertEqual({error, invalid_session_size},
                                  libsignal_protocol_nif:dr_decrypt(Blob, <<16#33, 0:64>>))
                  end,
                  [<<>>, Short, Long]).

%% Set each byte of a live session to 0xFF in turn and decrypt a real
%% ciphertext with the result. The NIF must always return a term -- never
%% crash the VM. This is the containment property for the bool fields:
%% `initialized`, `dh_recv_initialized` and every `mkskipped[i].occupied`
%% hold caller-supplied bytes, and reading a bool whose representation is
%% neither 0 nor 1 is undefined behaviour, so the loader normalises them.
corrupt_blob_never_crashes(_Config) ->
    {AlicePub, _AlicePriv, BobPub, BobPriv} = fresh_identities(),
    SS = rand:bytes(96),
    {ok, Alice} = libsignal_protocol_nif:dr_init(SS, AlicePub, BobPub, <<>>, 1),
    {ok, Bob} = libsignal_protocol_nif:dr_init(SS, BobPub, AlicePub, BobPriv, 0),
    {ok, {CT, _Alice1}} = libsignal_protocol_nif:dr_encrypt(Alice, <<"payload">>),
    Bad =
        [Pos
         || Pos <- lists:seq(0, byte_size(Bob) - 1),
            not is_term_result(
                    catch libsignal_protocol_nif:dr_decrypt(set_byte(Bob, Pos, 16#FF), CT))],
    ?assertEqual([], Bad).

is_term_result({ok, {_, _}}) -> true;
is_term_result({error, Atom}) when is_atom(Atom) -> true;
is_term_result(_) -> false.

%% ============================================================================
%% Helpers
%% ============================================================================

fresh_identities() ->
    {ok, {AlicePub, AlicePriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, {BobPub, BobPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {AlicePub, AlicePriv, BobPub, BobPriv}.

fresh_session() ->
    {AlicePub, _AlicePriv, BobPub, _BobPriv} = fresh_identities(),
    {ok, Session} = libsignal_protocol_nif:dr_init(rand:bytes(96), AlicePub, BobPub, <<>>, 1),
    Session.

flip_bit(Bin, Pos) ->
    <<Pre:Pos/binary, Byte:8, Rest/binary>> = Bin,
    <<Pre/binary, (Byte bxor 1):8, Rest/binary>>.

set_byte(Bin, Pos, Val) ->
    <<Pre:Pos/binary, _:8, Rest/binary>> = Bin,
    <<Pre/binary, Val:8, Rest/binary>>.
