-module(dr_he_envelope_SUITE).

%% Pins the DR-HE wire-format observable: the counter, previous_counter, and
%% ratchet_key are no longer visible on the wire because the inner header
%% protobuf is encrypted under header_key_send before being placed in the
%% outer envelope.
%%
%% The existing reorder + roundtrip + PKSM suites already prove the
%% encrypt/decrypt loop still composes correctly (so trial-decrypt + MAC
%% verify are functionally sound). This suite locks the actual traffic-
%% analysis property that motivated DR-HE.

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2]).
-export([wire_hides_counter/1,
         wire_hides_ratchet_key/1,
         tampered_envelope_rejected/1,
         wrong_session_cannot_decrypt/1,
         malformed_outer_envelope_rejected/1]).

all() ->
    [wire_hides_counter,
     wire_hides_ratchet_key,
     tampered_envelope_rejected,
     wrong_session_cannot_decrypt,
     malformed_outer_envelope_rejected].

init_per_suite(Config) ->
    rand:seed(exsss, {2, 3, 5}),
    case signal_nif:test_crypto() of
        crypto_ok -> Config;
        Other -> {skip, {nif_init_failed, Other}}
    end.

end_per_suite(_Config) ->
    ok.

init_per_testcase(_Name, Config) ->
    {ok, {AlicePub, _AlicePriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, {BobPub, BobPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    SS = rand:bytes(96),
    {ok, Alice} = libsignal_protocol_nif:dr_init(SS, AlicePub, BobPub, <<>>, 1),
    {ok, Bob} = libsignal_protocol_nif:dr_init(SS, BobPub, AlicePub, BobPriv, 0),
    [{alice, Alice}, {bob, Bob} | Config].

%% ============================================================================
%% Tests
%% ============================================================================

%% Send identical plaintexts back-to-back; the wire bytes must differ because
%% the encrypted header contains the (different) counter. Pre-DR-HE, the
%% counter was in cleartext and was the ONLY between-message difference, so
%% the bulk of the wire would have repeated. With DR-HE, two consecutive
%% messages share no enc_header bytes.
wire_hides_counter(Config) ->
    Alice0 = ?config(alice, Config),
    Plain = <<"identical">>,
    {ok, {CT0, Alice1}} = libsignal_protocol_nif:dr_encrypt(Alice0, Plain),
    {ok, {CT1, _Alice2}} = libsignal_protocol_nif:dr_encrypt(Alice1, Plain),
    %% Same length (PKCS#7 padding for the body is identical), but the
    %% enc_header portion must differ.
    ?assertEqual(byte_size(CT0), byte_size(CT1)),
    ?assertNotEqual(CT0, CT1),
    %% Stronger: the first ~60 wire bytes (version + outer protobuf prefix +
    %% enc_header) should disagree byte-for-byte. We just check at least a
    %% handful of byte positions in that range differ -- a deterministic
    %% AES-CBC output starts from the first block.
    %% Outer wire layout (worst case): version(1) + tag(1) + varint(1-2) +
    %% enc_header(>=16). Pull a 16-byte slice starting at byte 3.
    CT0Header = binary:part(CT0, 3, 16),
    CT1Header = binary:part(CT1, 3, 16),
    ?assertNotEqual(CT0Header, CT1Header).

%% Alice's DH ratchet public key (her dh_send_public) is embedded in every
%% message's inner header. Pre-DR-HE it appeared on the wire as a 32B
%% contiguous run. We can't read dh_send_public from the public NIF surface,
%% but we can construct an upper-bound test: send the same plaintext twice;
%% any 32B substring that appears in BOTH wires is by definition not part of
%% the per-message changing enc_header. Confirm no such common 32B run
%% exists except at MAC-position-irrelevant places. Concretely: the outer
%% protobuf framing (version + outer tags + the static-length varints) is
%% the only invariant region, which together is < 8 bytes.
wire_hides_ratchet_key(Config) ->
    Alice0 = ?config(alice, Config),
    Plain = <<"hide ratchet key">>,
    {ok, {CT0, Alice1}} = libsignal_protocol_nif:dr_encrypt(Alice0, Plain),
    {ok, {CT1, _Alice2}} = libsignal_protocol_nif:dr_encrypt(Alice1, Plain),
    Common = longest_common_substring(CT0, CT1),
    %% Pre-DR-HE the cleartext ratchet_key alone was a 32B common substring.
    %% With DR-HE the only structurally-invariant bytes between two
    %% consecutive messages are the outer protobuf framing tags +
    %% length varints -- well under 32 bytes.
    ?assert(byte_size(Common) < 32).

%% Flip one bit in the enc_header region. The wire still parses (it's just
%% bytes), the candidate header_keys still trial-decrypt (CBC produces some
%% output), but the resulting inner protobuf fails the parse / field-count
%% check and the message is rejected before any MAC computation runs.
tampered_envelope_rejected(Config) ->
    {Alice0, Bob0} = parties(Config),
    {ok, {CT, _A1}} = libsignal_protocol_nif:dr_encrypt(Alice0, <<"original">>),
    %% Outer protobuf starts at byte 1. Field 1 tag is 0x0A at byte 1,
    %% then a varint length, then the enc_header bytes. Tamper at byte ~5
    %% which is inside enc_header.
    Tampered = flip_bit(CT, 5),
    Result = libsignal_protocol_nif:dr_decrypt(Bob0, Tampered),
    ?assertMatch({error, _}, Result).

%% A session belonging to an unrelated pair cannot decrypt: every candidate
%% header_key (HKr, NHKr, MKSKIPPED entries) is unrelated, so trial-decrypt
%% rejects every option and the bad_mac error path fires.
wrong_session_cannot_decrypt(Config) ->
    Alice = ?config(alice, Config),
    {ok, {OtherPub, _OtherPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, {OtherBobPub, OtherBobPriv}} =
        libsignal_protocol_nif:generate_identity_key_pair(),
    OtherSS = rand:bytes(96),
    {ok, OtherBob} =
        libsignal_protocol_nif:dr_init(
          OtherSS, OtherBobPub, OtherPub, OtherBobPriv, 0),
    {ok, {CT, _A1}} = libsignal_protocol_nif:dr_encrypt(Alice, <<"oops">>),
    ?assertEqual({error, bad_mac},
                 libsignal_protocol_nif:dr_decrypt(OtherBob, CT)).

%% Truncating the outer envelope past the MAC region triggers a structural
%% reject before any cryptographic work happens.
malformed_outer_envelope_rejected(Config) ->
    Bob = ?config(bob, Config),
    %% Just the version byte + 8 zero MAC bytes -- no enc_header field.
    Bogus = <<16#33, 0:64>>,
    ?assertMatch({error, malformed_message},
                 libsignal_protocol_nif:dr_decrypt(Bob, Bogus)).

%% ============================================================================
%% Helpers
%% ============================================================================

parties(Config) ->
    {?config(alice, Config), ?config(bob, Config)}.

flip_bit(Bin, Pos) when Pos < byte_size(Bin) ->
    <<Pre:Pos/binary, Byte:8, Rest/binary>> = Bin,
    <<Pre/binary, (Byte bxor 1):8, Rest/binary>>.

%% Brute-force longest common substring between two binaries. Both inputs
%% are short (< 200B in this suite), so O(n*m) is fine.
longest_common_substring(A, B) ->
    ASize = byte_size(A),
    BSize = byte_size(B),
    longest_common_substring_loop(A, B, ASize, BSize, 0, 0, <<>>).

longest_common_substring_loop(_, _, ASize, _, I, _, Acc) when I >= ASize ->
    Acc;
longest_common_substring_loop(A, B, ASize, BSize, I, J, Acc) when J >= BSize ->
    longest_common_substring_loop(A, B, ASize, BSize, I + 1, 0, Acc);
longest_common_substring_loop(A, B, ASize, BSize, I, J, Acc) ->
    MaxLen = min(ASize - I, BSize - J),
    Len = match_prefix_len(A, I, B, J, MaxLen, 0),
    NewAcc =
        case Len > byte_size(Acc) of
            true -> binary:part(A, I, Len);
            false -> Acc
        end,
    longest_common_substring_loop(A, B, ASize, BSize, I, J + 1, NewAcc).

match_prefix_len(_, _, _, _, MaxLen, N) when N >= MaxLen -> N;
match_prefix_len(A, I, B, J, MaxLen, N) ->
    case binary:at(A, I + N) =:= binary:at(B, J + N) of
        true -> match_prefix_len(A, I, B, J, MaxLen, N + 1);
        false -> N
    end.
