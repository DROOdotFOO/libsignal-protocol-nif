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
-export([wire_hides_counter/1, wire_hides_ratchet_key/1, tampered_envelope_rejected/1,
         reflected_message_rejected/1, wrong_session_cannot_decrypt/1,
         malformed_outer_envelope_rejected/1, wrong_size_enc_header_rejected/1,
         forged_header_of_correct_length_rejected/1]).

%% iv(16) || AES-CBC(48) || tag(16); mirrors DR_ENC_HEADER_LEN in dr_crypto.h.
-define(ENC_HEADER_LEN, 80).
%% Mirrors MAX_SKIP in dr.h.
-define(MAX_SKIP, 32).

all() ->
    [wire_hides_counter,
     wire_hides_ratchet_key,
     tampered_envelope_rejected,
     reflected_message_rejected,
     wrong_session_cannot_decrypt,
     malformed_outer_envelope_rejected,
     wrong_size_enc_header_rejected,
     forged_header_of_correct_length_rejected].

init_per_suite(Config) ->
    dr_test_helpers:nif_or_skip(Config, {2, 3, 5}).

end_per_suite(_Config) ->
    ok.

init_per_testcase(_Name, Config) ->
    dr_test_helpers:fresh_dr_parties_to_config(Config).

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

%% Flip every bit of the 80-byte enc_header in turn. The header carries its
%% own 16-byte HMAC tag, so every flip -- IV, ciphertext, or tag -- must fail
%% the tag check under each candidate header key and surface as bad_mac.
%% Nothing else is acceptable: too_many_skipped or dh_ratchet_failed would
%% mean an unauthenticated header reached the ratchet, and any crash means
%% the CBC path ran on forged bytes.
tampered_envelope_rejected(Config) ->
    {Alice0, Bob0} = parties(Config),
    {ok, {CT, _A1}} = libsignal_protocol_nif:dr_encrypt(Alice0, <<"original">>),
    %% Wire: 0x33, 0x0A, varint(80) = <<80>>, then the 80 header bytes.
    <<16#33, 16#0A, ?ENC_HEADER_LEN, _/binary>> = CT,
    HeaderStart = 3,
    Outcomes =
        lists:usort([libsignal_protocol_nif:dr_decrypt(Bob0, flip_bit(CT, Pos, Bit))
                     || Pos <- lists:seq(HeaderStart, HeaderStart + ?ENC_HEADER_LEN - 1),
                        Bit <- lists:seq(0, 7)]),
    ?assertEqual([{error, bad_mac}], Outcomes).

%% A message must never authenticate under its own sender's receive keys.
%% Header keys are seeded per direction from distinct halves of the X3DH
%% output, so reflecting Alice's wire back to Alice finds no candidate header
%% key and stops at bad_mac. Pre-fix both directions shared one seed: the
%% header opened under Alice's next_header_key_recv, the receiver ran the DH
%% ratchet and then tried to skip N=MAX_SKIP+1 keys, surfacing
%% too_many_skipped -- unauthenticated work driven by a reflected message.
reflected_message_rejected(Config) ->
    Alice0 = ?config(alice, Config),
    {AliceN, CT} =
        lists:foldl(fun(_, {A, _}) ->
                       {ok, {C, A1}} = libsignal_protocol_nif:dr_encrypt(A, <<"x">>),
                       {A1, C}
                    end,
                    {Alice0, <<>>},
                    lists:seq(1, ?MAX_SKIP + 2)),
    ?assertEqual({error, bad_mac}, libsignal_protocol_nif:dr_decrypt(AliceN, CT)).

%% A session belonging to an unrelated pair cannot decrypt: every candidate
%% header_key (HKr, NHKr, MKSKIPPED entries) is unrelated, so trial-decrypt
%% rejects every option and the bad_mac error path fires.
wrong_session_cannot_decrypt(Config) ->
    Alice = ?config(alice, Config),
    {ok, {OtherPub, _OtherPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, {OtherBobPub, OtherBobPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
    OtherSS = rand:bytes(96),
    {ok, OtherBob} =
        libsignal_protocol_nif:dr_init(OtherSS, OtherBobPub, OtherPub, OtherBobPriv, 0),
    {ok, {CT, _A1}} = libsignal_protocol_nif:dr_encrypt(Alice, <<"oops">>),
    ?assertEqual({error, bad_mac}, libsignal_protocol_nif:dr_decrypt(OtherBob, CT)).

%% Truncating the outer envelope past the MAC region triggers a structural
%% reject before any cryptographic work happens.
malformed_outer_envelope_rejected(Config) ->
    Bob = ?config(bob, Config),
    %% Just the version byte + 8 zero MAC bytes -- no enc_header field.
    Bogus = <<16#33, 0:64>>,
    ?assertMatch({error, malformed_message}, libsignal_protocol_nif:dr_decrypt(Bob, Bogus)).

%% A legitimate enc_header is always iv(16) || AES-CBC(48) || tag(16) = 80B.
%% The receiver trial-opens enc_header into a fixed-size stack buffer
%% *before* the outer MAC is checked, so any other length must be rejected
%% structurally -- including the 0.2 size (64), block-aligned sizes the
%% original `>= 32 && % 16 == 0` check let through (48, 96, ...) and sizes
%% it rejected for the wrong reason (0, 16, 47, 79, 81). The 4 KB case
%% smashed the NIF stack before the pin existed.
wrong_size_enc_header_rejected(Config) ->
    Bob = ?config(bob, Config),
    lists:foreach(fun(HeaderLen) ->
                     Wire = forged_wire(HeaderLen),
                     ?assertEqual({error, malformed_message},
                                  libsignal_protocol_nif:dr_decrypt(Bob, Wire),
                                  {enc_header_len, HeaderLen})
                  end,
                  [0, 16, 47, 48, 63, 64, 65, 79, 81, 96, 112, 16 + 4096, 16 + 65536]).

%% The right length with random contents must fail the header tag, not
%% reach the cipher: bad_mac, never malformed_message or too_many_skipped.
forged_header_of_correct_length_rejected(Config) ->
    Bob = ?config(bob, Config),
    ?assertEqual({error, bad_mac},
                 libsignal_protocol_nif:dr_decrypt(Bob, forged_wire(?ENC_HEADER_LEN))).

%% ============================================================================
%% Helpers
%% ============================================================================

parties(Config) ->
    {?config(alice, Config), ?config(bob, Config)}.

flip_bit(Bin, Pos, Bit) when Pos < byte_size(Bin), Bit >= 0, Bit < 8 ->
    <<Pre:Pos/binary, Byte:8, Rest/binary>> = Bin,
    <<Pre/binary, (Byte bxor (1 bsl Bit)):8, Rest/binary>>.

%% version(1) || protobuf{1: enc_header, 2: ciphertext} || mac(8) with an
%% arbitrary enc_header length and a minimal 16B body ciphertext.
forged_wire(HeaderLen) ->
    Header = rand:bytes(HeaderLen),
    Body = rand:bytes(16),
    <<16#33,
      16#0A,
      (varint(HeaderLen))/binary,
      Header/binary,
      16#12,
      (varint(16))/binary,
      Body/binary,
      0:64>>.

varint(N) when N < 16#80 ->
    <<N>>;
varint(N) ->
    <<(16#80 bor N band 16#7F), (varint(N bsr 7))/binary>>.

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
            true ->
                binary:part(A, I, Len);
            false ->
                Acc
        end,
    longest_common_substring_loop(A, B, ASize, BSize, I, J + 1, NewAcc).

match_prefix_len(_, _, _, _, MaxLen, N) when N >= MaxLen ->
    N;
match_prefix_len(A, I, B, J, MaxLen, N) ->
    case binary:at(A, I + N) =:= binary:at(B, J + N) of
        true ->
            match_prefix_len(A, I, B, J, MaxLen, N + 1);
        false ->
            N
    end.
