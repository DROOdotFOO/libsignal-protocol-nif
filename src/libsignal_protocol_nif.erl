-module(libsignal_protocol_nif).

-export([init/0, generate_identity_key_pair/0, generate_pre_key/1,
         generate_signed_pre_key/2, process_pre_key_bundle/2,
         process_pre_key_bundle_bob/5, dr_init/5,
         dr_encrypt/2, dr_encrypt_prekey/3, dr_decrypt/2, pksm_decode/1]).

-on_load load_nif/0.

%% See libsignal_nif_loader for the path-resolution strategy. The fun must
%% live in this module so erlang:load_nif/2 attaches the library here.
-spec load_nif() -> ok | {error, term()}.
load_nif() ->
    libsignal_nif_loader:load(?MODULE, fun(Path) -> erlang:load_nif(Path, 0) end).

%% NIF function stubs (replaced by C implementations when NIF loads).
%% If load_nif/0 fails, the module itself fails to load (see -on_load).
%% These bodies only fire if a caller reaches them through a dev hot-reload
%% without the NIF attached -- never in a production load path.

-spec init() -> ok.
init() ->
    erlang:nif_error(nif_not_loaded).

-spec generate_identity_key_pair() ->
                                    {ok, {Ed25519Pub :: binary(), Ed25519Priv :: binary()}} |
                                    {error, atom()}.
generate_identity_key_pair() ->
    erlang:nif_error(nif_not_loaded).

%% Both generators return the private half: Bob must keep it to run
%% process_pre_key_bundle_bob/5 against the bundle he published.
-spec generate_pre_key(KeyId :: non_neg_integer()) ->
                          {ok,
                           {non_neg_integer(), X25519Pub :: binary(), X25519Priv :: binary()}} |
                          {error, atom()}.
generate_pre_key(_KeyId) ->
    erlang:nif_error(nif_not_loaded).

-spec generate_signed_pre_key(IdentityPriv :: binary(), KeyId :: non_neg_integer()) ->
                                 {ok,
                                  {non_neg_integer(),
                                   SpkPub :: binary(),
                                   SpkPriv :: binary(),
                                   Signature :: binary()}} |
                                 {error, atom()}.
generate_signed_pre_key(_IdentityKey, _KeyId) ->
    erlang:nif_error(nif_not_loaded).

-spec process_pre_key_bundle(LocalIdentityPriv :: binary(), Bundle :: binary()) ->
                                {ok, {SharedSecret :: binary(), EphemeralPub :: binary()}} |
                                {error, atom()}.
process_pre_key_bundle(_LocalIdentityKey, _Bundle) ->
    erlang:nif_error(nif_not_loaded).

%% Bob-side X3DH. Inputs are Bob's private material plus the two pubs Alice
%% sends with her first message (her identity pub and her ephemeral pub).
%% IdentityPriv: 64B Ed25519 secret (Bob's identity).
%% SignedPreKeyPriv: 32B X25519 secret (the SPK Alice consumed from his bundle).
%% OneTimePreKeyPriv: 32B X25519 secret or <<>> if no OPK was used.
%% RemoteIdentityPub: 32B Ed25519 (Alice's identity pub).
%% RemoteEphemeralPub: 32B X25519 (Alice's ephemeral, returned by her
%%   process_pre_key_bundle/2). Returns {ok, SharedSecret} with the same 96B
%%   secret Alice derived (64B X3DH SK || 32B shared header-key seed for DR-HE).
-spec process_pre_key_bundle_bob(IdentityPriv :: binary(),
                                 SignedPreKeyPriv :: binary(),
                                 OneTimePreKeyPriv :: binary(),
                                 RemoteIdentityPub :: binary(),
                                 RemoteEphemeralPub :: binary()) ->
                                    {ok, SharedSecret :: binary()} | {error, atom()}.
process_pre_key_bundle_bob(_IdentityPriv,
                           _SignedPreKeyPriv,
                           _OneTimePreKeyPriv,
                           _RemoteIdentityPub,
                           _RemoteEphemeralPub) ->
    erlang:nif_error(nif_not_loaded).

% Double Ratchet functions.
% LocalIdentityPub and RemoteIdentityPub are Ed25519 identity public keys
% (32B each). At init they are converted to X25519 form via
% crypto_sign_ed25519_pk_to_curve25519 and the X25519 form is what gets folded
% into every MAC -- Signal-spec scope:
%   sender_x25519_id || receiver_x25519_id || version || serialized_message
% Callers pass Ed25519 form to keep the public API aligned with how we hand out
% identity keys elsewhere (generate_identity_key_pair returns Ed25519).
% For Alice: SelfIdentityPriv may be <<>> (she uses a fresh ephemeral for DH);
%   RemoteIdentityPub is Bob's Ed25519 identity public key.
% For Bob:   SelfIdentityPriv is his 64B Ed25519 identity private key,
%   converted to X25519 internally for the initial DH ratchet pair. Bob's
%   encrypt fails until he receives Alice's first message.
-spec dr_init(SharedSecret :: binary(),
              LocalIdentityPub :: binary(),
              RemoteIdentityPub :: binary(),
              SelfIdentityPriv :: binary(),
              IsAlice :: 0 | 1) ->
                 {ok, DrSession :: binary()} | {error, atom()}.
dr_init(_SharedSecret,
        _LocalIdentityPub,
        _RemoteIdentityPub,
        _SelfIdentityPriv,
        _IsAlice) ->
    erlang:nif_error(nif_not_loaded).

-spec dr_encrypt(DrSession :: binary(), Message :: binary()) ->
                    {ok, {Ciphertext :: binary(), NewSession :: binary()}} | {error, atom()}.
dr_encrypt(_DrSession, _Message) ->
    erlang:nif_error(nif_not_loaded).

%% Encrypt Alice's first message and wrap it in a PreKeySignalMessage envelope
%% so Bob can recover the X3DH SK before decrypting the inner SignalMessage.
%% PreKeyInfo = {RegistrationId, OneTimePreKeyId | undefined, SignedPreKeyId,
%%               AliceX3dhEphemeralPub}. AliceX3dhEphemeralPub is the 32B X25519
%% pub returned by process_pre_key_bundle/2.
%% Returns {ok, {PksmWireBytes, NewSession}} | {error, Atom}.
-spec dr_encrypt_prekey(DrSession :: binary(),
                        Message :: binary(),
                        PreKeyInfo ::
                            {RegistrationId :: non_neg_integer(),
                             OneTimePreKeyId :: non_neg_integer() | undefined,
                             SignedPreKeyId :: non_neg_integer(),
                             AliceEphemeralPub :: binary()}) ->
                           {ok, {PksmWire :: binary(), NewSession :: binary()}} | {error, atom()}.
dr_encrypt_prekey(_DrSession, _Message, _PreKeyInfo) ->
    erlang:nif_error(nif_not_loaded).

-spec dr_decrypt(DrSession :: binary(), Encrypted :: binary()) ->
                    {ok, {Plaintext :: binary(), NewSession :: binary()}} | {error, atom()}.
dr_decrypt(_DrSession, _EncryptedMessage) ->
    erlang:nif_error(nif_not_loaded).

%% Decode a PreKeySignalMessage wire envelope. Pure parse -- Bob's side then
%% looks up his SPK/OPK by id, runs process_pre_key_bundle_bob/5 to derive SK,
%% calls dr_init/5, and decrypts the InnerMessage with dr_decrypt/2.
%% Returns
%%   {ok, {RegistrationId, BaseKey, IdentityKey, OneTimePreKeyId | undefined,
%%         SignedPreKeyId, InnerMessage}}
%% | {error, malformed_message}.
-spec pksm_decode(Wire :: binary()) ->
                     {ok,
                      {RegistrationId :: non_neg_integer(),
                       BaseKey :: binary(),
                       IdentityKey :: binary(),
                       OneTimePreKeyId :: non_neg_integer() | undefined,
                       SignedPreKeyId :: non_neg_integer(),
                       InnerMessage :: binary()}} |
                     {error, atom()}.
pksm_decode(_Wire) ->
    erlang:nif_error(nif_not_loaded).
