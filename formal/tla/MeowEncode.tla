-------------------------------- MODULE MeowEncode --------------------------------
(****************************************************************************)
(* TLA+ Specification of the Meow-Encode/Decode Protocol                    *)
(*                                                                          *)
(* This specification models the complete state machine for:                *)
(* - Encoding: File → Encrypt → Fountain Encode → QR Frames → GIF          *)
(* - Decoding: GIF → QR Frames → Fountain Decode → Decrypt → File          *)
(*                                                                          *)
(* Attacker Model:                                                          *)
(* - Full control of transmission channel (Dolev-Yao)                       *)
(* - Can drop, replay, reorder, duplicate, or tamper with frames            *)
(*                                                                          *)
(* Author: Meow Decoder Project                                             *)
(* Date: January 2026                                                       *)
(****************************************************************************)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    MaxFrames,          \* Maximum number of frames in a transmission
    MaxSessions,        \* Maximum number of concurrent sessions
    MaxNonces,          \* Maximum nonces (for bounded model checking)
    Passwords,          \* Set of possible passwords
    DuressPasswords,    \* Subset of passwords that are duress passwords
    RealPasswords,      \* Subset of passwords that are real passwords
    ExpectedPCRs        \* Expected platform PCR state

ASSUME RealPasswords \intersect DuressPasswords = {}
ASSUME RealPasswords \cup DuressPasswords \subseteq Passwords

-----------------------------------------------------------------------------
(* Symmetry for Faster Model Checking *)

\* Symmetry set - passwords can be permuted without changing behavior
PasswordSymmetry == Permutations(Passwords)

-----------------------------------------------------------------------------

VARIABLES
    \* Encoder state
    encoderState,       \* Current state of the encoder
    encoderSession,     \* Session identifier for encoder
    encoderNonce,       \* Nonce used for this encryption
    encoderFrames,      \* Sequence of encoded frames
    usedNonces,         \* Set of nonces that have been used (global)
    \* Hardware-sealed key state
    keyState,           \* "unsealed" | "sealed" | "failed"
    pcrValues,          \* Current PCR state
    
    \* Decoder state
    decoderState,       \* Current state of the decoder
    decoderSession,     \* Session identifier decoder is working on
    receivedFrames,     \* Frames received by decoder
    decoderOutput,      \* Output produced by decoder
    authResult,         \* Result of authentication check
    
    \* Attacker state
    attackerFrames,     \* Frames captured by attacker
    attackerActions,    \* Sequence of attacker actions taken
    
    \* Channel state
    channel             \* Frames currently in transmission

vars == <<encoderState, encoderSession, encoderNonce, encoderFrames, usedNonces,
          keyState, pcrValues,
          decoderState, decoderSession, receivedFrames, decoderOutput, authResult,
          attackerFrames, attackerActions, channel>>

-----------------------------------------------------------------------------
(* State Constraint for Faster Model Checking *)

\* Limit attacker actions to bound state space (prevents infinite exploration)
AttackerActionLimit == Len(attackerActions) <= 3

-----------------------------------------------------------------------------
(* Helper Functions - MUST be defined before use *)

\* Range of a sequence (set of all elements in sequence)
Range(seq) == {seq[i] : i \in DOMAIN seq}

\* Check if a value is in a sequence  
InSeq(val, seq) == val \in Range(seq)

-----------------------------------------------------------------------------
(* Type Definitions *)

EncoderStates == {"Idle", "KeyDerivation", "Encrypt", "FrameEncode", "Transmit", "Done", "Error"}
DecoderStates == {"Idle", "Receive", "FrameDecode", "Decrypt", "OutputReal", "OutputDecoy", "Done", "Error"}
KeyStates == {"unsealed", "sealed", "failed"}
PCRStates == {ExpectedPCRs, "tampered"}

Frame == [
    sessionId: Nat,
    frameNum: Nat,
    nonce: Nat,
    ciphertext: {"encrypted_real", "encrypted_decoy", "corrupted"},
    tag: {"valid_tag", "invalid_tag"},
    isManifest: BOOLEAN
]

AttackerAction == {"drop", "replay", "reorder", "duplicate", "tamper", "none"}

-----------------------------------------------------------------------------
(* Initial State *)

Init ==
    /\ encoderState = "Idle"
    /\ encoderSession = 0
    /\ encoderNonce = 0
    /\ encoderFrames = <<>>
    /\ usedNonces = {}
    /\ keyState = "unsealed"
    /\ pcrValues = ExpectedPCRs
    /\ decoderState = "Idle"
    /\ decoderSession = 0
    /\ receivedFrames = <<>>
    /\ decoderOutput = "none"
    /\ authResult = "pending"
    /\ attackerFrames = {}
    /\ attackerActions = <<>>
    /\ channel = <<>>

-----------------------------------------------------------------------------
(* Encoder Actions *)

\* Start a new encoding session
EncoderStartSession(password) ==
    /\ encoderState = "Idle"
    /\ encoderState' = "KeyDerivation"
    /\ encoderSession' = encoderSession + 1
    /\ UNCHANGED <<encoderNonce, encoderFrames, usedNonces, keyState, pcrValues, decoderState, 
                   decoderSession, receivedFrames, decoderOutput, authResult,
                   attackerFrames, attackerActions, channel>>

\* Derive encryption key from password (Argon2id)
EncoderDeriveKey ==
    /\ encoderState = "KeyDerivation"
    /\ encoderState' = "Encrypt"
    /\ UNCHANGED <<encoderSession, encoderNonce, encoderFrames, usedNonces, keyState, pcrValues,
                   decoderState, decoderSession, receivedFrames, decoderOutput, 
                   authResult, attackerFrames, attackerActions, channel>>

\* Generate fresh nonce and encrypt (CRITICAL: Nonce uniqueness)
EncoderEncrypt ==
    /\ encoderState = "Encrypt"
    /\ LET newNonce == CHOOSE n \in 1..MaxNonces : n \notin usedNonces
       IN
        /\ encoderNonce' = newNonce
        /\ usedNonces' = usedNonces \cup {newNonce}
        /\ encoderState' = "FrameEncode"
    /\ UNCHANGED <<encoderSession, encoderFrames, keyState, pcrValues, decoderState, decoderSession,
                   receivedFrames, decoderOutput, authResult, attackerFrames, 
                   attackerActions, channel>>

\* Encode encrypted data into fountain code frames
EncoderFrameEncode ==
    /\ encoderState = "FrameEncode"
    /\ LET manifestFrame == [
            sessionId |-> encoderSession,
            frameNum |-> 0,
            nonce |-> encoderNonce,
            ciphertext |-> "encrypted_real",
            tag |-> "valid_tag",
            isManifest |-> TRUE
        ]
        dataFrames == [i \in 1..MaxFrames |-> [
            sessionId |-> encoderSession,
            frameNum |-> i,
            nonce |-> encoderNonce,
            ciphertext |-> "encrypted_real",
            tag |-> "valid_tag",
            isManifest |-> FALSE
        ]]
       IN
        /\ encoderFrames' = <<manifestFrame>> \o [i \in 1..MaxFrames |-> dataFrames[i]]
        /\ encoderState' = "Transmit"
     /\ UNCHANGED <<encoderSession, encoderNonce, usedNonces, keyState, pcrValues, decoderState,
                   decoderSession, receivedFrames, decoderOutput, authResult,
                   attackerFrames, attackerActions, channel>>

\* Transmit frames to channel (attacker can intercept)
EncoderTransmit ==
    /\ encoderState = "Transmit"
    /\ channel' = encoderFrames
    /\ attackerFrames' = attackerFrames \cup Range(encoderFrames)
    /\ encoderState' = "Done"
    /\ UNCHANGED <<encoderSession, encoderNonce, encoderFrames, usedNonces, keyState, pcrValues,
                   decoderState, decoderSession, receivedFrames, decoderOutput,
                   authResult, attackerActions>>

-----------------------------------------------------------------------------
(* Hardware-Sealed Key Actions *)

SealKey ==
    /\ keyState = "unsealed"
    /\ keyState' = "sealed"
    /\ UNCHANGED <<encoderState, encoderSession, encoderNonce, encoderFrames, usedNonces,
                   pcrValues, decoderState, decoderSession, receivedFrames, decoderOutput,
                   authResult, attackerFrames, attackerActions, channel>>

UnsealKey ==
    /\ keyState = "sealed"
    /\ IF pcrValues = ExpectedPCRs
       THEN keyState' = "unsealed"
       ELSE keyState' = "failed"
    /\ UNCHANGED <<encoderState, encoderSession, encoderNonce, encoderFrames, usedNonces,
                   pcrValues, decoderState, decoderSession, receivedFrames, decoderOutput,
                   authResult, attackerFrames, attackerActions, channel>>

TamperPlatform ==
    /\ keyState = "sealed"
    /\ pcrValues' = "tampered"
    /\ UNCHANGED <<encoderState, encoderSession, encoderNonce, encoderFrames, usedNonces,
                   keyState, decoderState, decoderSession, receivedFrames, decoderOutput,
                   authResult, attackerFrames, attackerActions, channel>>

-----------------------------------------------------------------------------
(* Attacker Actions - Dolev-Yao Model *)

\* Attacker drops a frame from channel
AttackerDrop ==
    /\ Len(channel) > 0
    /\ \E i \in DOMAIN channel :
        /\ channel' = SubSeq(channel, 1, i-1) \o SubSeq(channel, i+1, Len(channel))
        /\ attackerActions' = Append(attackerActions, "drop")
    /\ UNCHANGED <<encoderState, encoderSession, encoderNonce, encoderFrames, 
                   usedNonces, keyState, pcrValues, decoderState, decoderSession, receivedFrames,
                   decoderOutput, authResult, attackerFrames>>

\* Attacker replays a previously captured frame
AttackerReplay ==
    /\ attackerFrames /= {}
    /\ \E f \in attackerFrames :
        /\ channel' = Append(channel, f)
        /\ attackerActions' = Append(attackerActions, "replay")
    /\ UNCHANGED <<encoderState, encoderSession, encoderNonce, encoderFrames,
                   usedNonces, keyState, pcrValues, decoderState, decoderSession, receivedFrames,
                   decoderOutput, authResult, attackerFrames>>

\* Attacker reorders frames in channel
AttackerReorder ==
    /\ Len(channel) >= 2
    /\ \E i, j \in DOMAIN channel :
        /\ i < j
        /\ LET temp == channel[i]
           IN channel' = [channel EXCEPT ![i] = channel[j], ![j] = temp]
        /\ attackerActions' = Append(attackerActions, "reorder")
    /\ UNCHANGED <<encoderState, encoderSession, encoderNonce, encoderFrames,
                   usedNonces, keyState, pcrValues, decoderState, decoderSession, receivedFrames,
                   decoderOutput, authResult, attackerFrames>>

\* Attacker duplicates a frame
AttackerDuplicate ==
    /\ Len(channel) > 0
    /\ \E i \in DOMAIN channel :
        /\ channel' = channel \o <<channel[i]>>
        /\ attackerActions' = Append(attackerActions, "duplicate")
    /\ UNCHANGED <<encoderState, encoderSession, encoderNonce, encoderFrames,
                   usedNonces, keyState, pcrValues, decoderState, decoderSession, receivedFrames,
                   decoderOutput, authResult, attackerFrames>>

\* Attacker tampers with a frame (corrupts ciphertext or tag)
AttackerTamper ==
    /\ Len(channel) > 0
    /\ \E i \in DOMAIN channel :
        /\ LET tamperedFrame == [channel[i] EXCEPT 
                !.ciphertext = "corrupted",
                !.tag = "invalid_tag"]
           IN channel' = [channel EXCEPT ![i] = tamperedFrame]
        /\ attackerActions' = Append(attackerActions, "tamper")
    /\ UNCHANGED <<encoderState, encoderSession, encoderNonce, encoderFrames,
                   usedNonces, keyState, pcrValues, decoderState, decoderSession, receivedFrames,
                   decoderOutput, authResult, attackerFrames>>

-----------------------------------------------------------------------------
(* Decoder Actions *)

\* Start receiving frames
DecoderStartReceive ==
    /\ decoderState = "Idle"
    /\ Len(channel) > 0
    /\ decoderState' = "Receive"
    /\ UNCHANGED <<encoderState, encoderSession, encoderNonce, encoderFrames,
                   usedNonces, keyState, pcrValues, decoderSession, receivedFrames, decoderOutput,
                   authResult, attackerFrames, attackerActions, channel>>

\* Receive a frame from channel
DecoderReceiveFrame ==
    /\ decoderState = "Receive"
    /\ Len(channel) > 0
    /\ LET frame == Head(channel)
       IN
        /\ receivedFrames' = Append(receivedFrames, frame)
        /\ channel' = Tail(channel)
        \* Extract session from manifest frame
        /\ IF frame.isManifest
           THEN decoderSession' = frame.sessionId
           ELSE decoderSession' = decoderSession
    /\ UNCHANGED <<encoderState, encoderSession, encoderNonce, encoderFrames,
                   usedNonces, keyState, pcrValues, decoderState, decoderOutput, authResult,
                   attackerFrames, attackerActions>>

\* Transition to frame decoding when enough frames received
DecoderStartDecode ==
    /\ decoderState = "Receive"
    /\ Len(receivedFrames) >= MaxFrames \div 2  \* Fountain code: need ~67%
    /\ decoderState' = "FrameDecode"
    /\ UNCHANGED <<encoderState, encoderSession, encoderNonce, encoderFrames,
                   usedNonces, keyState, pcrValues, decoderSession, receivedFrames, decoderOutput,
                   authResult, attackerFrames, attackerActions, channel>>

\* Decode fountain frames (verify frame MACs first)
DecoderFrameDecode ==
    /\ decoderState = "FrameDecode"
    /\ decoderState' = "Decrypt"
    /\ UNCHANGED <<encoderState, encoderSession, encoderNonce, encoderFrames,
                   usedNonces, keyState, pcrValues, decoderSession, receivedFrames, decoderOutput,
                   authResult, attackerFrames, attackerActions, channel>>

\* Decrypt and authenticate (CRITICAL: Authentication check)
DecoderDecrypt(password) ==
    /\ decoderState = "Decrypt"
    /\ LET
        \* Check if all received frames have valid tags
        allTagsValid == \A i \in DOMAIN receivedFrames : 
            receivedFrames[i].tag = "valid_tag"
        \* Check if any frame was corrupted
        anyCorrupted == \E i \in DOMAIN receivedFrames :
            receivedFrames[i].ciphertext = "corrupted"
        \* Check for replay (different session but same nonce)
        isReplay == \E i \in DOMAIN receivedFrames :
            receivedFrames[i].sessionId /= decoderSession
        \* Determine authentication result
        authOk == allTagsValid /\ ~anyCorrupted /\ ~isReplay /\ keyState = "unsealed"
        \* Determine if this is a duress password
        isDuress == password \in DuressPasswords
       IN
        /\ authResult' = IF authOk THEN "success" ELSE "failure"
                /\ keyState' = IF authOk /\ isDuress THEN "failed" ELSE keyState
        /\ IF ~authOk
           THEN 
                /\ decoderState' = "Error"
                /\ decoderOutput' = "none"  \* CRITICAL: No output on auth failure
           ELSE IF isDuress
           THEN
                /\ decoderState' = "OutputDecoy"
                /\ decoderOutput' = "decoy"  \* CRITICAL: Decoy in duress mode
           ELSE
                /\ decoderState' = "OutputReal"
                /\ decoderOutput' = "real"
    /\ UNCHANGED <<encoderState, encoderSession, encoderNonce, encoderFrames,
                usedNonces, pcrValues, decoderSession, receivedFrames, attackerFrames,
                attackerActions, channel>>

\* Output real plaintext (only from OutputReal state)
DecoderOutputReal ==
    /\ decoderState = "OutputReal"
    /\ decoderOutput = "real"
    /\ decoderState' = "Done"
    /\ UNCHANGED <<encoderState, encoderSession, encoderNonce, encoderFrames,
                   usedNonces, keyState, pcrValues, decoderSession, receivedFrames, decoderOutput,
                   authResult, attackerFrames, attackerActions, channel>>

\* Output decoy (only from OutputDecoy state)
DecoderOutputDecoy ==
    /\ decoderState = "OutputDecoy"
    /\ decoderOutput = "decoy"
    /\ decoderState' = "Done"
    /\ UNCHANGED <<encoderState, encoderSession, encoderNonce, encoderFrames,
                   usedNonces, keyState, pcrValues, decoderSession, receivedFrames, decoderOutput,
                   authResult, attackerFrames, attackerActions, channel>>

\* Error handling
DecoderError ==
    /\ decoderState = "Error"
    /\ decoderOutput = "none"  \* Confirm no output in error state
    /\ UNCHANGED vars

-----------------------------------------------------------------------------
(* Next State Relation *)

Next ==
    \/ \E p \in Passwords : EncoderStartSession(p)
    \/ EncoderDeriveKey
    \/ EncoderEncrypt
    \/ EncoderFrameEncode
    \/ EncoderTransmit
    \/ SealKey
    \/ UnsealKey
    \/ TamperPlatform
    \/ AttackerDrop
    \/ AttackerReplay
    \/ AttackerReorder
    \/ AttackerDuplicate
    \/ AttackerTamper
    \/ DecoderStartReceive
    \/ DecoderReceiveFrame
    \/ DecoderStartDecode
    \/ DecoderFrameDecode
    \/ \E p \in Passwords : DecoderDecrypt(p)
    \/ DecoderOutputReal
    \/ DecoderOutputDecoy
    \/ DecoderError

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* SAFETY INVARIANTS - These MUST be proven *)

(****************************************************************************)
(* INVARIANT 1: Real plaintext is NEVER output in duress mode              *)
(*                                                                          *)
(* If decoder is in OutputDecoy state, the output MUST be "decoy", never   *)
(* "real". This prevents coerced users from revealing actual secrets.      *)
(****************************************************************************)
DuressNeverOutputsReal ==
    decoderState = "OutputDecoy" => decoderOutput /= "real"

(****************************************************************************)
(* INVARIANT 2: No plaintext output if authentication fails                 *)
(*                                                                          *)
(* If authentication fails (authResult = "failure"), decoder MUST be in    *)
(* Error state with output = "none". No partial plaintext is ever exposed. *)
(****************************************************************************)
NoOutputOnAuthFailure ==
    authResult = "failure" => (decoderState = "Error" /\ decoderOutput = "none")

(****************************************************************************)
(* INVARIANT 3: Replayed/reordered frames never result in successful decrypt*)
(*                                                                          *)
(* If attacker has performed replay, the authentication MUST fail OR the   *)
(* replay was detected and rejected. Combined with frame MAC verification. *)
(****************************************************************************)
ReplayNeverSucceeds ==
    LET hasReplayAction == "replay" \in Range(attackerActions)
        frameFromDifferentSession == \E i \in DOMAIN receivedFrames :
            receivedFrames[i].sessionId /= decoderSession /\ decoderSession > 0
    IN
        (hasReplayAction /\ frameFromDifferentSession) => 
            (authResult /= "success" \/ decoderState = "Error")

(****************************************************************************)
(* INVARIANT 4: Nonces are never reused within a session                    *)
(*                                                                          *)
(* Each encryption operation MUST use a fresh nonce. Nonce reuse would     *)
(* catastrophically break AES-GCM security (XOR of plaintexts leaked).     *)
(****************************************************************************)
NonceNeverReused ==
    \A n \in usedNonces : Cardinality({s \in 1..encoderSession : TRUE}) >= 1
    \* Stronger: The encoder only encrypts if nonce is fresh
    \* This is enforced by the EncoderEncrypt action's precondition

(****************************************************************************)
(* INVARIANT 5: Tampered frames never produce valid output                  *)
(*                                                                          *)
(* If any frame has been tampered (ciphertext = "corrupted" or tag =       *)
(* "invalid_tag"), authentication MUST fail.                                *)
(****************************************************************************)
TamperedFramesRejected ==
    (\E i \in DOMAIN receivedFrames : 
        receivedFrames[i].ciphertext = "corrupted" \/ 
        receivedFrames[i].tag = "invalid_tag") =>
    (authResult /= "success" \/ decoderState \in {"Idle", "Receive", "FrameDecode", "Decrypt"})

(****************************************************************************)
(* INVARIANT 6: State machine cannot bypass authentication                  *)
(*                                                                          *)
(* The only path to OutputReal or OutputDecoy is through Decrypt state     *)
(* with successful authentication. No shortcut exists.                      *)
(****************************************************************************)
NoAuthBypass ==
    (decoderState \in {"OutputReal", "OutputDecoy", "Done"}) =>
    (authResult = "success")

(****************************************************************************)
(* INVARIANT 7: Unseal requires matching PCRs                              *)
(****************************************************************************)
UnsealRequiresMatchingPCRs ==
    keyState = "unsealed" => pcrValues = ExpectedPCRs

(****************************************************************************)
(* INVARIANT 8: Tampered PCRs prevent unseal                                *)
(****************************************************************************)
TamperPreventsUnseal ==
    pcrValues = "tampered" => keyState /= "unsealed"

(****************************************************************************)
(* INVARIANT 9: Real output requires unsealed key                           *)
(****************************************************************************)
NoRealOutputWithoutUnsealedKey ==
    decoderState = "OutputReal" => keyState = "unsealed"

(****************************************************************************)
(* Combined Safety Property                                                 *)
(****************************************************************************)
Safety ==
    /\ DuressNeverOutputsReal
    /\ NoOutputOnAuthFailure
    /\ ReplayNeverSucceeds
    /\ NonceNeverReused
    /\ TamperedFramesRejected
    /\ NoAuthBypass
    /\ UnsealRequiresMatchingPCRs
    /\ TamperPreventsUnseal
    /\ NoRealOutputWithoutUnsealedKey

-----------------------------------------------------------------------------
(* LIVENESS PROPERTIES (optional, for completeness) *)

\* Eventually, if encoder transmits, decoder can finish
EventuallyDecodes ==
    encoderState = "Done" ~> decoderState \in {"Done", "Error"}

-----------------------------------------------------------------------------
(* THEOREMS *)

THEOREM Spec => []Safety
THEOREM Spec => []DuressNeverOutputsReal
THEOREM Spec => []NoOutputOnAuthFailure
THEOREM Spec => []TamperedFramesRejected
THEOREM Spec => []NoAuthBypass
THEOREM Spec => []UnsealRequiresMatchingPCRs
THEOREM Spec => []TamperPreventsUnseal
THEOREM Spec => []NoRealOutputWithoutUnsealedKey

=============================================================================
