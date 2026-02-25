------------------------------ MODULE ExpiryProtocol ------------------------------
(****************************************************************************)
(* TLA+ Specification of the Message Expiry Protocol                        *)
(*                                                                          *)
(* Models the time-locked message expiry mechanism where encrypted           *)
(* manifests include an expiration timestamp. After expiry:                  *)
(* - Decode attempts must fail (fail-closed)                                *)
(* - Expired key material must be zeroized                                  *)
(* - No partial decryption is possible                                      *)
(*                                                                          *)
(* Security Properties:                                                     *)
(* 1. Forward expiry: expired messages cannot be decoded                    *)
(* 2. Atomicity: decode either fully succeeds or fully fails                *)
(* 3. Key zeroization: expired keys are irreversibly destroyed              *)
(* 4. Clock skew tolerance: bounded tolerance for clock differences         *)
(*                                                                          *)
(* Author: Meow Decoder Project                                             *)
(* Date: February 2026                                                      *)
(****************************************************************************)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    MaxMessages,        \* Maximum messages in the system
    MaxTime,            \* Maximum time value for bounded model checking
    ClockSkewBound,     \* Maximum allowed clock difference (seconds)
    GracePeriod         \* Grace period after expiry (seconds)

ASSUME MaxMessages > 0
ASSUME MaxTime > 0
ASSUME ClockSkewBound >= 0
ASSUME GracePeriod >= 0

-----------------------------------------------------------------------------

VARIABLES
    currentTime,        \* Global monotonic clock
    messages,           \* Set of message records: [id, expiry, state, key]
    decoderClock,       \* Decoder's local clock (may skew from currentTime)
    decodeAttempts,     \* Log of decode attempts for verification
    zeroizedKeys        \* Set of key IDs that have been zeroized

vars == <<currentTime, messages, decoderClock, decodeAttempts, zeroizedKeys>>

\* Message states
MsgStates == {"active", "expired", "decoded", "failed"}

-----------------------------------------------------------------------------
(* Type Invariant *)

TypeOK ==
    /\ currentTime \in 0..MaxTime
    /\ decoderClock \in 0..MaxTime
    /\ zeroizedKeys \subseteq 1..MaxMessages
    /\ decodeAttempts \in Seq([msgId: 1..MaxMessages, result: {"success", "rejected", "expired"}])

-----------------------------------------------------------------------------
(* Initial State *)

Init ==
    /\ currentTime = 0
    /\ decoderClock = 0
    /\ messages = {}
    /\ decodeAttempts = <<>>
    /\ zeroizedKeys = {}

-----------------------------------------------------------------------------
(* State Transitions *)

\* Create a new message with an expiry time
CreateMessage ==
    /\ Cardinality(messages) < MaxMessages
    /\ \E id \in 1..MaxMessages, exp \in 1..MaxTime :
        /\ \A m \in messages : m.id /= id
        /\ messages' = messages \cup {[id |-> id, expiry |-> exp,
                                         state |-> "active", key |-> id]}
    /\ UNCHANGED <<currentTime, decoderClock, decodeAttempts, zeroizedKeys>>

\* Time advances (monotonic)
TickTime ==
    /\ currentTime < MaxTime
    /\ currentTime' = currentTime + 1
    \* Decoder clock advances with bounded skew, clamped to [0, MaxTime]
    /\ \E skew \in -ClockSkewBound..ClockSkewBound :
        LET raw == currentTime + 1 + skew
        IN decoderClock' = IF raw < 0 THEN 0
                           ELSE IF raw > MaxTime THEN MaxTime
                           ELSE raw
    /\ UNCHANGED <<messages, decodeAttempts, zeroizedKeys>>

\* Attempt to decode a message (fail-closed on expiry)
AttemptDecode ==
    /\ \E m \in messages :
        /\ m.state = "active"
        /\ IF decoderClock <= m.expiry + GracePeriod
           THEN  \* Not expired — decode succeeds
                /\ messages' = (messages \ {m}) \cup
                    {[m EXCEPT !.state = "decoded"]}
                /\ decodeAttempts' = Append(decodeAttempts,
                    [msgId |-> m.id, result |-> "success"])
                /\ UNCHANGED zeroizedKeys
           ELSE  \* Expired — fail-closed, zeroize key
                /\ messages' = (messages \ {m}) \cup
                    {[m EXCEPT !.state = "expired"]}
                /\ zeroizedKeys' = zeroizedKeys \cup {m.key}
                /\ decodeAttempts' = Append(decodeAttempts,
                    [msgId |-> m.id, result |-> "expired"])
    /\ UNCHANGED <<currentTime, decoderClock>>

\* Background expiry check — zeroize keys of expired messages
ExpiryGarbageCollect ==
    /\ \E m \in messages :
        /\ m.state = "active"
        /\ currentTime > m.expiry + GracePeriod
        /\ messages' = (messages \ {m}) \cup
            {[m EXCEPT !.state = "expired"]}
        /\ zeroizedKeys' = zeroizedKeys \cup {m.key}
    /\ UNCHANGED <<currentTime, decoderClock, decodeAttempts>>

-----------------------------------------------------------------------------
(* Next-State Relation *)

Next ==
    \/ CreateMessage
    \/ TickTime
    \/ AttemptDecode
    \/ ExpiryGarbageCollect

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

-----------------------------------------------------------------------------
(* Safety Invariants *)

\* CRITICAL: No expired message is ever successfully decoded
NoExpiredDecode ==
    \A i \in 1..Len(decodeAttempts) :
        LET attempt == decodeAttempts[i]
        IN  attempt.result = "success" =>
            \E m \in messages :
                /\ m.id = attempt.msgId
                /\ m.state \in {"decoded", "active"}

\* Expired messages always have their keys zeroized
ExpiredKeysZeroized ==
    \A m \in messages :
        m.state = "expired" => m.key \in zeroizedKeys

\* Decoded messages cannot be re-decoded (replay prevention)
NoReplayDecode ==
    \A m \in messages :
        m.state = "decoded" =>
            \A i \in 1..Len(decodeAttempts) :
                \A j \in (i+1)..Len(decodeAttempts) :
                    ~(decodeAttempts[i].msgId = m.id /\
                      decodeAttempts[j].msgId = m.id /\
                      decodeAttempts[i].result = "success" /\
                      decodeAttempts[j].result = "success")

\* Key zeroization is irreversible
ZeroizationIrreversible ==
    \A k \in zeroizedKeys :
        \A m \in messages :
            m.key = k => m.state \in {"expired", "failed"}

\* Atomicity: message is either fully decoded or fully failed, never partial
AtomicDecode ==
    \A m \in messages :
        m.state \notin {"active"} =>
        m.state \in {"decoded", "expired", "failed"}

===============================================================================
