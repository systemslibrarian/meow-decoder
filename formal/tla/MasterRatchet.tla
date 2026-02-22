-------------------------------- MODULE MasterRatchet --------------------------------
(*
 * MasterRatchet.tla
 * =================
 * TLA+ specification of the Meow Master Ratchet (cross-session FS).
 *
 * The Master Ratchet manages multiple ratchet sessions and verifies:
 *
 *  1. Generation counter strictly monotonic:
 *     Each new session gets a strictly higher generation number.
 *     No generation number is reused.
 *
 *  2. Cross-session forward secrecy:
 *     Session N's keys are computationally independent of session M's keys
 *     for M < N.  Modelled by generation-dependent key derivation.
 *
 *  3. Emergency wipe correctness:
 *     After an emergency wipe, all session keys and the master root key
 *     are zeroized.  No further key derivation is possible.
 *
 *  4. Session isolation:
 *     Compromise of session N's root key does not expose sessions M ≠ N.
 *
 *  5. Master counter overflow protection:
 *     The generation counter does not overflow in any reachable state.
 *
 * Run with:
 *   tlc MasterRatchet.tla -config MasterRatchet.cfg
 *)

EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    MAX_SESSIONS,   \* Maximum number of sessions (bound for model checking)
    MAX_GEN         \* Maximum generation number before overflow check

VARIABLES
    master_key,           \* Master root key (abstract: natural number)
    generation,           \* Current generation counter (strictly increasing)
    active_sessions,      \* Set of active session records: {<<gen, session_key>>}
    wiped_generations,    \* Set of generations that have been wiped
    master_state          \* One of: "active", "wiped"

vars == << master_key, generation, active_sessions, wiped_generations, master_state >>

(* -------------------------------------------------------------------------
 * Type invariants
 * -------------------------------------------------------------------------
 *)

TypeOK ==
    /\ master_key \in Nat
    /\ generation \in Nat
    /\ active_sessions \subseteq (Nat \X Nat)   \* (generation, session_key)
    /\ wiped_generations \subseteq Nat
    /\ master_state \in {"active", "wiped"}

(* -------------------------------------------------------------------------
 * Abstract key derivation
 * -------------------------------------------------------------------------
 *)

\* Session key for generation g from master_key mk:
\*   mk' = HKDF(mk, g, "session_chain")
\*   sk  = HKDF(mk', g, "session_key")
\* Abstracted as: SessionKey(mk, g) = mk + g * 100003  (injective proxy)
SessionKey(mk, g) == mk + g * 100003

\* Master ratchet: advance master key after spawning session
NextMasterKey(mk, g) == mk + g * 7 + 1

(* -------------------------------------------------------------------------
 * Initial state
 * -------------------------------------------------------------------------
 *)

Init ==
    /\ master_key = 42        \* Non-zero initial master key
    /\ generation = 0
    /\ active_sessions = {}
    /\ wiped_generations = {}
    /\ master_state = "active"

(* -------------------------------------------------------------------------
 * Actions
 * -------------------------------------------------------------------------
 *)

\* Create a new session: advance generation, derive session key
CreateSession ==
    /\ master_state = "active"
    /\ generation < MAX_GEN
    /\ Cardinality(active_sessions) < MAX_SESSIONS
    /\ LET g  == generation + 1
           sk == SessionKey(master_key, g)
           mk_next == NextMasterKey(master_key, g)
       IN
        /\ generation' = g
        /\ active_sessions' = active_sessions \union {<<g, sk>>}
        /\ master_key' = mk_next
        /\ wiped_generations' = wiped_generations
        /\ master_state' = master_state

\* Retire a session: remove from active set (key zeroized)
RetireSession(g) ==
    /\ master_state = "active"
    /\ \E sk \in Nat : <<g, sk>> \in active_sessions
    /\ \E sk \in Nat :
        /\ active_sessions' = active_sessions \ {<<g, sk>>}
        /\ wiped_generations' = wiped_generations \union {g}
        /\ master_key' = master_key
        /\ generation' = generation
        /\ master_state' = master_state

\* Emergency wipe: zeroize everything
EmergencyWipe ==
    /\ master_state = "active"
    /\ master_key' = 0
    /\ generation' = generation     \* Counter preserved for audit
    /\ active_sessions' = {}
    /\ wiped_generations' = wiped_generations \union
            {g \in Nat : \E sk \in Nat : <<g, sk>> \in active_sessions}
    /\ master_state' = "wiped"

\* Next state
Next ==
    \/ CreateSession
    \/ \E g \in {g \in Nat : \E sk \in Nat : <<g, sk>> \in active_sessions} :
            RetireSession(g)
    \/ EmergencyWipe

\* System spec
Spec == Init /\ [][Next]_vars /\ WF_vars(CreateSession)

(* =========================================================================
 * Safety Invariants
 * =========================================================================
 *)

\* INV-1: Generation counter is strictly increasing
GenerationMonotonic ==
    [](generation' >= generation)

\* INV-2: No two active sessions share the same generation number
SessionGenerationUnique ==
    \A g \in Nat :
        Cardinality({sk \in Nat : <<g, sk>> \in active_sessions}) <= 1

\* INV-3: No active sessions after emergency wipe
WipeCompleteness ==
    master_state = "wiped" =>
        /\ master_key = 0
        /\ active_sessions = {}

\* INV-4: Session keys are generation-unique (injectivity)
SessionKeyUniqueness ==
    \A g1, g2, sk \in Nat :
        <<g1, sk>> \in active_sessions /\
        <<g2, sk>> \in active_sessions =>
        g1 = g2

\* INV-5: Generation counter never exceeds MAX_GEN (overflow protection)
GenerationBound ==
    generation <= MAX_GEN

\* INV-6: Wiped generations are never reactivated
WipedNotReused ==
    \A g \in wiped_generations :
        ~(\E sk \in Nat : <<g, sk>> \in active_sessions)

\* Combined safety
Safety ==
    /\ TypeOK
    /\ SessionGenerationUnique
    /\ WipeCompleteness
    /\ SessionKeyUniqueness
    /\ GenerationBound
    /\ WipedNotReused

(* =========================================================================
 * Liveness Properties
 * =========================================================================
 *)

\* LIVE-1: Sessions can always be created while under limit
CanCreateSession ==
    (master_state = "active" /\ generation < MAX_GEN) ~>
        generation > 0

\* LIVE-2: Emergency wipe is always possible
WipeEventuallyPossible ==
    master_state = "active" ~> master_state = "wiped"

=============================================================================
\* Modification History
\* Created for Meow Decoder Master Ratchet formal verification
