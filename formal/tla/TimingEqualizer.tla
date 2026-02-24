------------------------------ MODULE TimingEqualizer ------------------------------
(****************************************************************************)
(* TLA+ Specification of the Timing Equalizer                               *)
(*                                                                          *)
(* Models the constant-time execution guarantees for cryptographic           *)
(* operations. Verifies that all code paths through the equalizer           *)
(* produce the same observable timing, preventing timing side channels.     *)
(*                                                                          *)
(* Security Property: An observer measuring wall-clock time of any          *)
(* equalized operation cannot distinguish between different inputs or       *)
(* different code paths (success vs error).                                 *)
(*                                                                          *)
(* Author: Meow Decoder Project                                             *)
(* Date: February 2026                                                      *)
(****************************************************************************)

EXTENDS Integers, Sequences, FiniteSets, TLC, Reals

CONSTANTS
    MaxOps,             \* Maximum number of equalized operations
    MinDuration,        \* Minimum operation duration (time units)
    MaxDuration,        \* Maximum operation duration (time units)
    TargetDuration,     \* Target equalized duration (time units)
    Jitter              \* Maximum allowed timing jitter (time units)

ASSUME MinDuration >= 0
ASSUME MaxDuration >= MinDuration
ASSUME TargetDuration >= MaxDuration
ASSUME Jitter >= 0

-----------------------------------------------------------------------------

VARIABLES
    opState,            \* "idle" | "running" | "sleeping" | "done"
    actualDuration,     \* Actual computation time for current op
    sleepDuration,      \* Sleep time to pad to target
    observedDuration,   \* Total wall-clock time observed by attacker
    operationResult,    \* "success" | "error" (hidden from observer)
    opsCompleted,       \* Counter of completed operations
    timingHistory       \* Sequence of observed durations (attacker's view)

vars == <<opState, actualDuration, sleepDuration, observedDuration,
          operationResult, opsCompleted, timingHistory>>

-----------------------------------------------------------------------------
(* Type Invariant *)

TypeOK ==
    /\ opState \in {"idle", "running", "sleeping", "done"}
    /\ actualDuration \in 0..MaxDuration           \* 0 is valid in "idle" state
    /\ sleepDuration \in 0..(TargetDuration - MinDuration + Jitter)
    /\ observedDuration \in 0..(TargetDuration + Jitter)
    /\ operationResult \in {"success", "error", "none"}
    /\ opsCompleted \in 0..MaxOps
    /\ timingHistory \in Seq(0..(TargetDuration + Jitter))

-----------------------------------------------------------------------------
(* Initial State *)

Init ==
    /\ opState = "idle"
    /\ actualDuration = 0
    /\ sleepDuration = 0
    /\ observedDuration = 0
    /\ operationResult = "none"
    /\ opsCompleted = 0
    /\ timingHistory = <<>>

-----------------------------------------------------------------------------
(* State Transitions *)

\* Start an equalized operation (nondeterministic duration + result)
StartOp ==
    /\ opState = "idle"
    /\ opsCompleted < MaxOps
    /\ \E d \in MinDuration..MaxDuration :
        /\ actualDuration' = d
        /\ opState' = "running"
    /\ \E r \in {"success", "error"} :
        /\ operationResult' = r
    /\ UNCHANGED <<sleepDuration, observedDuration, opsCompleted, timingHistory>>

\* Operation completes — calculate required sleep padding
FinishComputation ==
    /\ opState = "running"
    /\ sleepDuration' = TargetDuration - actualDuration
    /\ opState' = "sleeping"
    /\ UNCHANGED <<actualDuration, observedDuration, operationResult,
                   opsCompleted, timingHistory>>

\* Sleep phase completes — attacker observes total duration (with OS jitter)
\* Jitter models OS scheduler variance: observedDuration \in [target, target+Jitter]
FinishSleep ==
    /\ opState = "sleeping"
    /\ \E jitter \in 0..Jitter :
        /\ observedDuration' = actualDuration + sleepDuration + jitter
    /\ opState' = "done"
    /\ UNCHANGED <<actualDuration, sleepDuration, operationResult,
                   opsCompleted, timingHistory>>

\* Record observation and reset for next operation
RecordAndReset ==
    /\ opState = "done"
    /\ timingHistory' = Append(timingHistory, observedDuration)
    /\ opsCompleted' = opsCompleted + 1
    /\ opState' = "idle"
    /\ actualDuration' = 0
    /\ sleepDuration' = 0
    /\ observedDuration' = 0
    /\ operationResult' = "none"

-----------------------------------------------------------------------------
(* Next-State Relation *)

Next ==
    \/ StartOp
    \/ FinishComputation
    \/ FinishSleep
    \/ RecordAndReset

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

-----------------------------------------------------------------------------
(* Safety Properties — jitter-tolerant, production-realistic               *)

\* CORE INVARIANT: all observed durations lie in [TargetDuration, TargetDuration+Jitter].
\* Rationale: sleep pads to exactly TargetDuration, but OS scheduler adds up to Jitter
\* extra ticks.  The security property is that the inter-operation variance visible
\* to an attacker is bounded by Jitter, not by the semantically-significant
\* actualDuration variance (which can be as large as MaxDuration-MinDuration).
ConstantTimeInvariant ==
    opState = "done" =>
        /\ observedDuration >= TargetDuration
        /\ observedDuration <= TargetDuration + Jitter

\* Timing history bounded — every recorded observation is in the jitter band.
\* An unbounded attacker cannot distinguish two operations whose actualDuration
\* values differ by less than Jitter.
TimingHistoryBounded ==
    \A i \in 1..Len(timingHistory) :
        /\ timingHistory[i] >= TargetDuration
        /\ timingHistory[i] <= TargetDuration + Jitter

\* Sleep is non-negative (we never finish before the minimum padding is done).
SleepNonNegative ==
    opState = "sleeping" => sleepDuration >= 0

\* Result indistinguishability: success and error observations both lie in
\* [TargetDuration, TargetDuration+Jitter] — no timing oracle can distinguish them.
ResultIndistinguishable ==
    opState = "done" =>
        /\ observedDuration >= TargetDuration
        /\ observedDuration <= TargetDuration + Jitter

-----------------------------------------------------------------------------
(* Liveness Properties *)

\* Every started operation eventually completes
OperationsComplete ==
    opState = "running" ~> opState = "idle"

\* Progress: operations are eventually recorded
ProgressProperty ==
    [](opState = "idle" /\ opsCompleted < MaxOps => <>(opsCompleted > opsCompleted))

===============================================================================
