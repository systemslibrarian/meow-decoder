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
    /\ actualDuration \in MinDuration..MaxDuration
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

\* Sleep phase completes — attacker observes total duration
FinishSleep ==
    /\ opState = "sleeping"
    /\ observedDuration' = actualDuration + sleepDuration
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
(* Safety Properties *)

\* CRITICAL INVARIANT: All observed durations equal the target duration.
\* This is the core timing side-channel prevention property.
ConstantTimeInvariant ==
    opState = "done" => observedDuration = TargetDuration

\* Timing history is constant — every observation is TargetDuration.
\* An attacker with unbounded observations still learns nothing.
TimingHistoryConstant ==
    \A i \in 1..Len(timingHistory) : timingHistory[i] = TargetDuration

\* Sleep is non-negative (we never finish faster than target)
SleepNonNegative ==
    opState = "sleeping" => sleepDuration >= 0

\* Result is hidden from timing observations.
\* For any two completed ops with different results, the observed
\* durations are identical (indistinguishability).
ResultIndistinguishable ==
    opState = "done" => observedDuration = TargetDuration

-----------------------------------------------------------------------------
(* Liveness Properties *)

\* Every started operation eventually completes
OperationsComplete ==
    opState = "running" ~> opState = "idle"

\* Progress: operations are eventually recorded
ProgressProperty ==
    [](opState = "idle" /\ opsCompleted < MaxOps => <>(opsCompleted > opsCompleted))

===============================================================================
