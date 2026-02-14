---- MODULE MeowStreaming ----
\* =========================================================================
\* TLA+ Model: Streaming Encryption (AES-256-CTR + Encrypt-then-MAC)
\*
\* Models the StreamingCipher from meow_decoder/streaming_crypto.py:
\* - AES-256-CTR with 16-byte nonce, per-session
\* - HMAC-SHA256 Encrypt-then-MAC authentication
\* - HKDF domain separation for MAC key
\* - Chunk-at-a-time processing with bounded counter
\*
\* Safety invariants:
\*  1. NonceUniqueness:    Same (key, nonce) never reused across sessions
\*  2. MACCoversAll:       MAC digest includes every ciphertext chunk
\*  3. DomainSeparation:   enc_key ≠ mac_key for every session
\*  4. EncryptThenMAC:     MAC always computed over ciphertext (never plaintext)
\*  5. CounterNoWrap:      CTR counter stays within 2^128 (modelled as < MAX_CTR)
\*  6. MACVerifyBeforeUse: Decryption only after MAC verification succeeds
\*
\* Author: Meow-Decoder Formal Verification (TODO 5a)
\* =========================================================================
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    MAX_CHUNKS,       \* Maximum chunks per session (bounds state space)
    MAX_SESSIONS,     \* Maximum number of encryption sessions
    MAX_CTR,          \* Counter ceiling (models 2^128 in real CTR mode)
    NUM_KEYS          \* Number of distinct keys in the model

VARIABLES
    \* --- Session management ---
    sessions,         \* Set of session records: [key, nonce, role, ...]
    sessionCount,     \* Current number of started sessions
    \* --- Per-session chunk state ---
    chunkIndex,       \* Function: sessionId -> next chunk index (0-based)
    ciphertextLog,    \* Function: sessionId -> sequence of ciphertext chunks
    macState,         \* Function: sessionId -> set of chunk indices included in MAC
    macFinalized,     \* Function: sessionId -> BOOLEAN (has MAC been finalized?)
    \* --- Nonce tracking (cross-session) ---
    usedNonces,       \* Set of <<key, nonce>> pairs already consumed
    \* --- Decryption state ---
    macVerified,      \* Function: sessionId -> BOOLEAN (MAC verified before decrypt?)
    decryptStarted,   \* Function: sessionId -> BOOLEAN (decryption begun?)
    \* --- Global phase ---
    phase             \* "running" | "done"

vars == <<sessions, sessionCount, chunkIndex, ciphertextLog,
          macState, macFinalized, usedNonces, macVerified,
          decryptStarted, phase>>

\* =========================================================================
\* Type invariant
\* =========================================================================
SessionIds == 1..MAX_SESSIONS

TypeOK ==
    /\ sessionCount \in 0..MAX_SESSIONS
    /\ phase \in {"running", "done"}
    /\ usedNonces \subseteq (1..NUM_KEYS) \X (1..NUM_KEYS)
    /\ \A sid \in 1..sessionCount :
        /\ chunkIndex[sid] \in 0..MAX_CHUNKS
        /\ macFinalized[sid] \in BOOLEAN
        /\ macVerified[sid] \in BOOLEAN
        /\ decryptStarted[sid] \in BOOLEAN
        /\ macState[sid] \subseteq 0..(MAX_CHUNKS - 1)

\* =========================================================================
\* Initial state
\* =========================================================================
Init ==
    /\ sessions = <<>>
    /\ sessionCount = 0
    /\ chunkIndex = [sid \in SessionIds |-> 0]
    /\ ciphertextLog = [sid \in SessionIds |-> <<>>]
    /\ macState = [sid \in SessionIds |-> {}]
    /\ macFinalized = [sid \in SessionIds |-> FALSE]
    /\ usedNonces = {}
    /\ macVerified = [sid \in SessionIds |-> FALSE]
    /\ decryptStarted = [sid \in SessionIds |-> FALSE]
    /\ phase = "running"

\* =========================================================================
\* Actions
\* =========================================================================

\* --- Start a new encryption session with fresh nonce ---
StartSession(key, nonce) ==
    /\ phase = "running"
    /\ sessionCount < MAX_SESSIONS
    /\ key \in 1..NUM_KEYS
    /\ nonce \in 1..NUM_KEYS
    \* CRITICAL: reject if (key, nonce) pair already used
    /\ <<key, nonce>> \notin usedNonces
    /\ LET sid == sessionCount + 1
           \* Model HKDF domain separation: mac key = key + NUM_KEYS offset
           \* In implementation: HKDF(key, salt=nonce, info=STREAMING_MAC_INFO)
           macKeyVal == key + NUM_KEYS
       IN /\ sessionCount' = sid
          /\ sessions' = Append(sessions, [
                key |-> key,
                nonce |-> nonce,
                role |-> "encrypt",
                macKey |-> macKeyVal
             ])
          /\ usedNonces' = usedNonces \cup {<<key, nonce>>}
          /\ UNCHANGED <<chunkIndex, ciphertextLog, macState,
                         macFinalized, macVerified, decryptStarted, phase>>

\* --- Encrypt one chunk (Encrypt-then-MAC: encrypt, then feed ct to MAC) ---
EncryptChunk(sid) ==
    /\ phase = "running"
    /\ sid \in 1..sessionCount
    /\ sessions[sid].role = "encrypt"
    /\ ~macFinalized[sid]
    /\ chunkIndex[sid] < MAX_CHUNKS
    /\ LET ci == chunkIndex[sid]
       IN /\ chunkIndex' = [chunkIndex EXCEPT ![sid] = ci + 1]
          \* Record ciphertext chunk (abstract token)
          /\ ciphertextLog' = [ciphertextLog EXCEPT
                ![sid] = Append(ciphertextLog[sid], ci)]
          \* Feed ciphertext chunk into MAC (Encrypt-then-MAC)
          /\ macState' = [macState EXCEPT ![sid] = macState[sid] \cup {ci}]
          /\ UNCHANGED <<sessions, sessionCount, macFinalized,
                         usedNonces, macVerified, decryptStarted, phase>>

\* --- Finalize MAC (no more chunks accepted after this) ---
FinalizeMAC(sid) ==
    /\ phase = "running"
    /\ sid \in 1..sessionCount
    /\ sessions[sid].role = "encrypt"
    /\ ~macFinalized[sid]
    /\ chunkIndex[sid] > 0           \* must have encrypted at least 1 chunk
    /\ macFinalized' = [macFinalized EXCEPT ![sid] = TRUE]
    /\ UNCHANGED <<sessions, sessionCount, chunkIndex, ciphertextLog,
                   macState, usedNonces, macVerified, decryptStarted, phase>>

\* --- Start decrypt session (paired with an existing encrypt session) ---
StartDecryptSession(encSid) ==
    /\ phase = "running"
    /\ sessionCount < MAX_SESSIONS
    /\ encSid \in 1..sessionCount
    /\ sessions[encSid].role = "encrypt"
    /\ macFinalized[encSid]          \* encrypt must be finalized
    /\ LET sid == sessionCount + 1
       IN /\ sessionCount' = sid
          /\ sessions' = Append(sessions, [
                key |-> sessions[encSid].key,
                nonce |-> sessions[encSid].nonce,
                role |-> "decrypt",
                macKey |-> sessions[encSid].macKey,
                encSid |-> encSid
             ])
          \* Do NOT add to usedNonces again — decrypt reuses same (key,nonce)
          /\ UNCHANGED <<chunkIndex, ciphertextLog, macState,
                         macFinalized, usedNonces, macVerified,
                         decryptStarted, phase>>

\* --- Verify MAC (must happen before any decryption) ---
VerifyMAC(sid) ==
    /\ phase = "running"
    /\ sid \in 1..sessionCount
    /\ sessions[sid].role = "decrypt"
    /\ ~macVerified[sid]
    /\ ~decryptStarted[sid]
    /\ macVerified' = [macVerified EXCEPT ![sid] = TRUE]
    /\ UNCHANGED <<sessions, sessionCount, chunkIndex, ciphertextLog,
                   macState, macFinalized, usedNonces, decryptStarted, phase>>

\* --- Decrypt one chunk (only after MAC verification) ---
DecryptChunk(sid) ==
    /\ phase = "running"
    /\ sid \in 1..sessionCount
    /\ sessions[sid].role = "decrypt"
    /\ macVerified[sid]               \* CRITICAL: MAC must be verified first
    /\ chunkIndex[sid] < MAX_CHUNKS
    /\ LET ci == chunkIndex[sid]
       IN /\ chunkIndex' = [chunkIndex EXCEPT ![sid] = ci + 1]
          /\ decryptStarted' = [decryptStarted EXCEPT ![sid] = TRUE]
          /\ UNCHANGED <<sessions, sessionCount, ciphertextLog,
                         macState, macFinalized, usedNonces,
                         macVerified, phase>>

\* --- System terminates ---
Finish ==
    /\ phase = "running"
    /\ phase' = "done"
    /\ UNCHANGED <<sessions, sessionCount, chunkIndex, ciphertextLog,
                   macState, macFinalized, usedNonces, macVerified,
                   decryptStarted>>

\* --- Stutter in done state (prevents deadlock) ---
Stutter ==
    /\ phase = "done"
    /\ UNCHANGED vars

\* =========================================================================
\* Next-state relation
\* =========================================================================
Next ==
    \/ \E key \in 1..NUM_KEYS, nonce \in 1..NUM_KEYS :
          StartSession(key, nonce)
    \/ \E sid \in 1..MAX_SESSIONS : EncryptChunk(sid)
    \/ \E sid \in 1..MAX_SESSIONS : FinalizeMAC(sid)
    \/ \E sid \in 1..MAX_SESSIONS : StartDecryptSession(sid)
    \/ \E sid \in 1..MAX_SESSIONS : VerifyMAC(sid)
    \/ \E sid \in 1..MAX_SESSIONS : DecryptChunk(sid)
    \/ Finish
    \/ Stutter

Spec == Init /\ [][Next]_vars

\* =========================================================================
\* SAFETY INVARIANTS
\* =========================================================================

\* INV-1: Nonce uniqueness — no two ENCRYPT sessions share (key, nonce)
\* This is enforced by the StartSession guard, but we verify it holds globally.
NonceUniqueness ==
    \A i, j \in 1..sessionCount :
        (i /= j /\ sessions[i].role = "encrypt" /\ sessions[j].role = "encrypt")
        => (sessions[i].key /= sessions[j].key \/ sessions[i].nonce /= sessions[j].nonce)

\* INV-2: MAC covers every ciphertext chunk (no chunk is missed)
MACCoversAllChunks ==
    \A sid \in 1..sessionCount :
        sessions[sid].role = "encrypt"
        => macState[sid] = {ci \in 0..(chunkIndex[sid] - 1) : TRUE}

\* INV-3: Domain separation — macKey is structurally distinct from enc key
\* In implementation: HKDF with STREAMING_MAC_INFO salt.
\* Here we model it as the mac key record /= the raw key.
DomainSeparation ==
    \A sid \in 1..sessionCount :
        sessions[sid].macKey /= sessions[sid].key

\* INV-4: Encrypt-then-MAC ordering — every chunk in macState is a ciphertext
\* chunk that was actually encrypted (exists in ciphertextLog).
EncryptThenMAC ==
    \A sid \in 1..sessionCount :
        sessions[sid].role = "encrypt"
        => \A ci \in macState[sid] :
              ci \in {ciphertextLog[sid][i] : i \in 1..Len(ciphertextLog[sid])}

\* INV-5: CTR counter never reaches the wrap-around ceiling
CounterNoWrap ==
    \A sid \in 1..sessionCount :
        chunkIndex[sid] < MAX_CTR

\* INV-6: Decryption never starts without prior MAC verification
MACVerifyBeforeDecrypt ==
    \A sid \in 1..sessionCount :
        (sessions[sid].role = "decrypt" /\ decryptStarted[sid])
        => macVerified[sid]

\* =========================================================================
\* Composite invariant
\* =========================================================================
AllInvariants ==
    /\ TypeOK
    /\ NonceUniqueness
    /\ MACCoversAllChunks
    /\ DomainSeparation
    /\ EncryptThenMAC
    /\ CounterNoWrap
    /\ MACVerifyBeforeDecrypt

\* =========================================================================
\* Liveness (under fairness)
\* =========================================================================
EventuallyDone == <>(phase = "done")

\* =========================================================================
\* THEOREMS
\* =========================================================================

THEOREM NonceUniquenessHolds  == Spec => []NonceUniqueness
THEOREM MACCoverageHolds      == Spec => []MACCoversAllChunks
THEOREM DomainSepHolds        == Spec => []DomainSeparation
THEOREM EncryptThenMACHolds   == Spec => []EncryptThenMAC
THEOREM CounterSafe           == Spec => []CounterNoWrap
THEOREM MACBeforeDecryptHolds == Spec => []MACVerifyBeforeDecrypt
THEOREM TypeCorrectness       == Spec => []TypeOK

====
