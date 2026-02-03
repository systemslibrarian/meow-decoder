# 🐱 Protocol Diagrams - Meow Decoder v1.0

**Mermaid visualizations of Meow Decoder data flows and state machines**

---

## 🔐 Encoding Pipeline State Machine

```mermaid
stateDiagram-v2
    [*] --> ReadFile
    
    ReadFile: 📁 Read Input File
    ReadFile --> Compress: File loaded
    
    Compress: 📦 Compress with zlib
    Compress --> Hash: Compression complete
    
    Hash: #️⃣ Compute SHA-256
    Hash --> Encrypt: Hash computed
    
    Encrypt: 🔐 Encrypt (AES-256-GCM)
    Encrypt: Password → Argon2id → Key
    Encrypt --> FountainEncode: Encryption complete
    
    FountainEncode: 🌊 Fountain Encode (LT codes)
    FountainEncode: Split into K blocks
    FountainEncode: Generate K×1.5 droplets
    FountainEncode --> QRGenerate: Droplets generated
    
    QRGenerate: 📱 Generate QR Codes
    QRGenerate: Frame 0: Manifest (collar tag)
    QRGenerate: Frame 1+: Fountain droplets
    QRGenerate --> GIFCreate: All QR codes generated
    
    GIFCreate: 🎬 Create Animated GIF
    GIFCreate: Combine frames @ 10 FPS
    GIFCreate --> [*]: GIF complete!
    
    note right of Encrypt
        ✅ HMAC protects manifest
        ✅ AAD binds all metadata
        ✅ Nonce is unique per call
    end note
    
    note right of FountainEncode
        ✅ Robust Soliton distribution
        ✅ ~33% frame loss tolerance
        ✅ Belief propagation decode
    end note
```

---

## 🎯 Decoding Pipeline State Machine

```mermaid
stateDiagram-v2
    [*] --> LoadGIF
    
    LoadGIF: 📺 Load GIF/Video File
    LoadGIF --> ExtractFrames: File opened
    
    ExtractFrames: 🎞️ Extract Frames
    ExtractFrames --> ReadQR: Frames extracted
    
    ReadQR: 📱 Read QR Codes
    ReadQR: Frame 0: Manifest
    ReadQR: Frame 1+: Droplets
    ReadQR --> ParseManifest: All QR decoded
    
    ParseManifest: 📋 Parse Manifest
    ParseManifest: Unpack: salt, nonce, sizes
    ParseManifest --> VerifyHMAC: Manifest parsed
    
    VerifyHMAC: ✅ Verify HMAC
    VerifyHMAC: Authenticate manifest core
    VerifyHMAC --> DeriveKey: HMAC valid
    VerifyHMAC --> ErrorAuth: HMAC invalid ❌
    ErrorAuth --> [*]
    
    DeriveKey: 🔑 Derive Key
    DeriveKey: Password + Argon2id
    DeriveKey --> FountainDecode: Key derived
    
    FountainDecode: 🌊 Fountain Decode
    FountainDecode: Belief propagation
    FountainDecode: Collect droplets until K blocks
    FountainDecode --> CheckComplete: Decoding attempted
    
    CheckComplete: 🔢 Check Completion
    CheckComplete --> Decrypt: All blocks recovered ✅
    CheckComplete --> MoreFrames: Need more droplets ⏳
    MoreFrames --> ReadQR: Read more frames
    
    Decrypt: 🔓 Decrypt Data
    Decrypt: AES-256-GCM decrypt
    Decrypt --> Decompress: Decryption successful
    
    Decompress: 📦 Decompress
    Decompress: zlib decompress
    Decompress --> Verify: Decompression complete
    
    Verify: #️⃣ Verify SHA-256
    Verify --> WriteFile: Hash matches! ✅
    Verify --> ErrorCorrupt: Hash mismatch ❌
    ErrorCorrupt --> [*]
    
    WriteFile: 💾 Write Output File
    WriteFile --> [*]: Complete! ✅
    
    note right of VerifyHMAC
        ⚠️ CRITICAL: Fail-closed
        If HMAC fails, stop immediately
        Never output partial plaintext
    end note
    
    note right of FountainDecode
        ✅ Redundant codes tolerate loss
        ✅ Works from any K+epsilon droplets
        ✅ Automatic error recovery
    end note
```

---

## 🔮 Time-Lock Duress State Machine

```mermaid
stateDiagram-v2
    [*] --> Armed
    
    Armed: ⏰ ARMED STATE
    Armed: checkin_interval set
    Armed: next_deadline = now + interval
    Armed: Waiting for user renewal
    
    Armed --> Renewal: User runs meow-deadmans-switch renew
    Armed --> Deadline: next_deadline exceeded ⏰
    
    Renewal: 🔄 RENEWAL ACTION
    Renewal: next_deadline = now + interval
    Renewal: Grace period reset
    Renewal --> Armed: Clock restarted ✅
    
    Deadline: ⏰ DEADLINE PASSED
    Deadline: next_deadline < now
    Deadline: Grace period expired
    Deadline --> Triggered: Auto-trigger on any decode attempt
    
    Triggered: 🚨 TRIGGERED STATE
    Triggered: Real file → LOCKED 🔒
    Triggered: Decoy file → RELEASED 📄
    Triggered: decode_gif returns fake "success"
    Triggered --> DecoyReleased: Decoy released
    
    DecoyReleased: 🎭 DECOY RELEASED
    DecoyReleased: User sees innocent file
    DecoyReleased: Cannot prove real secret existed
    DecoyReleased --> [*]: Deniability achieved ✅
    
    Armed --> Disabled: User runs meow-deadmans-switch disable
    Disabled: 🛑 DISABLED STATE
    Disabled: Clock stopped
    Disabled: next_deadline cleared
    Disabled --> [*]: Disarmed (no auto-trigger)
    
    note right of Armed
        ✅ Safe state
        ✅ No deadline pressure
        Renewal keeps switch alive
    end note
    
    note right of Triggered
        🚨 EMERGENCY STATE
        Real data inaccessible
        Plausible deniability activated
    end note
```

---

## 🔐 Forward Secrecy Key Exchange (MEOW3)

```mermaid
sequenceDiagram
    actor Sender
    actor Receiver
    participant Channel as Optical<br/>Channel
    
    Sender->>Sender: Generate ephemeral<br/>X25519 keypair
    Sender->>Sender: ephemeral_private (destroy after use)
    Sender->>Sender: ephemeral_public (send to receiver)
    
    Sender->>Sender: Load receiver_public<br/>(known in advance)
    
    Sender->>Sender: X25519 ECDH:<br/>ephemeral_private +<br/>receiver_public
    Sender->>Sender: = shared_secret_1 (32 bytes)
    
    Sender->>Sender: HKDF(shared_secret_1 +<br/>password)<br/>= encryption_key
    
    Sender->>Sender: Encrypt file with<br/>encryption_key
    Sender->>Channel: Send: ephemeral_public +<br/>ciphertext in GIF
    
    Channel->>Receiver: Receive GIF
    Receiver->>Receiver: Extract<br/>ephemeral_public
    
    Receiver->>Receiver: Load receiver_private<br/>(stored locally)
    
    Receiver->>Receiver: X25519 ECDH:<br/>receiver_private +<br/>ephemeral_public
    Receiver->>Receiver: = shared_secret_2 (same!)
    
    Receiver->>Receiver: HKDF(shared_secret_2 +<br/>password)<br/>= encryption_key (same!)
    
    Receiver->>Receiver: Decrypt with<br/>encryption_key ✅
    
    note over Sender: Sender: Ephemeral private<br/>destroyed after use<br/>Never stored!
    note over Channel: Channel: Only public keys +<br/>ciphertext visible<br/>No long-term secrets
    note over Receiver: Receiver: Future compromise<br/>of receiver_private<br/>doesn't decrypt past<br/>messages (already destroyed)
```

---

## 🌊 Fountain Encoding Flow (Luby Transform)

```mermaid
graph LR
    A["📊 Source Data<br/>(K blocks)"] -->|Robust Soliton| B["🎲 Select<br/>degree d"]
    
    B -->|d = 1| C1["🧩 Block 0"]
    B -->|d = 2| C2["🧩 Block 0<br/>XOR<br/>Block 3"]
    B -->|d = 3| C3["🧩 Block 1<br/>XOR<br/>Block 4<br/>XOR<br/>Block 7"]
    B -->|d = 4+| C4["🧩 Multi-block<br/>XOR"]
    
    C1 -->|XOR| D["🌊 DROPLET<br/>(encoded symbol)"]
    C2 -->|XOR| D
    C3 -->|XOR| D
    C4 -->|XOR| D
    
    D -->|Store seed| E["📱 QR Code<br/>(droplet)"]
    
    E -->|Infinite| F["🎬 GIF<br/>(K × 1.5 droplets)"]
    
    style A fill:#90EE90
    style D fill:#FFB6C6
    style F fill:#87CEEB
```

---

## 🎲 Fountain Decoding Flow (Belief Propagation)

```mermaid
graph TD
    A["🎲 Collect Droplets<br/>(from GIF)"] --> B["🧩 Check Degree"]
    
    B -->|degree = 1| C["✅ Immediate<br/>Decode!"]
    B -->|degree > 1| D["⏳ Add to<br/>Pending List"]
    
    C --> E["🧬 XOR Out<br/>Solved Block"]
    E --> F["🔄 Reduce<br/>Pending Droplets"]
    
    F -->|New degree 1| G["✅ Cascade<br/>Solving!"]
    G --> E
    
    F -->|No degree 1| H{"All K<br/>blocks<br/>solved?"}
    
    H -->|YES| I["🎉 SUCCESS!<br/>Data recovered"]
    H -->|NO| J["⏳ Need more<br/>droplets"]
    J --> A
    
    style C fill:#90EE90
    style G fill:#90EE90
    style I fill:#90EE90
    style J fill:#FFB6C6
    
    note over C
        Degree 1 = raw data
        Decode immediately
    end note
    
    note over E
        Already-solved blocks
        can be XORed out
    end note
    
    note over F
        Reduces degree of
        pending droplets
    end note
```

---

## 🔒 Manifest Authentication Chain

```mermaid
graph LR
    A["🔐 Manifest Core<br/>(all metadata)"] -->|"Pack without HMAC"| B["📋 Packed Manifest"]
    
    B -->|"Argon2id(password)"| C["🔑 Encryption Key"]
    
    C -->|"HKDF + domain sep"| D["🔑 HMAC Key"]
    
    B -->|"+ HMAC Key"| E["🔏 Compute HMAC"]
    
    E --> F["✅ HMAC Tag<br/>(32 bytes)"]
    
    F -->|"Pack with HMAC"| G["📦 Final Manifest<br/>(authenticated)"]
    
    H["📬 Receiver"] -->|"extract"| I["🔓 Manifest<br/>+ HMAC tag"]
    
    I -->|"derive same key"| J["🔑 HMAC Key"]
    
    I -->|"+ HMAC Key"| K["🔏 Compute HMAC<br/>(verify)"]
    
    K -->|"compare with tag"| L{"HMAC<br/>Match?"}
    
    L -->|"YES"| M["✅ Valid<br/>Proceed"]
    L -->|"NO"| N["❌ Tampered<br/>Stop"]
    
    style F fill:#90EE90
    style M fill:#90EE90
    style N fill:#FFB6C6
```

---

## 📊 Schrödinger Quantum Superposition

```mermaid
graph TB
    A["🔐 Reality A<br/>(real secret)<br/>AES-encrypt"] -->|XOR| B["⚛️ Quantum<br/>Noise"]
    
    C["🎭 Reality B<br/>(decoy secret)<br/>AES-encrypt"] -->|XOR| B
    
    B -->|"Interleave A/B<br/>even/odd positions"| D["👁️ Superposition<br/>(both realities<br/>mixed)")
    
    D -->|"Password A"| E["🔮 Collapse<br/>to Reality A"]
    D -->|"Password B"| F["🔮 Collapse<br/>to Reality B"]
    
    E --> G["✅ Real Secret<br/>Decrypted"]
    F --> H["🎭 Decoy Secret<br/>Decrypted"]
    
    G -->|"Cannot prove"| I["❌ Reality B<br/>existence<br/>unprovable"]
    
    H -->|"Cannot prove"| J["❌ Reality A<br/>existence<br/>unprovable"]
    
    style D fill:#9966CC
    style G fill:#90EE90
    style H fill:#FFB6C6
    style I fill:#888888
    style J fill:#888888
    
    note over D
        Both realities exist
        in statistical
        superposition
        Neither provable
        without correct
        password
    end note
```

---

## 🎯 Security Verification Points

```mermaid
graph LR
    subgraph Encoding["Encoding Security"]
        E1["🔑 Key Derivation<br/>(Argon2id)"]
        E2["🔐 Encryption<br/>(AES-256-GCM)"]
        E3["✅ HMAC<br/>Authentication"]
        E4["📱 QR Integrity<br/>(Frame MACs)"]
        
        E1 --> E2
        E2 --> E3
        E3 --> E4
    end
    
    subgraph Decoding["Decoding Verification"]
        D1["✅ Frame MAC<br/>Verify"]
        D2["✅ HMAC<br/>Verify"]
        D3["🔓 Decrypt"]
        D4["#️⃣ SHA-256<br/>Verify"]
        
        D1 --> D2
        D2 --> D3
        D3 --> D4
    end
    
    subgraph Output["Output Safety"]
        O1["❌ No plaintext<br/>on error"]
        O2["🔒 Fail-closed<br/>behavior"]
        O3["✅ Complete<br/>decryption"]
    end
    
    E4 -->|GIF transmission| D1
    D4 -->|Verified| O3
    D2 -->|Tamper detected| O1
    O1 --> O2
    
    style E3 fill:#90EE90
    style D2 fill:#90EE90
    style D4 fill:#90EE90
    style O2 fill:#90EE90
```

---

**Last Updated**: 2026-01-29  
**Version**: 1.0.0 (SECURITY-REVIEWED v1.0 INTERNAL REVIEW)  
**Visualization**: Mermaid diagrams (6 flows, state machines, and verification chain)

