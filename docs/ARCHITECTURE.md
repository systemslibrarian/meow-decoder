# 🏗️ Meow Decoder - Architecture Documentation

**Version:** 1.0.0 (SECURITY-REVIEWED v1.0 INTERNAL REVIEW)  
**Date:** 2026-01-22  
**Status:** Production

---

## 📋 **Overview**

Meow Decoder is an optical air-gap file transfer system that combines:
- **Cryptography** (AES-256-GCM, Argon2id, optional Kyber)
- **Error Correction** (Luby Transform fountain codes)
- **Visual Encoding** (QR codes in GIF animations)
- **Optical Transfer** (screen → camera)

---

## 🎯 **High-Level Architecture**

```
┌──────────────────────────────────────────────────────────────────┐
│                         MEOW DECODER                             │
│                  Air-Gap File Transfer System                    │
└──────────────────────────────────────────────────────────────────┘

┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│   SENDER    │    │   OPTICAL    │    │  RECEIVER   │
│   DEVICE    │───▶│   CHANNEL    │───▶│   DEVICE    │
│             │    │  (screen →   │    │             │
│  encode.py  │    │   camera)    │    │ decode.py   │
└─────────────┘    └──────────────┘    └─────────────┘
      │                                       │
      ▼                                       ▼
┌─────────────┐                        ┌─────────────┐
│ secret.pdf  │                        │ secret.pdf  │
│  (plain)    │                        │  (plain)    │
└─────────────┘                        └─────────────┘
```

---

## 🔄 **Data Flow - Encoding Pipeline**

```
INPUT FILE (secret.pdf)
    │
    │  1. READ
    ▼
┌──────────────────────────────────────────┐
│  FILE BYTES (original_data)              │
│  Size: N bytes                           │
└──────────────────────────────────────────┘
    │
    │  2. COMPRESS (zlib level 9)
    ▼
┌──────────────────────────────────────────┐
│  COMPRESSED DATA                         │
│  Size: ~0.7N bytes (typical)             │
└──────────────────────────────────────────┘
    │
    │  3. ENCRYPT (AES-256-GCM + Argon2id)
    ▼
┌──────────────────────────────────────────┐
│  CIPHERTEXT                              │
│  Size: ~0.7N bytes                       │
│  + Nonce (12B)                           │
│  + GCM Tag (16B)                         │
└──────────────────────────────────────────┘
    │
    │  4. FOUNTAIN ENCODE (Luby Transform)
    ▼
┌──────────────────────────────────────────┐
│  FOUNTAIN DROPLETS (kibbles)             │
│  Count: K blocks × 1.5 redundancy        │
│  Each: block_size bytes                  │
└──────────────────────────────────────────┘
    │
    │  5. QR ENCODE (per droplet)
    ▼
┌──────────────────────────────────────────┐
│  QR CODE FRAMES (paw prints)             │
│  Count: K × 1.5 frames                   │
│  Each: 600×600 pixels                    │
└──────────────────────────────────────────┘
    │
    │  6. GIF CREATION
    ▼
┌──────────────────────────────────────────┐
│  ANIMATED GIF (yarn ball)                │
│  Frames: K × 1.5                         │
│  FPS: 10                                 │
│  Size: ~10 MB (for 1 MB input)          │
└──────────────────────────────────────────┘
    │
    │  7. DISPLAY (optical transfer)
    ▼
OUTPUT GIF (secret.gif)
```

---

## 🔄 **Data Flow - Decoding Pipeline**

```
INPUT GIF (secret.gif)
    │
    │  1. GIF PARSE
    ▼
┌──────────────────────────────────────────┐
│  GIF FRAMES (extracted)                  │
│  Count: K × 1.5 frames                   │
└──────────────────────────────────────────┘
    │
    │  2. QR DECODE (each frame)
    ▼
┌──────────────────────────────────────────┐
│  QR DATA (droplets)                      │
│  Frame 0: Manifest (collar tag)          │
│  Frame 1+: Fountain droplets             │
└──────────────────────────────────────────┘
    │
    │  3. FOUNTAIN DECODE (belief propagation)
    ▼
┌──────────────────────────────────────────┐
│  RECONSTRUCTED CIPHERTEXT                │
│  Size: ~0.7N bytes                       │
└──────────────────────────────────────────┘
    │
    │  4. DECRYPT (AES-256-GCM + verify HMAC)
    ▼
┌──────────────────────────────────────────┐
│  COMPRESSED DATA                         │
│  Size: ~0.7N bytes                       │
└──────────────────────────────────────────┘
    │
    │  5. DECOMPRESS (zlib)
    ▼
┌──────────────────────────────────────────┐
│  ORIGINAL DATA                           │
│  Size: N bytes                           │
└──────────────────────────────────────────┘
    │
    │  6. VERIFY (SHA-256 check)
    ▼
OUTPUT FILE (secret.pdf)
```

---

## 🧩 **Component Architecture**

```
┌───────────────────────────────────────────────────────────────────┐
│                        MEOW DECODER MODULES                       │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   CONFIG    │  │   CRYPTO    │  │  FOUNTAIN   │             │
│  │             │  │             │  │             │             │
│  │ • Settings  │  │ • AES-GCM   │  │ • Encoder   │             │
│  │ • Presets   │  │ • Argon2id  │  │ • Decoder   │             │
│  │ • Validate  │  │ • HMAC      │  │ • Soliton   │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                                                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   QR CODE   │  │  GIF HANDLER│  │  CAT UTILS  │             │
│  │             │  │             │  │             │             │
│  │ • Generate  │  │ • Create    │  │ • Sounds    │             │
│  │ • Read      │  │ • Parse     │  │ • Facts     │             │
│  │ • Webcam    │  │ • Optimize  │  │ • Progress  │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                                                                   │
│  ┌─────────────────────────────────────────────────┐            │
│  │           SECURITY ENHANCEMENTS                 │            │
│  │                                                 │            │
│  │  • Forward Secrecy (MEOW3)                     │            │
│  │  • Post-Quantum (MEOW4)                        │            │
│  │  • Steganography (Ninja Cat)                   │            │
│  │  • Streaming Crypto (Prowling)                 │            │
│  │  • Resume Support                              │            │
│  └─────────────────────────────────────────────────┘            │
│                                                                   │
│  ┌─────────────────────────────────────────────────┐            │
│  │              USER INTERFACES                    │            │
│  │                                                 │            │
│  │  • encode.py (CLI encoder)                     │            │
│  │  • decode_gif.py (CLI decoder + --tamper-report)│            │
│  │  • decode_webcam.py (webcam capture)           │            │
│  │  • meow_dashboard.py (GUI)                     │            │
│  └─────────────────────────────────────────────────┘            │
│                                                                   │
│  ┌─────────────────────────────────────────────────┐            │
│  │              SUPPORT MODULES                    │            │
│  │                                                 │            │
│  │  • canonical_aad.py (deterministic AAD)        │            │
│  │  • tamper_report.py (frame MAC timeline)       │            │
│  │  • mobile/bridge/protocol.py (phone bridge)    │            │
│  └─────────────────────────────────────────────────┘            │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

---

## 🔐 **Security Layers**

```
┌──────────────────────────────────────────────────────────┐
│                   SECURITY ONION                         │
│              (Defense in Depth - 7 Layers)               │
└──────────────────────────────────────────────────────────┘

Layer 7: Air-Gap (optical transfer, no network)
           ↑
Layer 6: Steganography (optional, hides presence)
           ↑
Layer 5: Forward Secrecy (per-block keys, ratcheting)
           ↑
Layer 4: Encryption (AES-256-GCM)
           ↑
Layer 3: Authentication (HMAC-SHA256)
           ↑
Layer 2: KDF (Argon2id, memory-hard)
           ↑
Layer 1: Strong Password + Optional Keyfile (2FA)

┌──────────────────────────────────────────────────────────┐
│  Attack Surface: Minimal (endpoint only)                 │
└──────────────────────────────────────────────────────────┘
```

---

## 🔒 **Cryptographic Architecture**

### **MEOW2: Base Encryption**

```
PASSWORD + SALT
    │
    │  Argon2id (47 MB, 2 iter)
    ▼
256-bit MASTER KEY
    │
    ├─────────────────┬─────────────────┐
    │                 │                 │
    ▼                 ▼                 ▼
AES-256-GCM      HMAC Key         (unused)
Encryption       (manifest        
                 auth)            
```

### **MEOW3: Forward Secrecy**

```
PASSWORD + SALT
    │
    │  Argon2id
    ▼
MASTER KEY
    │
    │  HKDF
    ▼
INITIAL CHAIN KEY
    │
    ├──▶ Block 0 Key ──▶ Encrypt Block 0
    │         │
    │         │  HKDF (ratchet)
    │         ▼
    ├──▶ Block 1 Key ──▶ Encrypt Block 1
    │         │
    │         │  HKDF (ratchet)
    │         ▼
    └──▶ Block 2 Key ──▶ Encrypt Block 2
          ...

(Each block key is independent!)
```

### **MEOW4: Post-Quantum Hybrid**

```
PASSWORD + SALT
    │
    │  Argon2id
    ▼
MASTER KEY
    │
    ├───────────────┬────────────────┐
    │               │                │
    ▼               ▼                ▼
Generate        Generate         Generate
X25519          ML-KEM-1024      HKDF Keys
Keypair         Keypair
    │               │
    │  ECDH         │  KEM Encap
    ▼               ▼
Classical     Quantum
Shared (32B)  Shared (32B)
    │               │
    └───────┬───────┘
            │  XOR + HKDF
            ▼
    HYBRID SHARED SECRET
            │
            ▼
    AES-256-GCM Key
```

---

## 🌊 **Fountain Code Architecture**

```
┌────────────────────────────────────────────────────┐
│            LUBY TRANSFORM FOUNTAIN                 │
└────────────────────────────────────────────────────┘

ENCODING:
                                                                           
Input Data (N bytes)                                                      
    │                                                                     
    │  Split into K blocks                                               
    ▼                                                                     
┌────┬────┬────┬────┬────┬────┐                                         
│ B0 │ B1 │ B2 │ B3 │ B4 │ B5 │  K blocks                               
└────┴────┴────┴────┴────┴────┘                                         
  │    │    │    │    │    │                                             
  └──┬─┴──┬─┴──┬─┴──┬─┴──┬─┘                                            
     │    │    │    │    │                                               
     │  Robust Soliton Distribution                                      
     │  (determines degree d)                                            
     ▼                                                                    
┌──────────────────────────────┐                                         
│   SELECT d random blocks      │                                         
│   XOR them together           │                                         
└──────────────────────────────┘                                         
     │                                                                    
     ▼                                                                    
  DROPLET (can reconstruct infinite!)                                    

DECODING (Belief Propagation):

Collect droplets until K blocks solved
    │
    ▼
┌────────────────────────────────────┐
│  DEGREE 1 DROPLETS                │
│  (single block)                   │
│  → Immediately solved!            │
└────────────────────────────────────┘
    │
    ▼
┌────────────────────────────────────┐
│  DEGREE 2+ DROPLETS               │
│  (multiple blocks)                │
│  → XOR out solved blocks          │
│  → May become degree 1            │
│  → Cascade solving!               │
└────────────────────────────────────┘
    │
    ▼
ALL K BLOCKS SOLVED → SUCCESS!
```

---

## 📊 **Module Dependencies**

```
┌──────────────┐
│  encode.py   │
└──────┬───────┘
       │
       ├──▶ config.py (load settings)
       ├──▶ crypto.py (encrypt)
       ├──▶ fountain.py (encode)
       ├──▶ qr_code.py (generate QR)
       ├──▶ gif_handler.py (create GIF)
       └──▶ cat_utils.py (fun features)

┌──────────────┐
│ decode_gif.py│
└──────┬───────┘
       │
       ├──▶ config.py (load settings)
       ├──▶ crypto.py (decrypt)
       ├──▶ fountain.py (decode)
       ├──▶ qr_code.py (read QR)
       ├──▶ gif_handler.py (parse GIF)
       └──▶ cat_utils.py (fun features)

┌───────────────────┐
│ meow_dashboard.py │ (GUI)
└────────┬──────────┘
         │
         ├──▶ dearpygui (UI framework)
         ├──▶ encode.py (background threads)
         ├──▶ decode_gif.py (background threads)
         └──▶ cat_utils.py (progress, sounds)

SECURITY MODULES (optional):
├──▶ forward_secrecy.py (MEOW3)
├──▶ pq_crypto_real.py (MEOW4)
├──▶ ninja_cat_ultra.py (steganography)
├──▶ prowling_mode.py (low-memory)
└──▶ resume_secured.py (resume support)
```

---

## 🔄 **State Machine - Encoding**

```
[IDLE]
  │
  │  encode.py --input file.pdf
  ▼
[READING FILE]
  │
  │  Success
  ▼
[COMPRESSING]
  │
  │  zlib compress
  ▼
[ENCRYPTING]
  │
  │  AES-GCM encrypt
  ▼
[FOUNTAIN ENCODING]
  │
  │  Generate K×1.5 droplets
  ▼
[QR GENERATION]
  │
  │  Create QR for each droplet
  ▼
[GIF CREATION]
  │
  │  Combine frames into GIF
  ▼
[WRITING OUTPUT]
  │
  │  Save secret.gif
  ▼
[COMPLETE] ✅
  │
  │  (Optional: wipe source)
  ▼
[DONE]
```

---

## 🔄 **State Machine - Decoding**

```
[IDLE]
  │
  │  decode_gif.py --input secret.gif
  ▼
[READING GIF]
  │
  │  Parse frames
  ▼
[QR DECODING]
  │
  │  Frame 0 → Manifest
  │  Frame 1+ → Droplets
  ▼
[MANIFEST VALIDATION]
  │
  │  Verify HMAC
  ▼
[FOUNTAIN DECODING]
  │
  │  Collect droplets
  │  Belief propagation
  ▼
[CHECKING COMPLETION]
  │
  ├─ All blocks solved? ─▶ [DECRYPTING]
  │                           │
  └─ Need more? ─▶ [QR DECODING]
                    (retry/continue)

[DECRYPTING]
  │
  │  AES-GCM decrypt
  ▼
[DECOMPRESSING]
  │
  │  zlib decompress
  ▼
[VERIFYING]
  │
  │  Check SHA-256
  ▼
[WRITING OUTPUT]
  │
  │  Save secret.pdf
  ▼
[COMPLETE] ✅
```

---

## 🎯 **Trust Boundaries**

```
┌─────────────────────────────────────────────────────────┐
│                    TRUSTED ZONE                         │
│                                                         │
│  • User's computer (sender/receiver)                   │
│  • Python interpreter                                  │
│  • Meow Decoder code                                   │
│  • Cryptography libraries                              │
│  • User's memory/disk                                  │
│                                                         │
└─────────────────────────────────────────────────────────┘
                         │
                         │  TRUST BOUNDARY
                         ▼
┌─────────────────────────────────────────────────────────┐
│                   UNTRUSTED ZONE                        │
│                                                         │
│  • Optical channel (screen → camera)                   │
│  • Anyone who can see the screen                       │
│  • Recorded video/photos                               │
│  • GIF file in transit                                 │
│                                                         │
└─────────────────────────────────────────────────────────┘

KEY INSIGHT: 
Even if attacker controls UNTRUSTED zone, they
cannot decrypt without password (cryptography).
```

---

## 📈 **Performance Characteristics**

```
┌──────────────────────────────────────────────────────┐
│              PERFORMANCE PROFILE                     │
│          (1 MB input file, typical setup)            │
└──────────────────────────────────────────────────────┘

ENCODING BREAKDOWN:
┌────────────────┬──────────┬──────────┐
│ Phase          │ Time     │ % Total  │
├────────────────┼──────────┼──────────┤
│ Read file      │  0.1s    │   1%     │
│ Compress       │  1.2s    │  14%     │
│ Encrypt        │  0.3s    │   4%     │
│ Fountain       │  2.1s    │  25%     │
│ QR generation  │  4.2s    │  49%     │ ← Bottleneck!
│ GIF creation   │  0.7s    │   8%     │
├────────────────┼──────────┼──────────┤
│ TOTAL          │  8.6s    │ 100%     │
└────────────────┴──────────┴──────────┘

DECODING BREAKDOWN:
┌────────────────┬──────────┬──────────┐
│ Phase          │ Time     │ % Total  │
├────────────────┼──────────┼──────────┤
│ Read GIF       │  0.5s    │  12%     │
│ QR decode      │  2.1s    │  50%     │ ← Bottleneck!
│ Fountain       │  0.8s    │  19%     │
│ Decrypt        │  0.3s    │   7%     │
│ Decompress     │  0.3s    │   7%     │
│ Verify SHA     │  0.2s    │   5%     │
├────────────────┼──────────┼──────────┤
│ TOTAL          │  4.2s    │ 100%     │
└────────────────┴──────────┴──────────┘

MEMORY USAGE:
┌────────────────┬────────────┐
│ Mode           │ Peak RAM   │
├────────────────┼────────────┤
│ Normal encode  │  ~200 MB   │
│ Normal decode  │  ~150 MB   │
│ Prowling mode  │   ~50 MB   │ ← Low-memory!
└────────────────┴────────────┘
```

---

## 🔍 **Attack Surface Analysis**

```
┌──────────────────────────────────────────────────────┐
│                ATTACK SURFACES                       │
└──────────────────────────────────────────────────────┘

1. INPUT VALIDATION
   ├─ File paths        [LOW RISK]
   ├─ Password input    [MEDIUM RISK - weak passwords]
   ├─ Keyfile format    [LOW RISK - validation in place]
   └─ Config files      [LOW RISK - JSON parsing]

2. CRYPTOGRAPHIC
   ├─ Key derivation    [LOW RISK - uses Argon2id]
   ├─ Encryption        [LOW RISK - uses cryptography lib]
   ├─ HMAC              [LOW RISK - constant-time compare]
   └─ Random generation [LOW RISK - uses secrets module]

3. DATA PROCESSING
   ├─ Compression       [LOW RISK - zlib is mature]
   ├─ QR encoding       [LOW RISK - qrcode lib]
   ├─ QR decoding       [MEDIUM RISK - pyzbar can crash on bad data]
   └─ GIF handling      [MEDIUM RISK - Pillow has had vulns]

4. DEPENDENCIES
   ├─ Python stdlib     [LOW RISK]
   ├─ cryptography      [LOW RISK - well-audited]
   ├─ Pillow            [MEDIUM RISK - monitor CVEs]
   ├─ opencv-python     [MEDIUM RISK - C++ code]
   └─ Third-party libs  [MEDIUM RISK - supply chain]

5. SIDE CHANNELS
   ├─ Timing            [HIGH RISK - Python not const-time]
   ├─ Power analysis    [HIGH RISK - no mitigation]
   ├─ EM emissions      [HIGH RISK - no mitigation]
   └─ Cache timing      [HIGH RISK - no mitigation]

6. OPERATIONAL
   ├─ Password entry    [HIGH RISK - keyloggers]
   ├─ Screen recording  [HIGH RISK - endpoint compromise]
   ├─ Memory forensics  [MEDIUM RISK - key zeroing helps]
   └─ Physical access   [HIGH RISK - rubber-hose]

OVERALL RISK: MEDIUM
(Depends heavily on endpoint security and password strength)
```

---

## 🎨 **Extension Points**

Want to add new features? Here are the extension points:

### **1. New Manifest Version (MEOW5)**
```python
# In crypto.py
MANIFEST_VERSION_5 = 0x05

def pack_manifest_v5(manifest: Manifest, extensions: dict) -> bytes:
    """Pack MEOW5 manifest with new features."""
    # Your code here
```

### **2. New Steganography Algorithm**
```python
# In ninja_cat_ultra.py
class SuperNinjaCat(NinjaCatUltra):
    """Even stealthier than ULTRA!"""
    
    def apply_quantum_stego(self, frame):
        # Your quantum stego code
```

### **3. New Cat Breed Preset**
```python
# In cat_utils.py
CAT_BREED_PRESETS[CatBreed.RAGDOLL] = {
    "stego_palette": "fluffy-cream",
    "success_message": "😻 Ragdoll says: So soft, so secure!",
    # Your preset
}
```

### **4. New GUI Tab**
```python
# In meow_dashboard.py
def _create_statistics_tab(self):
    """Add a statistics/analytics tab."""
    with dpg.tab(label="📊 Statistics"):
        # Your tab UI
```

---

## 🐾 **Cat-Themed Architecture Fun Facts**

1. **Hissing** (encryption) happens in `crypto.py` 🔐
2. **Purring** (decryption) also in `crypto.py` 😻
3. **Kibbles** (droplets) are dispensed by `fountain.py` 🍖
4. **Paw Prints** (QR codes) made by `qr_code.py` 🐾
5. **Yarn Balls** (GIFs) created by `gif_handler.py` 🧶
6. **Nine Lives** (forward secrecy) in `forward_secrecy.py` 🐱
7. **Quantum Nine Lives** (post-quantum) in `pq_crypto_real.py` 🔮
8. **Ninja Cat** (steganography) in `ninja_cat_ultra.py` 🥷
9. **Prowling** (low-memory) in `prowling_mode.py` 🐾
10. **Collar Tags** (manifests) in all the above! 🏷️

---

**🐾 "The architecture is like a cat: elegant, mysterious, and always lands on its feet!" 😺**

---

**Last Updated:** 2026-01-22  
**Version:** 1.0.0 (SECURITY-REVIEWED v1.0 INTERNAL REVIEW)  
**Status:** Production
