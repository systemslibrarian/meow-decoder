# 🚀 5-Minute Quickstart - Phone Capture Demo

**Goal:** See Meow Decoder work in 5 minutes  
**What you'll do:** Encode → Capture → Decode  
**Equipment needed:** Computer + phone camera

---

## ⚡ What You'll Learn

In 5 minutes you'll:
1. Encrypt a file to animated QR GIF (30 sec)
2. Capture the GIF with your phone (30 sec)
3. Transfer video to computer (1 min)
4. Decode back to original file (30 sec)

**Total time:** 3-5 minutes ⏱️

---

## 📋 Prerequisites

**Required:**
- Python 3.10+ installed
- Phone with camera
- Way to transfer files (AirDrop, email, USB, etc.)

**Install Meow Decoder:**
```bash
pip install meow-decoder

# Or from source:
git clone https://github.com/YOUR_USERNAME/meow-decoder.git
cd meow-decoder
pip install -e .
```

---

## 🎯 Step-by-Step Demo

### Level 0: Instant Recovery (Optional)

Don't want to record a video right now? We included a sample GIF for you!

1. **Locate the demo file**: `assets/demo.gif` included in this repo.
2. **Decode it immediately**:
   ```bash
   meow-decode-gif -i assets/demo.gif -o recovered_demo.txt -p "demo123"
   ```
3. **Success!** You should see "The cat is out of the bag!" in `recovered_demo.txt`.

### Step 1: Create a Test File (10 seconds)

```bash
# Create a secret message
echo "Top Secret: The cat is out of the bag! 🐱" > secret.txt

# Verify it
cat secret.txt
# Should show: Top Secret: The cat is out of the bag! 🐱
```

---

### Step 2: Encode to QR GIF (30 seconds)

```bash
# Encrypt and encode to animated GIF
meow-encode -i secret.txt -o secret.gif -p "demo123"
```

**You should see:**
```
🐱 Encoding secret.txt...
✅ Encrypted (AES-256-GCM)
✅ Fountain coded (12 droplets needed)
✅ Generated 18 QR frames (1.5x redundancy)
✅ Saved to secret.gif

File size: 4.2 KB
Password: demo123 (remember this!)
```

**Now open the GIF:**
```bash
# Mac
open secret.gif

# Linux
xdg-open secret.gif

# Windows
start secret.gif
```

**What you should see:**
- Animated GIF with QR codes
- Looping continuously
- Each frame shows a different QR code

**💡 Tip:** Make it full-screen (F11 in most browsers/viewers)

---

### Step 3: Capture with Your Phone (30 seconds)

Now for the fun part - use your phone as a camera!

**Instructions:**

1. **Open camera app** on your phone
   - Standard camera app is fine
   - No special QR scanner needed

2. **Start video recording**
   - Point at the screen showing the GIF
   - Hold phone ~2-3 feet away
   - Landscape or portrait both work

3. **Record for 10-15 seconds**
   - The GIF will loop several times
   - No need to be perfectly steady
   - No need to time it precisely

4. **Stop recording**

**Tips for best results:**
- ✅ Hold phone reasonably steady (but doesn't need to be perfect)
- ✅ Make sure screen brightness is high
- ✅ 2-3 feet distance works best
- ✅ Make GIF full-screen if possible
- ❌ Don't need to scan each QR individually
- ❌ Don't need precision - redundancy helps!

**What your video should look like:**
- 10-30 second video
- Shows looping QR codes
- Might be slightly blurry (that's OK!)

---

### Step 4: Transfer Video to Computer (1 minute)

**Choose your method:**

#### Mac + iPhone (AirDrop - easiest)
1. On iPhone: Open Photos app
2. Select the video you just recorded
3. Tap Share → AirDrop
4. Select your Mac
5. Video appears in Downloads

#### Windows + Android (Several options)
**Option A - USB Cable:**
1. Connect phone to computer
2. Open phone in File Explorer
3. Navigate to DCIM/Camera
4. Copy video to computer

**Option B - Email:**
1. Email video to yourself
2. Download from email on computer

**Option C - Cloud:**
1. Upload to Google Drive/Dropbox
2. Download on computer

#### Linux
- USB cable + file manager
- KDE Connect
- Email/cloud

**Result:** You now have the video file on your computer (e.g., `captured.mp4`)

---

### Step 5: Decode from Video (30 seconds)

```bash
# Decode from the video you captured
meow-decode-gif -i captured.mp4 -o recovered.txt -p "demo123"
```

**You should see:**
```
🐱 Decoding captured.mp4...
📱 Extracting frames from video...
   Found 180 frames (10 seconds @ 18 fps)
🔍 Scanning for QR codes...
   Found 15 QR frames
✅ Decoded fountain codes (15/12 droplets = 125% redundancy)
🔓 Decrypting with password...
✅ Authenticated and verified
✅ Saved to recovered.txt

Original hash: a3f5e2d8...
Recovered hash: a3f5e2d8...
✅ Integrity verified!
```

**Verify it worked:**
```bash
cat recovered.txt
# Should show: Top Secret: The cat is out of the bag! 🐱

# Compare with original
diff secret.txt recovered.txt
# Should show: (no output = files are identical)
```

---

## ✅ Success!

**You just:**
- ✅ Encrypted a file with AES-256-GCM
- ✅ Encoded it into fountain codes + QR codes
- ✅ Transferred it through an air gap (via phone camera!)
- ✅ Decoded and verified integrity
- ✅ Got your original file back perfectly

**Total time:** ~5 minutes ⏱️

---

## 🎯 Try It With Your Own Files

Now try with your own files:

```bash
# Any file type works
meow-encode -i photo.jpg -o photo.gif -p "your-secure-password"

# Larger files = more QR frames
meow-encode -i document.pdf -o document.gif -p "long-and-complex-password"

# Use a keyfile for extra security
meow-encode -i secrets.txt -o secrets.gif -p "password" --keyfile keyfile.key
```

---

## 🐛 Troubleshooting

### Problem: QR codes too small on screen

**Solution:**
- Make GIF full-screen (F11 in browser)
- Zoom in (Ctrl/Cmd + Plus)
- Use larger monitor if available

### Problem: Phone can't capture all frames

**Solution:**
- Record for longer (20-30 seconds instead of 10)
- Fountain codes are redundant - you don't need ALL frames
- Try from 2-3 feet away

### Problem: Decoding fails with "Not enough droplets"

**Solution:**
- Record longer video (more frames captured)
- Hold phone steadier
- Increase screen brightness
- Try from photos: `meow-decode-gif -i photos-directory/`

### Problem: Video file too large to transfer

**Solution:**
- Compress video (video is encrypted - safe to compress)
- Use lower resolution when recording
- Remember: Video itself is encrypted garbage without password

### Problem: Wrong password error

**Solution:**
- Double-check password (case-sensitive!)
- If you used `--keyfile`, you need it for decoding too:
  ```bash
  meow-decode-gif -i captured.mp4 -o output.txt -p "password" --keyfile keyfile.key
  ```

### Problem: "No QR codes found"

**Solution:**
- Video might be too blurry
- Try burst photos instead: Take 20-30 photos while GIF loops
- Decode from photos: `meow-decode-gif -i photos/`
- Make sure screen brightness is high

---

## 💡 Pro Tips

### Tip 1: Use Strong Passwords

```bash
# Weak (don't use)
meow-encode -i file.txt -o file.gif -p "password"

# Strong (better)
meow-encode -i file.txt -o file.gif -p "Tr0ub4dor&3_But_Longer_Is_Better"

# Strongest (recommended)
# Use a passphrase: 4-5 random words
meow-encode -i file.txt -o file.gif -p "correct horse battery staple meow"
```

### Tip 2: Adjust Redundancy for Reliability

```bash
# Default: 1.5x redundancy (50% extra frames)
meow-encode -i file.txt -o file.gif -p "pass"

# Lower redundancy (smaller GIF, needs more precision)
meow-encode -i file.txt -o file.gif -p "pass" --redundancy 1.2

# Higher redundancy (larger GIF, more reliable)
meow-encode -i file.txt -o file.gif -p "pass" --redundancy 2.0
```

### Tip 3: Forward Secrecy for Extra Protection

```bash
# Generate receiver keypair (one-time setup)
python -c "from meow_decoder.x25519_forward_secrecy import X25519KeyPair; kp = X25519KeyPair.generate(); print(f'Public: {kp.public_key_b64()}'); kp.save_to_file('receiver.key')"

# Sender encrypts with receiver's public key
meow-encode -i file.txt -o file.gif -p "pass" --forward-secrecy --receiver-key "PUBLIC_KEY_HERE"

# Receiver decrypts with their private key
meow-decode-gif -i captured.mp4 -o file.txt -p "pass" --receiver-key-file receiver.key
```

### Tip 4: Test Before You Need It

```bash
# Always test your workflow before relying on it:
# 1. Encode test file
# 2. Capture with phone
# 3. Decode on different computer
# 4. Verify file matches

# This helps you:
# - Find optimal distance/brightness
# - Practice the workflow
# - Verify your equipment works
```

---

## 🎓 What's Happening Under the Hood?

### Encoding (meow-encode)
1. **Compression:** File is compressed with zlib
2. **Encryption:** AES-256-GCM with Argon2id key derivation
3. **Fountain Coding:** Data split into redundant chunks (LT codes)
4. **QR Generation:** Each chunk becomes a QR code
5. **GIF Creation:** QR codes assembled into animated GIF

### Decoding (meow-decode-gif)
1. **Frame Extraction:** Video/GIF split into frames
2. **QR Scanning:** Each frame decoded to recover chunks
3. **Fountain Decoding:** Redundant chunks reassembled (belief propagation)
4. **Decryption:** AES-256-GCM decryption with your password
5. **Verification:** Hash checked, file decompressed

**Security Properties:**
- ✅ Password never stored (only derived key)
- ✅ Unique nonce per encryption (prevents replay)
- ✅ HMAC authentication (detects tampering)
- ✅ Frame MACs (prevents frame injection)
- ✅ Fail-closed (errors caught, never output garbage)

---

## 📚 Next Steps

### Learn More
- Read [ARCHITECTURE.md](docs/ARCHITECTURE.md) for technical details
- Read [SECURITY.md](SECURITY.md) for threat model
- Read [SCHRODINGER.md](docs/SCHRODINGER.md) for plausible deniability

### Use Cases
- **Air-gapped transfer:** Move files between isolated networks
- **Paper backup:** Print QR codes for physical storage
- **Covert sharing:** Hide files in cat meme GIFs
- **Mobile sharing:** Share via messaging apps (encrypted!)

### Advanced Features
- **Schrödinger mode:** Dual-password plausible deniability
- **Decoy generation:** Automatic cover story files
- **Forward secrecy:** Ephemeral keys for future-proof security
- **Post-quantum:** Experimental quantum-resistant encryption

---

## ❓ FAQ

**Q: How large can files be?**  
A: Practical limit ~50 MB (QR codes become unwieldy above this). For larger files, split into chunks.

**Q: Is the phone recording secure?**  
A: Yes! The recording is encrypted garbage without the password. Safe to transfer via email/cloud.

**Q: Do I need internet?**  
A: No! Everything works offline. Perfect for air-gapped environments.

**Q: What if I lose some frames?**  
A: Fountain codes are redundant - you don't need ALL frames. Default 1.5x redundancy means you can lose 33% of frames.

**Q: Can I use this in production?**  
A: Core features (Tier 1) are production-ready. See [STABILITY_TIERS.md](docs/STABILITY_TIERS.md) for feature classification.

---

## ✅ Quickstart Complete!

You now know how to:
- ✅ Encode files to QR GIFs
- ✅ Capture with phone camera
- ✅ Decode back to original
- ✅ Troubleshoot common issues

**Ready to transfer real files?** Just replace `secret.txt` with your actual file and use a strong password!

---

**Need help?** Open an issue or check the docs:
- [README.md](README.md) - Full documentation
- [SECURITY.md](SECURITY.md) - Security model
- [STABILITY_TIERS.md](docs/STABILITY_TIERS.md) - Feature maturity

---

*Made with 🐱 by the Meow Decoder team*
