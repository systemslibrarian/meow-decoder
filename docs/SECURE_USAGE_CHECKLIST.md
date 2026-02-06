# 🐾 Secure Usage Checklist

> Operational security (OPSEC) guidance for using Meow Decoder safely.
> This is **not** a substitute for understanding your threat model — see [THREAT_MODEL.md](THREAT_MODEL.md).

---

## Before Encoding

- [ ] **Strong passphrase:** Use ≥6 diceware words or ≥20 random characters
- [ ] **Keyfile (recommended):** Generate with `dd if=/dev/urandom of=meow.key bs=32 count=1`
- [ ] **Close unnecessary apps:** Reduce risk of screen recording, clipboard sniffing, or keylogging
- [ ] **Disable cloud sync:** Ensure no iCloud / Google Drive / Dropbox syncs your working directory
- [ ] **Encrypted filesystem:** Work from an encrypted volume (LUKS, FileVault, BitLocker)
- [ ] **Swap disabled or encrypted:** `sudo swapoff -a` or use encrypted swap
- [ ] **No screenshots/screen recording:** Verify no screen capture tools are running

## During Encoding

- [ ] **Air-gapped machine (ideal):** Encode on a machine with no network connection
- [ ] **Verify backend:** Run `meow-encode --self-test` to confirm Rust backend is active
- [ ] **Forward secrecy ON:** Ensure `--no-forward-secrecy` is **not** used unless intentional
- [ ] **Check output path:** Don't write to a network share or cloud-synced folder
- [ ] **Duress password (optional):** Set with `--duress-password-prompt` for coercion resistance

## Transferring the GIF

- [ ] **Display on isolated screen:** Show GIF on a screen not connected to the internet
- [ ] **Camera distance:** Hold phone 15–30 cm from screen for optimal QR capture
- [ ] **No reflections:** Ensure no mirrors or cameras can see the screen
- [ ] **Verify frame count:** Check that the GIF has the expected number of frames
- [ ] **Delete after transfer:** Securely delete the GIF from the source machine

## During Decoding

- [ ] **Verify file integrity:** Compare SHA-256 hash of decoded output with original
- [ ] **Decode on trusted device:** Don't decode on a shared or compromised machine
- [ ] **Check for tampering:** Use `--tamper-report` to verify frame MAC integrity
- [ ] **Output to encrypted storage:** Write decoded files to encrypted volumes only

## After Use

- [ ] **Secure delete source files:** Use `shred -vfz -n 5 <file>` or `--wipe-source` flag
- [ ] **Secure delete GIF:** `shred -vfz -n 5 secret.gif`
- [ ] **Secure delete keyfile:** `shred -vfz -n 5 meow.key`
- [ ] **Clear clipboard:** `xclip -selection clipboard < /dev/null` or equivalent
- [ ] **Clear terminal history:** `history -c && history -w` or `unset HISTFILE`
- [ ] **Reboot (ideal):** Power cycle to clear RAM residue
- [ ] **Verify deletion:** `ls -la` to confirm files are gone from directory

## Common Mistakes to Avoid

| Mistake | Risk | Mitigation |
|---------|------|------------|
| Typing password on CLI (`-p "pass"`) | Visible in shell history, `ps aux` | Use interactive prompt (omit `-p`) |
| Encoding to cloud folder | Plaintext GIF synced to cloud | Use local-only directory |
| Leaving decoded file on disk | Unencrypted plaintext exposure | Shred immediately after use |
| Using short password | Brute-force in hours | ≥6 diceware words |
| Screen recording active | Entire session captured | Disable before starting |
| Decoding on shared WiFi | Network metadata exposure | Air-gap or VPN |
| Using `--no-forward-secrecy` | Missing key rotation, no PFS | Keep forward secrecy on |

## OS Hardening Recommendations

### Linux
```bash
# Disable swap
sudo swapoff -a

# Lock memory pages (prevents swap of key material)
# Add to /etc/security/limits.conf:
# * hard memlock unlimited

# Restrict ptrace (prevents memory dumping)
echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

### macOS
```bash
# Disable swap (not recommended for daily use)
sudo nvram boot-args="vm_compressor=2"

# Lock Keychain when sleeping
security set-keychain-settings -l
```

### Windows
```powershell
# Check pagefile encryption
fsutil behavior query encryptpagingfile

# Enable pagefile encryption
fsutil behavior set encryptpagingfile 1
```

## Camera Security

When capturing QR codes from a screen:

- **Phone camera only:** Use the built-in camera app or Meow Decoder's scanner
- **No cloud photo backup:** Disable Google Photos / iCloud Photos auto-upload
- **Delete captures:** Remove photos/videos of the GIF after decoding
- **Clean camera roll:** Verify no QR frame images remain in recently deleted

## Physical Security

- **Clean desk:** No sensitive documents visible during encoding/decoding
- **No observers:** Ensure no one can see your screen or keyboard
- **Sound isolation:** If using `--fun` cat sounds, use headphones
- **Shoulder surfing:** Face wall or use privacy screen filter

---

> 🐱 *"A careful cat always lands on its feet — and shreds the evidence." — The Cat*

## Related Documentation

- [THREAT_MODEL.md](THREAT_MODEL.md) — What Meow Decoder protects against
- [SECURITY.md](../SECURITY.md) — Vulnerability reporting (Catnip Bounty Program)
- [ARGON2ID_BENCHMARKS.md](ARGON2ID_BENCHMARKS.md) — Password strength tuning
- [QUICKSTART.md](../QUICKSTART.md) — Getting started guide
