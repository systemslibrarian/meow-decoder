# Formal Verification Tool Setup

Instructions for installing and running the formal verification tools used by Meow-Decoder.

**Target environment:** Alpine Linux (musl) dev container, as shipped with this repo.
Some tools require workarounds for musl compatibility — these are documented below.

---

## Quick Status

| Tool | Version | Status | Notes |
|------|---------|--------|-------|
| **ProVerif** | 2.05 | ✅ Native | Built from source (OCaml) |
| **TLC (TLA+)** | 2.20 | ✅ Native | Java-based, runs everywhere |
| **Lean 4** | 4.5.0 | ⚠️ Partial | Binary works; Lake builds possible but Mathlib compilation is slow (no elan cache on musl) |
| **Tamarin** | 1.8.0 | ❌ Blocked | Binary runs, but Maude dependency fails on musl (missing glibc fortification symbols) |
| **Verus** | — | ❌ Blocked | Requires GNU Rust toolchain (`x86_64-unknown-linux-gnu`), incompatible with musl |

**Recommendation:** Run ProVerif and TLC natively. For Tamarin and Verus, use Docker or a glibc-based system (Ubuntu/Debian).

---

## 1. ProVerif (Cryptographic Protocol Verifier)

### Install

```bash
# Prerequisites
sudo apk add --no-cache ocaml ocaml-findlib make

# Build from source (v2.05)
cd /tmp
wget https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz
tar xzf proverif2.05.tar.gz
cd proverif2.05
./build -nointeract        # Skip interactive GUI (requires lablgtk2)
sudo cp proverif proveriftotex /usr/local/bin/
```

### Verify

```bash
proverif --help
# Expected: "Proverif 2.05. Cryptographic protocol verifier..."
```

### Run

```bash
cd /workspaces/meow-decoder
proverif formal/proverif/meow_encode.pv
```

**Expected output:** Secrecy queries (`not attacker(real_secret[])`, `not attacker(real_password[])`) should return `RESULT ... is true`.

> **Note:** Some correspondence queries (e.g., `EncoderEncrypted`, `EncoderStarted`) may return `false` — these are known modeling limitations, not security issues. See [todo-formal.md](todo-formal.md) item 2 for planned improvements.

---

## 2. TLC / TLA+ (Model Checker)

### Install

```bash
# Prerequisites
sudo apk add --no-cache openjdk17-jre

# Download TLA+ tools
mkdir -p ~/tla
wget -O ~/tla/tla2tools.jar \
  https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar

# Create wrapper script
sudo tee /usr/local/bin/tlc > /dev/null << 'EOF'
#!/bin/sh
exec java -cp "$HOME/tla/tla2tools.jar" tlc2.TLC "$@"
EOF
sudo chmod +x /usr/local/bin/tlc
```

### Verify

```bash
tlc 2>&1 | head -1
# Expected: "TLC2 Version 2.20..."
```

### Run

```bash
cd /workspaces/meow-decoder/formal/tla

# MeowEncode model (~1.8M states, ~2 min)
tlc -config MeowEncode.cfg MeowEncode.tla

# MeowFountain model (~44 states, instant)
tlc -config MeowFountain.cfg MeowFountain.tla
```

**Expected output:** `Model checking completed. No error has been found.`

---

## 3. Lean 4 + Lake (Theorem Prover)

Lean 4 runs on musl via gcompat, but requires several workarounds.

### Install

```bash
# Prerequisites
sudo apk add --no-cache gcompat zstd git

# Download and extract Lean 4.5.0
cd /tmp
wget https://github.com/leanprover/lean4/releases/download/v4.5.0/lean-4.5.0-linux.tar.zst
zstd -d lean-4.5.0-linux.tar.zst -o lean-4.5.0.tar
sudo mkdir -p /opt/lean
sudo tar xf lean-4.5.0.tar -C /opt/lean --strip-components=1

# IMPORTANT: Remove glibc-linked libz.so that conflicts with musl
sudo rm -f /opt/lean/lib/libz.so /opt/lean/lib/libz.so.*
sudo apk fix zlib   # Restore musl-native zlib

# Create lean wrapper (fixes --print-prefix on musl)
sudo tee /usr/local/bin/lean > /dev/null << 'WRAPPER'
#!/bin/sh
case "$1" in
  --print-prefix) echo "/opt/lean"; exit 0;;
esac
exec /opt/lean/bin/lean "$@"
WRAPPER
sudo chmod +x /usr/local/bin/lean

# Create lake wrapper
sudo tee /usr/local/bin/lake > /dev/null << 'WRAPPER'
#!/bin/sh
exec /opt/lean/bin/lake "$@"
WRAPPER
sudo chmod +x /usr/local/bin/lake

# Create /bin/lean symlink (Lake resolves lean via /proc/self/exe → /lib/ld-musl,
# computes prefix as "/" and looks for /bin/lean)
sudo ln -sf /usr/local/bin/lean /bin/lean

# Create /lib/lean symlink (same prefix issue — Lake looks for /lib/lean/)
sudo ln -sf /opt/lean/lib/lean /lib/lean
```

### Verify

```bash
lean --version
# Expected: "Lean (version 4.5.0, ...)"

lean --print-prefix
# Expected: "/opt/lean"

lake --version < /dev/null
# Expected: "Lake version 5.0.0-..."
```

### Build FountainCodes proofs

```bash
cd /workspaces/meow-decoder/formal/lean
lake build FountainCodes < /dev/null
```

> **Warning:** This builds Mathlib from source since elan (the Lean version manager) doesn't work on musl. First build may take 30–60+ minutes. Subsequent builds are cached.

### musl Compatibility Notes

| Issue | Root Cause | Workaround |
|-------|-----------|------------|
| `lean --print-prefix` returns empty | musl `/proc/self/exe` resolves to ld-musl linker path | Shell wrapper intercepts `--print-prefix` |
| Lake "could not detect configuration" | Same `/proc/self/exe` issue — Lake computes prefix as `/` | Symlinks at `/bin/lean` and `/lib/lean` |
| `libz.so` breaks curl/wget | Lean tarball includes glibc-linked libz.so | Remove it, restore musl zlib via `apk fix` |
| No Mathlib prebuilt cache | elan doesn't support musl | Build from source (slow first time) |

---

## 4. Tamarin Prover (Security Protocol Verification)

### Status: ❌ Blocked on musl

Tamarin 1.8.0 binary runs on musl via gcompat, but its required dependency **Maude** (rewriting logic engine) fails with missing glibc fortification symbols (`__mbsnrtowcs_chk`, `__wmemmove_chk`, etc.) that musl/gcompat cannot provide.

### Install (for reference — won't fully work on musl)

```bash
# Binary works, but Maude doesn't
wget -O /usr/local/bin/tamarin-prover \
  https://github.com/tamarin-prover/tamarin-prover/releases/download/1.8.0/tamarin-prover-1.8.0-linux64-ubuntu
chmod +x /usr/local/bin/tamarin-prover

# Tamarin --help works, but actual verification requires Maude
tamarin-prover --help   # OK
tamarin-prover formal/tamarin/MeowDuressEquiv.spthy   # FAILS (no Maude)
```

### Docker Alternative

```bash
# Use the official Tamarin Docker image
docker run --rm -v "$PWD":/workdir -w /workdir \
  tamarin-prover/tamarin-prover:1.8.0 \
  tamarin-prover --prove formal/tamarin/MeowDuressEquiv.spthy

# Or add to docker-compose.yml:
# tamarin:
#   image: tamarin-prover/tamarin-prover:1.8.0
#   volumes:
#     - .:/workdir
#   working_dir: /workdir
```

### Ubuntu/Debian (glibc) Install

```bash
# On Ubuntu 22.04+
sudo apt install maude tamarin-prover
# Or install binaries:
wget https://github.com/tamarin-prover/tamarin-prover/releases/download/1.8.0/tamarin-prover-1.8.0-linux64-ubuntu
sudo install tamarin-prover-1.8.0-linux64-ubuntu /usr/local/bin/tamarin-prover
```

### Run

```bash
tamarin-prover --prove formal/tamarin/MeowDuressEquiv.spthy
```

---

## 5. Verus (Rust Verification)

### Status: ❌ Blocked on musl

Verus requires the GNU Rust toolchain (`x86_64-unknown-linux-gnu`). On Alpine Linux (musl), the GNU toolchain's `librustc_driver` fails with missing symbols (`__res_init`).

### Ubuntu/Debian Install

```bash
# Install Rust nightly (GNU target)
rustup install nightly
rustup default nightly

# Clone and build Verus
git clone https://github.com/verus-lang/verus.git
cd verus/source
./tools/get-z3.sh   # Download Z3 solver
cargo build --release

# Run against meow-decoder proofs
./target/release/verus /path/to/meow-decoder/crypto_core/src/verus_kdf_proofs.rs
```

### Docker Alternative

```bash
# Build a Verus container from Ubuntu
docker run --rm -v "$PWD":/workdir -w /workdir \
  rust:latest bash -c '
    rustup install nightly && rustup default nightly &&
    git clone https://github.com/verus-lang/verus.git /tmp/verus &&
    cd /tmp/verus/source && ./tools/get-z3.sh && cargo build --release &&
    /tmp/verus/source/target/release/verus /workdir/crypto_core/src/verus_kdf_proofs.rs
  '
```

### Run

```bash
verus crypto_core/src/verus_kdf_proofs.rs
```

---

## Running All Verifications

### Available natively (Alpine/musl)

```bash
# ProVerif — protocol security properties
proverif formal/proverif/meow_encode.pv

# TLC — state machine model checking
cd formal/tla && tlc -config MeowEncode.cfg MeowEncode.tla
cd formal/tla && tlc -config MeowFountain.cfg MeowFountain.tla

# Lean 4 — fountain code correctness proofs (slow first build)
cd formal/lean && lake build FountainCodes < /dev/null
```

### Requires Docker or glibc system

```bash
# Tamarin — observational equivalence
docker run --rm -v "$PWD":/w -w /w tamarin-prover/tamarin-prover:1.8.0 \
  tamarin-prover --prove formal/tamarin/MeowDuressEquiv.spthy

# Verus — Rust KDF proofs
# (see Docker instructions above)
```

---

## Makefile Integration

Add to the project `Makefile`:

```makefile
.PHONY: formal-proverif formal-tlc formal-lean formal-all

formal-proverif:
	proverif formal/proverif/meow_encode.pv

formal-tlc:
	cd formal/tla && tlc -config MeowEncode.cfg MeowEncode.tla
	cd formal/tla && tlc -config MeowFountain.cfg MeowFountain.tla

formal-lean:
	cd formal/lean && lake build FountainCodes < /dev/null

formal-all: formal-proverif formal-tlc formal-lean
```

---

## Troubleshooting

### "could not detect the configuration of the Lake installation"
Ensure both symlinks exist:
```bash
ls -la /bin/lean        # Should → /usr/local/bin/lean
ls -la /lib/lean        # Should → /opt/lean/lib/lean
```

### curl/wget broken after Lean install
The Lean tarball includes a glibc-linked `libz.so` that overwrites the system one:
```bash
sudo rm -f /opt/lean/lib/libz.so /opt/lean/lib/libz.so.*
sudo apk fix zlib
```

### Lake build hangs
Always redirect stdin: `lake build < /dev/null`. Without this, Lake may wait for input on Alpine.

### ProVerif build fails on lablgtk2
Use `./build -nointeract` to skip the interactive GUI dependency.

### "No Maude binary found" (Tamarin)
Maude doesn't work on musl. Use Docker: `docker run --rm tamarin-prover/tamarin-prover:1.8.0 tamarin-prover --help`
