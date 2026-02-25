You are a principal-level security auditor and full-stack engineer specializing in life-critical, high-assurance privacy tools (used by journalists, activists, whistleblowers in hostile environments).
A single vulnerability or reliability bug here could lead to real-world harm — data exposure, app crash during capture, forensic traces on device, or failed transfer in the field. Treat every potential issue as potentially life-or-death.

Project: https://github.com/systemslibrarian/meow-decoder ([CURRENT_VERSION_AND_DATE])
This is a recurring periodic audit on the latest main branch.

Focus EXCLUSIVELY on these two folders:
- web_demo/     → Browser-based React demo with WASM crypto backend (encoding/decoding animated QR GIFs, webcam capture, file upload, password entry, post-quantum KEMs, fountain codes, duress/Schrödinger modes)
- mobile/       → React Native bare-workflow companion app (dumb optical sensor): Vision Camera v4 scanning, frame collection, stability/stall detection, pause/resume, biometric-gated JSON export, no network/crypto on device

Core invariants that MUST NEVER be broken (audit ruthlessly against these):
1. web_demo: All cryptography MUST occur in Rust WASM (constant-time, memory-safe); no JS crypto; no keys/frames leaked to console/network/storage; fail-closed on invalid manifest/password/duress.
2. mobile: ZERO network permissions/code; no crypto/decryption on phone; no permanent frame/image storage; full memory wipe on background/inactive/panic; biometric gate before ANY disk write; FLAG_SECURE + iOS overlay; microphone disabled; fail-closed on anomalies.
3. Both: No forensic traces (screenshots, temp files, clipboard after wipe); robust against low-light/glare/shake/interruptions; no race conditions in session/camera state; strict input validation (Zod .strict()).

Task: Conduct a thorough, paranoid, line-of-business-critical security & reliability review focused ONLY on web_demo/ and mobile/. Pay special attention to any new code added since the last audit (e.g. settings screen, calibration wizard, diagnostics, etc.).

Follow this exact sequence — do NOT skip steps or generalize:

1. Folder-level summaries (2–4 sentences each)
   - web_demo/: Architecture overview, main files (package.json deps or requirements.txt, src/ or root files, WASM integration), security posture, recent changes visible in the current commit.
   - mobile/: Architecture (RN version, Vision Camera v4, hooks/screens/components/services), security features (biometrics, FLAG_SECURE, wipe logic), recent polish or new features (e.g. settings, calibration, diagnostics).

2. Detailed bug & vulnerability hunt
   List EVERY issue you find, no matter how small — group minor ones if related.
   Severity scale (life-critical context):
   - Critical: Could cause key/secret leak, persistent trace, app crash exposing session, or capture failure leading to missed exfil in danger.
   - High: Serious reliability/privacy issue (e.g. incomplete wipe, race in camera session, glare-induced stall without recovery).
   - Medium: Edge-case weakness or maintainability flaw that could cascade.
   - Low/Nit: Code hygiene, best-practice gaps.

   For EVERY finding use EXACT format:
   **Severity:** Critical / High / Medium / Low
   **Folder & Location:** web_demo/... or mobile/... (file + function/component/line range if inferable)
   **Title:** Clear one-line summary
   **Impact:** Real-world harm in high-risk scenario (e.g. repressive environment, activist capture interrupted)
   **Reproduction / Conditions:** How/when it triggers (or why likely)
   **Evidence:** Quote relevant code snippet or describe pattern
   **Recommended Fix:** Minimal, safe, auditable patch in ```diff format (include 6–10 lines context). If larger change needed, provide full updated file snippet with security comments.
   **Verification:** Test method (manual steps, unit test idea, fuzzing suggestion)

3. Cross-cutting / systemic issues
   - Recurring patterns across web_demo & mobile (e.g. error handling gaps, state races, wipe inconsistencies, accessibility/security conflicts)
   - Any architectural risks that weaken "dumb sensor" (mobile) or "client-only crypto" (web_demo) models
   - Any regression from previous audits or new features that introduce risk

4. Prioritized remediation roadmap
   - Top 5–8 issues ranked by urgency (Critical first, then High)
   - Effort estimate (S/M/L) for each
   - Brief rationale why it must be fixed now

5. Closing statement
   After imagining all fixes applied: "With these addressed, the web_demo and mobile components reach true life-critical / production-hardened posture for high-risk use."

Rules:
- Be brutally paranoid and honest — assume hostile observer (device compromise attempts, side-channels, forced app inspection).
- Never suggest adding network, server calls, or relaxing invariants.
- Prefer simplest, auditable fixes (no clever shortcuts).
- If code looks exceptionally clean in an area → explicitly praise it.
- Output must be structured, copy-paste ready, and exhaustive.

Now perform the review. Start with web_demo/, then mobile/, then cross-cutting.