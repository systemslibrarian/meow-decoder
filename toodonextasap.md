# To Do Next ASAP

Snapshot of what's queued to ship the iOS app and the few things that
still need a human at a keyboard. Update / strike through as items land.

Last updated: 2026-05-06.

---

## Hot path — first iOS build to TestFlight

Everything below the line is needed to get from `da7c8a2` (current head)
to "build available in TestFlight." Items are ordered. The starred ones
are blocking next steps.

1. **★ Generate App Store Connect API key** *(you, ~2 min, web UI only — Apple has no API for this bootstrap step)*
   - https://appstoreconnect.apple.com → **Users and Access** → **Integrations** → **App Store Connect API** → **Generate API Key**
   - Name: `Meow Decoder CI`. Access: **App Manager**.
   - Download the `.p8`. Save the **Key ID** (10 chars) and **Issuer ID** (UUID).
   - Note the **Team ID** from https://developer.apple.com/account → Membership.

2. **★ Upload `.p8` into the dev container** *(you, drag-and-drop)*
   ```bash
   mkdir -p /home/vscode/.private_keys
   chmod 700 /home/vscode/.private_keys
   # Drop AuthKey_<KEYID>.p8 into the dir, then:
   chmod 600 /home/vscode/.private_keys/AuthKey_<KEYID>.p8
   ```

3. **★ Paste me the three non-secret IDs in chat** *(you)*
   - Key ID, Issuer ID, Team ID. None are sensitive without the `.p8`.

4. **Run the bootstrap** *(me, one command)*
   ```bash
   export ASC_KEY_ID=...
   export ASC_ISSUER_ID=...
   export APPLE_TEAM_ID=...
   export ASC_PRIVATE_KEY_PATH=/home/vscode/.private_keys/AuthKey_<KEYID>.p8
   python3 mobile-ios/scripts/bootstrap-apple.py --set-secrets
   ```
   This registers the bundle ID, mints a Distribution cert, creates the
   App Store provisioning profile, and pushes seven CI secrets via
   `gh secret set`. Output: `apple-bootstrap-out/` (gitignored, mode 0700).

5. **Create the App Store Connect "App" record** *(you, ~30 sec, web UI — Apple has no API for this either)*
   - https://appstoreconnect.apple.com → My Apps → **+** → New App
   - Bundle ID: `com.systemslibrarian.meowdecoder`
   - Name: *Meow Decoder*. Primary language: English. SKU: `meow-decoder-ios-001`.

6. **Push the local commits** *(me, one command — needs your go-ahead)*
   ```bash
   git push origin main
   ```
   Currently `da7c8a2` (and the follow-up TODO commit) are local-only.

7. **Tag and fire the CI workflow** *(me, one command)*
   ```bash
   git tag v0.1.0-ios && git push origin v0.1.0-ios
   ```
   Workflow: `.github/workflows/ios-release.yml`. Runs ~10–15 min on
   `macos-26`, then Apple processes the build for 5–30 min.

8. **TestFlight setup** *(you, one-time, web UI)*
   - https://appstoreconnect.apple.com → My Apps → Meow Decoder → TestFlight
   - Add yourself as an Internal Tester
   - Install TestFlight on your iPhone, accept the invite, install the build

---

## Pre-public-App-Store (not blocking TestFlight)

These don't gate TestFlight but matter before the public App Store
listing goes live.

- [ ] **Final marketing icon.** `mobile-ios/resources/icon.png` is the
      auto-padded `assets/meow-decoder-logo.png`. Once a real square
      1024×1024 marketing icon exists, drop it in and re-run `cap:icons`.
- [ ] **Privacy policy URL.** Apple requires one even when you collect
      nothing. Easiest: a one-page GitHub Pages doc off this repo. Could
      reuse `docs/SECURITY.md` framing.
- [ ] **Store-listing screenshots** at 6.7" iPhone (1290×2796) and 12.9"
      iPad Pro (2048×2732). Capture from a simulator inside Xcode after
      a TestFlight build runs.
- [ ] **Review notes** in the App Store Connect submission. Reviewers
      bounce air-gap apps that they can't tell how to exercise — point
      them at the in-app self-test or a sample file.
- [ ] **Export compliance**: pick per-submission declaration vs. annual
      BIS self-classification report. See STORES.md "Export compliance".
- [ ] **Bundle trim.** `dist/` is currently ~43 MB (mostly `CatVideo.mp4`
      + demo gifs). If cellular-download limits matter, prune to a
      referenced-only asset set in `scripts/build-web.sh`.

---

## iOS receiver track (deferred — separate project)

The Capacitor app shipping above is the **sender / desktop-mirror** side
(encode + display QR + WASM round-trip). The **receiver** (camera scan)
lives at `mobile/` as a React Native app and is currently Android-only.
For an iOS receiver, two paths:

- **Finish the existing RN iOS scaffold** under `mobile/ios/` (currently
  only `Info.plist` + `MeowCrypto.swift` — needs `Podfile`, `xcodeproj`,
  `AppDelegate`, native module bridges for VisionCamera + biometrics).
  Largest amount of new native work.
- **Build a separate Capacitor receiver** that uses
  `@capacitor/camera` + a web-based QR scanner (jsQR is already in the
  repo). Faster, but iOS WKWebView's camera throughput is lower than
  VisionCamera; capture-quality coach features (FPS, exposure control)
  would need re-implementation.

Don't pursue this until the sender ships and you've run the full
TestFlight loop end-to-end.

---

## Roadmap items still open (from `docs/ROADMAP.md`)

These are inherited, not new — captured here so the roadmap doesn't get
forgotten while iOS work happens.

- [ ] Formal verification (Verus/Coq, CI-gated) — Phase 7 of security roadmap
- [ ] Professional third-party security audit — Phase 10 (in-house
      readiness package landed: `docs/AUDIT_READINESS.md`; blocked only
      on engaging a firm)
- [ ] Public CVE disclosure workflow / `SECURITY.md` PoC harness
- [ ] FIPS 140-3 / Common Criteria — demand-gated, not active

---

## Bookkeeping

- The `cipher-mix-main.zip` checked in at `da7c8a2`'s parent (`88b8632`)
  is the reference scaffold we built `mobile-ios/` from. Safe to delete
  from the repo at any time — it's no longer load-bearing. Suggested:
  delete after the first successful TestFlight build, so the reference
  is preserved while the pipeline is unproven.
- Local Claude Code state (`/.claude/settings.local.json`,
  `.claude/scheduled_tasks.lock`) is gitignored as of this commit.
