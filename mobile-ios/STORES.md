# Releasing Meow Decoder iOS to TestFlight and the App Store

This is the macOS / Apple-portal half of shipping `mobile-ios/`. The Linux
side (Capacitor scaffold, web bundle build, GitHub Actions workflow) is
already wired up — the steps below are the credential and review work that
can only happen in a browser, in Xcode, or on App Store Connect.

The pattern mirrors the proven `cipher-mix` shipping path. If you've done
that one, this is the same flow with a different bundle ID.

Bundle ID: **`com.systemslibrarian.meowdecoder`** (permanent — once an
App Store Connect record accepts it, it can't be changed).

App display name: **Meow Decoder**.

---

## Two paths to choose from

There are two ways to produce the IPA. Pick one and stick with it for a
given release.

| Path | What runs | When to use |
|------|-----------|-------------|
| **CI** (recommended) | `.github/workflows/ios-release.yml` on a `macos-26` runner — triggered by tag `v*-ios` or manual dispatch | Every release after the first. Reproducible, hands-off, IPA archived as a workflow artifact. |
| **Local Xcode** | `npm run cap:sync:ios && npm run cap:open:ios` on your Mac, then **Product → Archive** | The first run, when you're verifying signing manually, or for a quick TestFlight push without pushing a tag. |

The CI path is the one this document is mostly about. The local path is
covered briefly at the end.

---

## Fast path — `bootstrap-apple.py`

If you have an Apple Developer account already, the script at
`mobile-ios/scripts/bootstrap-apple.py` collapses **most** of the manual
setup below into one command. It uses the App Store Connect API to:

- Register bundle ID `com.systemslibrarian.meowdecoder`
- Generate an RSA-2048 keypair + CSR locally
- Upload the CSR and download a fresh Apple Distribution certificate
- Bundle the key + cert into a `.p12` with a strong random password
- Create the App Store provisioning profile bound to the cert + bundle ID
- Emit (or `gh secret set`) the seven CI secrets

**Prerequisites** — these still need a one-time human web step:

1. **App Store Connect API key.** https://appstoreconnect.apple.com →
   *Users and Access* → *Integrations* → *App Store Connect API* →
   *Generate API Key*. Access role: **App Manager**. Download the `.p8`
   (one chance only) and note the **Key ID** + **Issuer ID**.
2. **Apple Team ID** from https://developer.apple.com/account → *Membership*.

**Run it:**

```bash
export ASC_KEY_ID=<your 10-char key ID>
export ASC_ISSUER_ID=<your issuer UUID>
export APPLE_TEAM_ID=<your 10-char team ID>
export ASC_PRIVATE_KEY_PATH=~/.private_keys/AuthKey_<KEYID>.p8
python3 mobile-ios/scripts/bootstrap-apple.py --set-secrets
```

The script writes everything to `apple-bootstrap-out/` (gitignored, mode
0700). If you omit `--set-secrets` it just emits a `summary.env` you can
review and push later with `gh secret set -f apple-bootstrap-out/summary.env`.

**One step the script can't do** (Apple has no public API for it):
*creating the App Store Connect "App" record.* You still do that once at
https://appstoreconnect.apple.com → *My Apps* → **+** → *New App* (~30
seconds — bundle ID `com.systemslibrarian.meowdecoder`, name *Meow
Decoder*, primary language English, SKU anything unique).

After the script runs and you create the App record:

```bash
git tag v0.1.0-ios && git push origin v0.1.0-ios
```

— and the workflow ships the build to TestFlight.

The manual walkthrough below is still here as the fallback if anything in
the script's API calls fails or you prefer the click path.

---

## Manual path — Apple Developer Portal clicks

You only do this once per app, ever.

### 1. Register the App ID

1. https://developer.apple.com/account → **Certificates, Identifiers & Profiles**.
2. **Identifiers** → **+** → **App IDs** → **App**.
3. Description: *Meow Decoder*. Bundle ID: **`com.systemslibrarian.meowdecoder`**.
4. Capabilities: none required for this app.
5. **Continue → Register**.

### 2. Create the Apple Distribution certificate

The cert says "this signing key is allowed to ship App Store builds for
your team." You only need one of these per team — if you already have an
*Apple Distribution* cert from cipher-mix, **reuse it**. Skip ahead.

1. On your Mac, **Keychain Access → Certificate Assistant → Request a
   Certificate from a Certificate Authority**. Email = your Apple ID.
   Saved to disk = yes. You get `CertificateSigningRequest.certSigningRequest`.
2. https://developer.apple.com/account → **Certificates** → **+** → **Apple
   Distribution** → upload the `.certSigningRequest` → download the `.cer`.
3. Double-click the `.cer` to add it to your login keychain.
4. In Keychain Access, right-click the new cert (under **My Certificates**,
   not just Certificates) → **Export** → save as `meow-decoder-distribution.p12`
   with a password you remember. Keep it somewhere offline — losing this
   means revoking and re-issuing.

### 3. Create the App Store provisioning profile

The profile says "this cert is allowed to sign **`com.systemslibrarian.meowdecoder`**
for App Store distribution."

1. https://developer.apple.com/account → **Profiles** → **+** → **Distribution
   → App Store** → **Continue**.
2. App ID: pick `com.systemslibrarian.meowdecoder`.
3. Certificate: pick the Apple Distribution cert you just made (or reused).
4. Profile Name: `Meow Decoder App Store` (any name — the workflow looks
   it up by UUID at runtime, not by name).
5. **Generate → Download** → you get `Meow_Decoder_App_Store.mobileprovision`.

### 4. Create the App Store Connect record

Until this exists the workflow will archive and export fine but the upload
step fails with "No App Store Connect record found".

1. https://appstoreconnect.apple.com → **My Apps** → **+** → **New App**.
2. Platform: **iOS**.
3. Name: **Meow Decoder**.
4. Primary Language: English.
5. Bundle ID: pick `com.systemslibrarian.meowdecoder` from the dropdown
   (only appears after step 1 above).
6. SKU: anything unique, e.g. `meow-decoder-ios-001`.

### 5. Create the App Store Connect API key

This is what CI uses to upload the IPA. Don't reuse your developer-account
password — use a scoped API key.

1. https://appstoreconnect.apple.com → **Users and Access** → **Integrations**
   → **App Store Connect API** → **Generate API Key**.
2. Access: **Developer** (sufficient for `altool` upload). Name: `Meow
   Decoder CI`.
3. Download the `.p8`. **You only get to download it once** — save it
   offline.
4. Note the **Key ID** (10-char string) and **Issuer ID** (UUID at the top
   of the page) — both go into Actions secrets.

---

## Setting up the eight Actions secrets

Set these once at **Settings → Secrets and variables → Actions →
New repository secret**. Workflow at `.github/workflows/ios-release.yml`
reads all of them.

| Secret | What it is | How to populate |
|---|---|---|
| `BUILD_CERTIFICATE_BASE64` | base64 of your `.p12` from step 2 | `base64 -i meow-decoder-distribution.p12 \| pbcopy` |
| `P12_PASSWORD` | password you set when exporting the `.p12` | the literal password, no encoding |
| `BUILD_PROVISION_PROFILE_BASE64` | base64 of the profile from step 3 | `base64 -i Meow_Decoder_App_Store.mobileprovision \| pbcopy` |
| `KEYCHAIN_PASSWORD` | random throwaway string | `openssl rand -base64 24` |
| `ASC_KEY_ID` | the 10-char Key ID from step 5 | the literal value |
| `ASC_ISSUER_ID` | the UUID Issuer ID from step 5 | the literal value |
| `ASC_PRIVATE_KEY` | base64 of the `.p8` from step 5 | `base64 -i AuthKey_XXXXXXXXXX.p8 \| pbcopy` |
| `APPLE_TEAM_ID` | 10-char Team ID from your developer account | https://developer.apple.com/account → **Membership** |

> If you also ship cipher-mix, only `BUILD_CERTIFICATE_BASE64`,
> `P12_PASSWORD`, `KEYCHAIN_PASSWORD`, `ASC_*`, and `APPLE_TEAM_ID` are
> reusable. **`BUILD_PROVISION_PROFILE_BASE64` is per-bundle-ID** — you
> need a fresh meow-decoder profile.

---

## Triggering a release

```bash
# In the repo root, on main with everything you want to ship merged:
git tag v0.1.0-ios
git push origin v0.1.0-ios
```

…or open **Actions → Release iOS to TestFlight → Run workflow**.

The workflow:

1. Builds the Rust→WASM `crypto_core` from source.
2. Stages the meow-decoder web demo into `mobile-ios/dist/` via
   `scripts/build-web.sh` (which also runs `verify-bundle.mjs` to catch
   missing assets).
3. Runs `npx cap sync ios` to copy `dist/` into the iOS bundle.
4. Imports your cert + profile into a temporary keychain.
5. Stamps `CFBundleVersion` with the workflow run number — TestFlight
   rejects duplicate build numbers, so this guarantees uniqueness.
6. `xcodebuild archive` with manual signing pinned to your team and
   profile UUID.
7. `xcodebuild -exportArchive` against a rendered `ExportOptions.plist`.
8. `xcrun altool --upload-app` ships the IPA to App Store Connect →
   TestFlight.
9. Uploads the IPA as a workflow artifact (kept 14 days) so you can
   download it from the run page if anything is odd.

After upload, Apple's server-side processing takes 5–30 minutes. You'll
get an email when the build is ready in TestFlight.

---

## Export compliance — read this once

Meow Decoder uses non-exempt cryptography (AES-256-GCM, ML-KEM-768/1024,
Argon2id, X25519, etc.). The Info.plist sets `ITSAppUsesNonExemptEncryption`
to `true`.

You have two ways to satisfy U.S. export regulations:

1. **Per-submission declaration** (simplest first time). Each TestFlight
   build, App Store Connect prompts you with the standard questionnaire
   ("does your app qualify for any exemptions"). For an open-source app
   that uses standard crypto for protecting user data, you almost always
   qualify under the 740.13(e) exemption ("publicly available" mass-market
   software).
2. **Annual self-classification report to BIS.** File once a year at
   https://www.bis.doc.gov/encryption — covers all your submissions for
   the year. Recommended once you're shipping more than one crypto app.

Either is fine for TestFlight. Apple does not gate TestFlight on this; the
public App Store listing is where the questionnaire becomes binding.

---

## Store listing — what App Store Connect will ask for

Submitting to the public App Store (not just TestFlight) requires:

- **App Information**: category — *Utilities* or *Productivity*. Content
  rights, age rating (Meow Decoder is 4+).
- **Pricing**: free.
- **App Privacy**: data collection answers. Meow Decoder collects nothing,
  so every section is "We do not collect data." Camera access (for QR
  capture inside the in-app receiver) is not data collection — it's a
  device capability and goes under the permissions block in the
  description, not the privacy questionnaire.
- **Privacy Policy URL**: required even when you collect nothing. A
  GitHub Pages page off the meow-decoder repo is enough — link it to
  `docs/PRIVACY.md` if it exists, or write a short one.
- **Screenshots**: 6.7" iPhone (`iPhone 15 Pro Max`, 1290×2796) and 12.9"
  iPad Pro (2048×2732). Capture from a simulator booted to those models
  via **File → New Screenshot** in the simulator, after running the app.
- **Description**, **keywords**, **support URL** (your GitHub repo works).
- **Review notes**: include a sentence pointing the reviewer at the
  built-in self-test or the demo file path. Without this, reviewers don't
  know how to exercise an air-gapped tool — which can lead to bounce-backs
  citing "we couldn't tell what the app does."

Apple typically responds in 1–3 days for a fresh app, often faster for
subsequent versions.

---

## Local Xcode path (no CI)

If you want to push a build without tagging — first run, debugging, etc.:

```bash
cd mobile-ios
npm install
npm run cap:sync:ios   # build web bundle + cap sync
npm run cap:open:ios   # opens Xcode
```

In Xcode:

1. Select the **App** target → **Signing & Capabilities** → check
   *Automatically manage signing* → pick your Team.
2. Bump the **Version** (e.g. 1.0.0) and **Build** (e.g. 1) numbers in the
   General tab.
3. Choose **Any iOS Device (arm64)** as the run target.
4. **Product → Archive** → wait.
5. In the Organizer that opens: **Distribute App** → **App Store Connect**
   → **Upload**. The first upload takes 30–60 minutes server-side.

The CI path skips all of this — once you've set the eight secrets, every
tag push is fully hands-off.

---

## Open follow-ups

These don't block first ship but should land before you submit for
public-App-Store review (TestFlight is fine without them):

- **App icons regenerated from a final marketing logo.** The current
  `resources/icon.png` and `resources/splash.png` are auto-padded versions
  of `assets/meow-decoder-logo.png`. Once a final 1024×1024 marketing icon
  exists, drop it in and re-run `npm run cap:icons` on a Mac.
- **Privacy policy page** if one isn't already published.
- **Camera permission string** if/when the iOS app gains the receiver
  flow. The current bundle is the WASM sender + decoder UI, no camera
  required.
- **Bundle trimming.** `dist/` is currently ~43 MB, mostly `CatVideo.mp4`
  + demo assets. If App Store cellular-download limits become a concern,
  prune to a referenced-only asset set in `scripts/build-web.sh`.
