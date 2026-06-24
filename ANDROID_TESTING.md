# 🐱📱 Meow Capture — Android Testing Guide

How to get the latest Android build onto a phone and what to do once it's in
internal testing. Current build on Play: **versionName 3.2.3 / versionCode 4**,
uploaded to the **Internal testing** track (package `com.meowdecodermobile`).

There are two ways to test:

- **A. Play internal testing** — closest to the real install experience; needed
  before promoting to production. Installs through the Play Store.
- **B. Sideload via `adb` (USB *or* Wi-Fi)** — fastest for your own phone;
  installs the signed APK directly, no Play account needed. See the Quick start.

---

## ⚡ Quick start — install on your phone (Windows + Wi-Fi, the proven path)

This is the exact end-to-end flow that worked, copy-paste into **PowerShell**
from the repo root. Wi-Fi pairing is used because USB stays `unauthorized` on
Samsung; phone and PC must be on the **same network**. (USB and the
step-by-step explanations are in Part B below.)

```powershell
# ── 0) ONE-TIME: install adb (Android platform-tools) ─────────────────────────
# Download once: https://dl.google.com/android/repository/platform-tools-latest-windows.zip
Expand-Archive "$env:USERPROFILE\Downloads\platform-tools-latest-windows.zip" `
  -DestinationPath "$env:LOCALAPPDATA\Android" -Force
$adb = "$env:LOCALAPPDATA\Android\platform-tools\adb.exe"
# add to PATH permanently (so future terminals find `adb`)
[Environment]::SetEnvironmentVariable("Path",
  [Environment]::GetEnvironmentVariable("Path","User") + ";$env:LOCALAPPDATA\Android\platform-tools", "User")
& $adb version

# ── 1) download the signed APK from the latest successful release run ─────────
$run = gh run list --workflow=android-release.yml `
  --json databaseId,conclusion -q '[.[]|select(.conclusion=="success")][0].databaseId'
gh run download $run -n meow-capture-android-apk -D .\_apk    # -> .\_apk\app-release.apk

# ── 2) pair over Wi-Fi ────────────────────────────────────────────────────────
# On phone: Settings → Developer options → Wireless debugging → ON
#           → "Pair device with pairing code"  (shows a 6-digit code + IP:PORT)
& $adb pair <PAIRING_IP:PORT> <6-DIGIT-CODE>      # e.g.  192.168.4.32:45889  566939

# ── 3) connect (the *connect* port differs from the pairing port) ─────────────
& $adb mdns services                              # shows ..._adb-tls-connect._tcp  IP:PORT
& $adb connect <CONNECT_IP:PORT>                  # e.g.  192.168.4.32:39625
& $adb devices -l                                 # should show your phone as "device"

# ── 4) install + launch ───────────────────────────────────────────────────────
& $adb install -r .\_apk\app-release.apk          # "Success"
& $adb shell monkey -p com.meowdecodermobile -c android.intent.category.LAUNCHER 1
```

**Reinstall a later build** (already paired): re-toggle Wireless debugging if it
dropped, then:
```powershell
& $adb connect <CONNECT_IP:PORT>
gh run download <RUN_ID> -n meow-capture-android-apk -D .\_apk   # only for a new build
& $adb install -r .\_apk\app-release.apk
```

> The pairing code is single-use and the **pairing port ≠ connect port**, and
> both change every time you toggle Wireless debugging. If `adb connect` fails or
> shows `offline`, re-run `adb mdns services` for the current connect port (or
> re-pair). Signature-mismatch on install → `adb uninstall com.meowdecodermobile`
> first (wipes app data), then install.

---

## A. Test through Play internal testing

### 1. Add yourself (and others) as testers
Google Play Console → **Testing → Internal testing**:
1. Open the **Testers** tab.
2. Create or pick an email list, and add the Google accounts that should test
   (the account signed in on the phone must be in this list).
3. **Save changes.**

### 2. Install on the phone
1. Still on the Internal testing page, copy the **“Copy link”** opt-in URL
   (looks like `https://play.google.com/apps/internaltest/<id>`).
2. On the phone, signed in with a tester account, open that link → **Accept**
   the invite → tap **Download it on Google Play** → **Install/Update**.
3. The app installs/updates from the Play Store like any normal app.

> New uploads can take a few minutes to become available, and the Play Store
> entry may show “Update” rather than “Install” if a build is already on the
> device.

### 3. Promote when you're happy
Play Console → **Testing → Internal testing → Promote release →** Closed → Open
→ Production. You review and roll out from there; nothing reaches the public
until you promote to **Production**.

---

## B. Sideload the signed APK to a USB-connected phone (`adb`)

This pushes the exact signed release APK straight to a plugged-in phone.

### 1. Get `adb` (Android Platform Tools)
`adb` isn't installed on this machine yet. One-time setup:

- **Windows:** download **SDK Platform Tools** from
  <https://developer.android.com/tools/releases/platform-tools>, unzip, and add
  the folder to your `PATH` (or `cd` into it). Or: `winget install Google.PlatformTools`.
- **macOS:** `brew install android-platform-tools`
- **Linux:** `sudo apt install adb` (or the platform-tools zip)

Verify: `adb version`

### 2. Get the signed APK
Download the `meow-capture-android-apk` artifact from the latest successful
**Release Android to Google Play** run:

```bash
# from the repo root, using the GitHub CLI:
gh run download <RUN_ID> -n meow-capture-android-apk -D ./_apk
#   <RUN_ID> e.g. 28084636602 — find it with:  gh run list --workflow=android-release.yml
ls ./_apk   # -> app-release.apk
```

(Or grab it from the run page → **Artifacts** in a browser. `releases/android/`
is no longer used — release binaries live as CI artifacts now.)

### 3. Put the phone in USB-debugging mode
On the phone:
1. **Settings → About phone →** tap **Build number** 7 times to unlock
   *Developer options*.
2. **Settings → System → Developer options →** enable **USB debugging**.
3. Plug the phone into the computer with a USB **data** cable.
4. On the phone, tap **Allow** when the *“Allow USB debugging?”* prompt appears
   (tick *Always allow from this computer*).

### 4. Install
```bash
adb devices                       # should list your device as "device" (not "unauthorized")
adb install -r ./_apk/app-release.apk
#   -r = reinstall, keeping app data
```

Launch **Meow Capture** from the app drawer.

### Alternative: connect over Wi-Fi (Wireless debugging) — ✅ the route that worked

If USB keeps showing `unauthorized` (common on Samsung), pair over Wi-Fi
instead. Phone and computer must be on the **same network**.

**On the phone:** Settings → Developer options → **Wireless debugging → ON** →
tap **“Pair device with pairing code.”** It shows a **6-digit code** and an
**IP address & port** (the *pairing* port, e.g. `192.168.4.32:45889`).

**On the computer** (PowerShell, from the repo root):
```powershell
$adb = "$env:LOCALAPPDATA\Android\platform-tools\adb.exe"

# 1. Pair using the pairing IP:port + the 6-digit code (code expires fast — do this quickly)
& $adb pair 192.168.4.32:45889 566939

# 2. Connect. Easiest is to let mDNS find the *connect* port (different from the pairing port):
& $adb mdns services        # shows e.g.  ..._adb-tls-connect._tcp  192.168.4.32:39625
& $adb connect 192.168.4.32:39625
#   (or: & $adb connect adb-<SERIAL>-xxxx._adb-tls-connect._tcp )

& $adb devices -l           # should now show the device as "device"

# 3. Install
& $adb install -r .\_apk\app-release.apk
```

> The pairing port (from the popup) and the connect port (main Wireless
> debugging screen / `adb mdns services`) are **different**, and both change
> every time you toggle Wireless debugging. Pair once, then reconnect with
> `adb connect <ip>:<connect-port>` until the phone reboots or drops off.

### Troubleshooting
| Symptom | Fix |
| --- | --- |
| `adb: command not found` | Platform-tools not on `PATH` — see step B1. |
| device shows `unauthorized` (USB) | Accept the USB-debugging prompt on the phone; re-run `adb devices`. If it never appears, **Revoke USB debugging authorizations** in Developer options and replug — or use the Wi-Fi route above. |
| device shows `offline` (Wi-Fi) | You paired but didn't connect to the *connect* port. Run `adb mdns services` and `adb connect <ip>:<connect-port>`. |
| device not listed at all | Use a data-capable USB cable; try another port; on Windows install the OEM USB driver. |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` / signature mismatch | A build signed with a different key is installed. Remove it first: `adb uninstall com.meowdecodermobile`, then `adb install`. (This deletes the app's data.) |
| `INSTALL_FAILED_USER_RESTRICTED` (Xiaomi/MIUI etc.) | In Developer options, enable **Install via USB** / disable MIUI optimizations. |
| app installs but the QR/camera screen is blank | Grant Camera permission: **Settings → Apps → Meow Capture → Permissions**. |

---

## Cutting the next release

The release is fully automated (`.github/workflows/android-release.yml`):

1. Bump the version in **two** places:
   - `mobile/android/app/build.gradle` → `versionCode` (+1, e.g. 5) and
     `versionName` (e.g. `"3.2.4"`)
   - `mobile/package.json` → `"version": "3.2.4"`
2. Commit to `main`.
3. Trigger the build + Play upload, either:
   - **Tag:** `git tag v3.2.4-android && git push origin v3.2.4-android`, or
   - **Manual:** Actions tab → *Release Android to Google Play* → **Run workflow**
     (pick `track`: internal | alpha | beta | production).
4. The workflow builds, signs, and uploads the AAB to the chosen track via the
   `play-publisher@meowdecoder-495711.iam.gserviceaccount.com` service account.

> ⚠️ Each upload needs a **new, higher `versionCode`**. Re-running with the same
> versionCode (e.g. shipping 3.2.3/4 again) is rejected by Play as a duplicate.

See also `docs/RELEASING_ANDROID.md` for the full pipeline reference.
