# Releasing Meow Capture for Android

The Android release is fully automated via the
[`Release Android to Google Play`](../.github/workflows/android-release.yml)
workflow. It builds, signs, and (optionally) publishes a `.aab` to the Play
Console Internal Testing track.

## Triggers

- **Tag push** matching `v*-android` (e.g. `v3.2.3-android`).
- **Manual dispatch** from the Actions tab (lets you pick `track` and override
  `versionCode`).

## Required GitHub Actions secrets

Configure these under **Settings → Secrets and variables → Actions** for the
repository:

| Secret | Purpose |
| --- | --- |
| `ANDROID_KEYSTORE_BASE64` | base64 of `meow-decoder-release.jks` (`base64 -w0 release.jks`) |
| `ANDROID_KEYSTORE_PASSWORD` | keystore password |
| `ANDROID_KEY_ALIAS` | usually `meow-release` |
| `ANDROID_KEY_PASSWORD` | key password |

## Optional secret

| Secret | Purpose |
| --- | --- |
| `PLAY_SERVICE_ACCOUNT_JSON` | Service-account JSON with **Release Manager** rights on the app. When unset, the workflow still builds and signs the AAB and uploads it as a workflow artifact for manual upload via Play Console. |

## Cutting a release

```bash
# 1. Make sure main is green and up to date
git checkout main
git pull --ff-only

# 2. Tag and push (this fires the workflow)
git tag v3.2.3-android
git push origin v3.2.3-android
```

Then watch the run under **Actions → Release Android to Google Play**.

### Outputs

- `meow-capture-android-aab` — signed `app-release.aab` (Play upload format)
- `meow-capture-android-apk` — signed `app-release.apk` (sideload / sanity check)

If `PLAY_SERVICE_ACCOUNT_JSON` is configured, the `publish-play` job uploads
the AAB to the `internal` track with `status: completed`. Otherwise, download
the AAB artifact and upload it manually in the Play Console.

## Manual dispatch

From the Actions tab, pick the workflow → **Run workflow** and optionally
provide:

- `track` — `internal` (default) | `alpha` | `beta` | `production`
- `build_number` — overrides `versionCode` in `android/app/build.gradle`
