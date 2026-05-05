# Meow Decoder — iOS (Capacitor)

A Capacitor wrapper around the standalone WASM web demo
(`web_demo/wasm_browser_example_FULL.html`), packaged as an iOS app.
This is the **sender / desktop-mirror** path: encode files into animated
QR-code GIFs on iPhone or iPad, view the transfer, and run the in-app
WASM decode for round-trip verification.

The **receiver** (camera-scan-only companion) lives at `../mobile/` and
uses React Native — that app is the one already shipped on Android. This
directory is independent of that one.

The shipping pipeline mirrors the proven cipher-mix Capacitor pattern:
GitHub Actions on a `macos-26` runner, signed archive, `altool` upload to
TestFlight. Full setup walkthrough in [`STORES.md`](./STORES.md).

## Bundle ID

`com.systemslibrarian.meowdecoder` — permanent.

## Layout

```
mobile-ios/
├── package.json              # Capacitor deps + build:native script
├── capacitor.config.json     # appId / appName / webDir = dist
├── scripts/
│   ├── build-web.sh          # stage web_demo + assets + crypto_core/pkg → dist/
│   └── verify-bundle.mjs     # post-build sanity check on dist/index.html
├── resources/                # icon.png + splash.png inputs for `cap:icons`
├── ios/                      # Capacitor-scaffolded Xcode project
│   ├── App/App.xcodeproj/
│   ├── App/App/              # AppDelegate, Info.plist, Assets.xcassets, storyboards
│   ├── App/CapApp-SPM/       # Swift Package Manager bundling
│   └── App/ExportOptions.plist.tmpl
└── STORES.md                 # Apple-side credential + submission walkthrough
```

`dist/` is generated, not committed. CI rebuilds it on every run.

## Local dev (macOS only — Xcode is required)

```bash
cd mobile-ios
npm install
npm run cap:sync:ios   # build web bundle + cap sync ios
npm run cap:open:ios   # open in Xcode
```

Then **Product → Run** on a simulator, or **Product → Archive** for a
TestFlight build.

## CI

`.github/workflows/ios-release.yml` builds and ships on:

- `git push` of a tag matching `v*-ios` (e.g. `v0.1.0-ios`)
- manual dispatch from the Actions tab

Eight Actions secrets must be set first — see
[`STORES.md`](./STORES.md#setting-up-the-eight-actions-secrets).

## What's in the bundle

The vite-style `dist/` is staged from:

| Source | Destination |
|--------|-------------|
| `../web_demo/wasm_browser_example_FULL.html` | `dist/index.html` (with `../assets/` and `../crypto_core/` paths rewritten) |
| `../web_demo/*.js`, `../web_demo/static/`, `sw.js` | `dist/` (rsync, excluding Flask templates and Python) |
| `../assets/` | `dist/assets/` |
| `../crypto_core/pkg/` | `dist/crypto_core/pkg/` (built fresh in CI via `wasm-pack build --target web`) |
| `../examples/manifest.json` | `dist/manifest.json` (PWA manifest, paths rewritten) |

## Open follow-ups

See the *Open follow-ups* section of [`STORES.md`](./STORES.md#open-follow-ups).
