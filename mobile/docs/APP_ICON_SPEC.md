# App Icon & Splash Screen Design Spec

## Brand Assets for Meow Capture

### Icon Concept
- **Primary**: Cat face silhouette with QR-pattern eye (ties into QR scanning)
- **Style**: Flat, geometric, high-contrast on dark background
- **Colors**: Cat orange `#f5c842` on ink-black `#0a0a0f`
- **Shape**: Android adaptive icon safe-zone compliant (66dp inner content area)

### Required Files

#### Android (Adaptive Icon)
```
android/app/src/main/res/
├── mipmap-mdpi/
│   ├── ic_launcher.webp      (48×48)
│   ├── ic_launcher_round.webp (48×48)
│   └── ic_launcher_foreground.webp (108×108)
├── mipmap-hdpi/
│   ├── ic_launcher.webp      (72×72)
│   ├── ic_launcher_round.webp (72×72)
│   └── ic_launcher_foreground.webp (162×162)
├── mipmap-xhdpi/
│   ├── ic_launcher.webp      (96×96)
│   ├── ic_launcher_round.webp (96×96)
│   └── ic_launcher_foreground.webp (216×216)
├── mipmap-xxhdpi/
│   ├── ic_launcher.webp      (144×144)
│   ├── ic_launcher_round.webp (144×144)
│   └── ic_launcher_foreground.webp (324×324)
├── mipmap-xxxhdpi/
│   ├── ic_launcher.webp      (192×192)
│   ├── ic_launcher_round.webp (192×192)
│   └── ic_launcher_foreground.webp (432×432)
└── values/
    └── ic_launcher_background.xml  → #0a0a0f
```

**Adaptive icon XML** (`android/app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml`):
```xml
<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@color/ic_launcher_background"/>
    <foreground android:drawable="@mipmap/ic_launcher_foreground"/>
</adaptive-icon>
```

#### iOS
```
ios/MeowCapture/Images.xcassets/AppIcon.appiconset/
├── Contents.json
├── icon-20@2x.png    (40×40)
├── icon-20@3x.png    (60×60)
├── icon-29@2x.png    (58×58)
├── icon-29@3x.png    (87×87)
├── icon-40@2x.png    (80×80)
├── icon-40@3x.png    (120×120)
├── icon-60@2x.png    (120×120)
├── icon-60@3x.png    (180×180)
└── icon-1024.png     (1024×1024) ← App Store
```

#### Splash Screen
- **Android**: `android/app/src/main/res/drawable/launch_screen.xml`
  - Centered logo (120dp) on ink-black `#0a0a0f` background
- **iOS**: `ios/MeowCapture/LaunchScreen.storyboard`
  - Centered logo image view with autolayout constraints

### Generation Command
Use `@nicerapp/icon-gen` or Android Studio's Image Asset wizard:
```bash
npx @nicerapp/icon-gen -i src/assets/meow-icon-1024.png --android --ios
```

### Accessibility Notes
- Icon must be recognizable at 48×48 (mdpi) — avoid fine detail
- No text in the icon (not readable at small sizes, not i18n-friendly)
- Sufficient contrast between foreground and background for low-vision users
- `android:roundIcon` attribute in AndroidManifest.xml must point to round variant

### Status
- [ ] Design 1024×1024 source icon SVG
- [ ] Generate all density variants
- [ ] Update AndroidManifest.xml references
- [ ] Update iOS Images.xcassets
- [ ] Test on Android 8+ (adaptive) and Android 7 (legacy)
- [ ] Test on iOS 15+ (dark/tinted icon variants for iOS 18)
