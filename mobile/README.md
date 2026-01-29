# 📱 Meow Decoder Mobile Support

This directory contains stubs and documentation for mobile platform integration.

## Current Status: 🚧 Stubs Only

The mobile implementations are placeholder stubs designed to:
1. Define the target API surface
2. Provide compilation scaffolding for future development
3. Document integration patterns

## Platform Support

### iOS (Swift)

**Location:** `ios/MeowDecoder/`

**Requirements:**
- Xcode 15+
- iOS 16+ deployment target
- Swift 5.9+

**Integration approach:**
1. Build crypto_core as xcframework via cargo-lipo
2. Swift wrapper via C-FFI bindings
3. SwiftUI demo app

**Build (future):**
```bash
# Install iOS targets
rustup target add aarch64-apple-ios x86_64-apple-ios

# Build universal binary
cargo lipo --release --features pure-crypto

# Generate Swift bindings
cbindgen --lang c --output MeowCrypto.h
```

### Android (Kotlin)

**Location:** `android/meowdecoder/`

**Requirements:**
- Android Studio Hedgehog+
- Android NDK r25+
- Kotlin 1.9+

**Integration approach:**
1. Build crypto_core as .so via cargo-ndk
2. JNI bindings via jni-rs
3. Jetpack Compose demo app

**Build (future):**
```bash
# Install Android targets
rustup target add aarch64-linux-android armv7-linux-androideabi

# Build with NDK
cargo ndk -t armeabi-v7a -t arm64-v8a -o android/jniLibs build --release
```

## API Stubs

Both platforms expose the same API surface:

```
MeowCrypto
├── deriveKey(password: String, salt: Data) -> Data
├── encrypt(plaintext: Data, key: Data, nonce: Data) -> Data
├── decrypt(ciphertext: Data, key: Data, nonce: Data) -> Data
├── generateNonce() -> Data
├── generateSalt() -> Data
├── hmacSha256(key: Data, message: Data) -> Data
└── constantTimeEqual(a: Data, b: Data) -> Bool
```

## Security Considerations

### iOS
- Use Keychain for key storage
- Enable Data Protection
- Use Secure Enclave for biometric unlock
- Never log sensitive data

### Android
- Use EncryptedSharedPreferences or Keystore
- Enable android:extractNativeLibs="false"
- Use StrongBox if available
- Follow MASVS guidelines

## Testing

Mobile unit tests should verify:
1. Key derivation produces consistent results
2. Encrypt/decrypt roundtrip works
3. Wrong password fails gracefully
4. Memory is zeroed after operations

## Roadmap

1. **Phase 1:** Swift/Kotlin stubs (current)
2. **Phase 2:** Rust-to-native FFI bindings
3. **Phase 3:** Platform-specific key storage
4. **Phase 4:** QR scanner integration
5. **Phase 5:** Full encode/decode flow
6. **Phase 6:** App Store / Play Store release

## Contributing

Mobile development help wanted! See CONTRIBUTING.md for guidelines.

Key areas:
- Swift package for iOS
- Kotlin multiplatform for Android
- React Native / Flutter wrappers
- Secure enclave integration
