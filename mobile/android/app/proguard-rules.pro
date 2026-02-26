# React Native — keep JS bridge entry points
-keep class com.facebook.react.** { *; }
-keep class com.facebook.hermes.** { *; }

# react-native-vision-camera — JNI / native frame processor glue
-keep class com.mrousavy.camera.** { *; }
-keepclassmembers class com.mrousavy.camera.** { *; }

# react-native-mmkv — JNI storage
-keep class com.tencent.mmkv.** { *; }

# Biometric / fingerprint
-keep class androidx.biometric.** { *; }

# Kotlin metadata (required for coroutines)
-keepattributes *Annotation*, InnerClasses, Signature, EnclosingMethod
-keep class kotlin.Metadata { *; }

# ZXing (QR) — if bundled
-keep class com.google.zxing.** { *; }

# Remove log calls in release
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
}
