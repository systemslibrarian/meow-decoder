/**
 * MeowCrypto.kt - Android Stub Implementation
 * 🐱 Meow Decoder Android Cryptographic Wrapper
 *
 * STATUS: STUB - Not yet connected to Rust crypto_core
 *
 * This file defines the API surface for the Android crypto wrapper.
 * Actual implementation will use JNI bindings to the Rust crypto_core.
 */

package io.github.meowdecoder.crypto

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Errors that can occur during cryptographic operations
 */
sealed class MeowCryptoError : Exception() {
    object InvalidKeyLength : MeowCryptoError()
    object InvalidNonceLength : MeowCryptoError()
    object InvalidSaltLength : MeowCryptoError()
    object EncryptionFailed : MeowCryptoError()
    object DecryptionFailed : MeowCryptoError()
    object AuthenticationFailed : MeowCryptoError()
    object KeyDerivationFailed : MeowCryptoError()
    object NotImplemented : MeowCryptoError()
}

/**
 * Result type for crypto operations
 */
sealed class MeowCryptoResult<out T> {
    data class Success<T>(val value: T) : MeowCryptoResult<T>()
    data class Error(val error: MeowCryptoError) : MeowCryptoResult<Nothing>()

    inline fun <R> fold(
        onSuccess: (T) -> R,
        onError: (MeowCryptoError) -> R
    ): R = when (this) {
        is Success -> onSuccess(value)
        is Error -> onError(error)
    }
}

/**
 * Main cryptographic interface for Meow Decoder
 *
 * This is a STUB implementation using Android's javax.crypto.
 * Production version will use the Rust crypto_core via JNI.
 */
object MeowCrypto {

    // MARK: - Constants

    /** Expected key length in bytes (256 bits) */
    const val KEY_LENGTH = 32

    /** Expected nonce length in bytes (96 bits) */
    const val NONCE_LENGTH = 12

    /** Expected salt length in bytes (128 bits) */
    const val SALT_LENGTH = 16

    /** GCM authentication tag length in bits */
    const val TAG_LENGTH_BITS = 128

    /** GCM authentication tag length in bytes */
    const val TAG_LENGTH = 16

    /** AES/GCM transformation string */
    private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"

    /** Secure random instance */
    private val secureRandom = SecureRandom()

    // MARK: - Key Derivation

    /**
     * Derive encryption key from password using PBKDF2
     *
     * NOTE: STUB - Uses PBKDF2. Production will use Argon2id via JNI.
     *
     * @param password User password
     * @param salt Random salt (16 bytes)
     * @return Derived key (32 bytes) wrapped in Result
     */
    fun deriveKey(password: String, salt: ByteArray): MeowCryptoResult<ByteArray> {
        if (salt.size != SALT_LENGTH) {
            return MeowCryptoResult.Error(MeowCryptoError.InvalidSaltLength)
        }

        return try {
            // STUB: Using PBKDF2 as placeholder
            // Production: Call into Rust argon2_derive() via JNI
            val spec = PBEKeySpec(password.toCharArray(), salt, 100_000, KEY_LENGTH * 8)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val key = factory.generateSecret(spec).encoded
            spec.clearPassword()
            MeowCryptoResult.Success(key)
        } catch (e: Exception) {
            MeowCryptoResult.Error(MeowCryptoError.KeyDerivationFailed)
        }
    }

    // MARK: - Encryption

    /**
     * Encrypt data using AES-256-GCM
     *
     * @param plaintext Data to encrypt
     * @param key 32-byte encryption key
     * @param nonce 12-byte nonce (must be unique per encryption)
     * @param aad Optional additional authenticated data
     * @return Ciphertext with appended authentication tag
     */
    fun encrypt(
        plaintext: ByteArray,
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray? = null
    ): MeowCryptoResult<ByteArray> {
        if (key.size != KEY_LENGTH) {
            return MeowCryptoResult.Error(MeowCryptoError.InvalidKeyLength)
        }
        if (nonce.size != NONCE_LENGTH) {
            return MeowCryptoResult.Error(MeowCryptoError.InvalidNonceLength)
        }

        return try {
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            val keySpec = SecretKeySpec(key, "AES")
            val gcmSpec = GCMParameterSpec(TAG_LENGTH_BITS, nonce)

            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
            aad?.let { cipher.updateAAD(it) }

            val ciphertext = cipher.doFinal(plaintext)
            MeowCryptoResult.Success(ciphertext)
        } catch (e: Exception) {
            MeowCryptoResult.Error(MeowCryptoError.EncryptionFailed)
        }
    }

    /**
     * Decrypt data using AES-256-GCM
     *
     * @param ciphertext Encrypted data with tag appended
     * @param key 32-byte encryption key
     * @param nonce 12-byte nonce used during encryption
     * @param aad Optional additional authenticated data (must match encryption)
     * @return Decrypted plaintext
     */
    fun decrypt(
        ciphertext: ByteArray,
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray? = null
    ): MeowCryptoResult<ByteArray> {
        if (key.size != KEY_LENGTH) {
            return MeowCryptoResult.Error(MeowCryptoError.InvalidKeyLength)
        }
        if (nonce.size != NONCE_LENGTH) {
            return MeowCryptoResult.Error(MeowCryptoError.InvalidNonceLength)
        }
        if (ciphertext.size < TAG_LENGTH) {
            return MeowCryptoResult.Error(MeowCryptoError.DecryptionFailed)
        }

        return try {
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            val keySpec = SecretKeySpec(key, "AES")
            val gcmSpec = GCMParameterSpec(TAG_LENGTH_BITS, nonce)

            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
            aad?.let { cipher.updateAAD(it) }

            val plaintext = cipher.doFinal(ciphertext)
            MeowCryptoResult.Success(plaintext)
        } catch (e: javax.crypto.AEADBadTagException) {
            MeowCryptoResult.Error(MeowCryptoError.AuthenticationFailed)
        } catch (e: Exception) {
            MeowCryptoResult.Error(MeowCryptoError.DecryptionFailed)
        }
    }

    // MARK: - Random Generation

    /**
     * Generate cryptographically secure random nonce
     *
     * @return 12-byte random nonce
     */
    fun generateNonce(): ByteArray {
        val bytes = ByteArray(NONCE_LENGTH)
        secureRandom.nextBytes(bytes)
        return bytes
    }

    /**
     * Generate cryptographically secure random salt
     *
     * @return 16-byte random salt
     */
    fun generateSalt(): ByteArray {
        val bytes = ByteArray(SALT_LENGTH)
        secureRandom.nextBytes(bytes)
        return bytes
    }

    /**
     * Generate cryptographically secure random key
     *
     * @return 32-byte random key
     */
    fun generateKey(): ByteArray {
        val bytes = ByteArray(KEY_LENGTH)
        secureRandom.nextBytes(bytes)
        return bytes
    }

    // MARK: - HMAC

    /**
     * Compute HMAC-SHA256
     *
     * @param key HMAC key
     * @param message Message to authenticate
     * @return 32-byte HMAC tag
     */
    fun hmacSha256(key: ByteArray, message: ByteArray): MeowCryptoResult<ByteArray> {
        return try {
            val mac = Mac.getInstance("HmacSHA256")
            val keySpec = SecretKeySpec(key, "HmacSHA256")
            mac.init(keySpec)
            val result = mac.doFinal(message)
            MeowCryptoResult.Success(result)
        } catch (e: Exception) {
            MeowCryptoResult.Error(MeowCryptoError.AuthenticationFailed)
        }
    }

    // MARK: - Constant Time Comparison

    /**
     * Compare two byte arrays in constant time
     *
     * Important: This prevents timing attacks
     *
     * @param a First value
     * @param b Second value
     * @return true if equal
     */
    fun constantTimeEqual(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false

        var result: Int = 0
        for (i in a.indices) {
            result = result or (a[i].toInt() xor b[i].toInt())
        }

        return result == 0
    }

    // MARK: - Secure Memory

    /**
     * Securely zero memory
     *
     * Note: JVM makes true secure zeroing difficult.
     * Production should use Rust crypto_core which uses zeroize crate.
     *
     * @param data ByteArray to zero
     */
    fun secureZero(data: ByteArray) {
        java.util.Arrays.fill(data, 0.toByte())
    }
}

// MARK: - Extension Functions

/**
 * Convert ByteArray to hex string
 */
fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }

/**
 * Convert hex string to ByteArray
 */
fun String.hexToByteArray(): ByteArray {
    check(length % 2 == 0) { "Hex string must have even length" }
    return chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()
}

// MARK: - Keystore Integration Stub

/**
 * Android Keystore wrapper for secure key storage
 *
 * STATUS: STUB - Defines API for secure hardware-backed key storage
 *
 * Production implementation will:
 * - Use Android Keystore for key storage
 * - Use StrongBox if available (hardware security module)
 * - Require biometric authentication for key access
 */
object MeowKeystore {

    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val KEY_ALIAS_PREFIX = "meow_decoder_"

    /**
     * Check if StrongBox hardware security module is available
     *
     * @return true if StrongBox is available
     */
    fun isStrongBoxAvailable(): Boolean {
        // STUB: Would check Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
        // and KeyInfo.isInsideSecureHardware()
        return false
    }

    /**
     * Generate and store a key in the Android Keystore
     *
     * @param alias Key alias
     * @param requireBiometric Require biometric authentication
     * @return true on success
     */
    fun generateKey(alias: String, requireBiometric: Boolean = false): Boolean {
        // STUB: Would use KeyGenerator with AndroidKeyStore provider
        // and KeyGenParameterSpec.Builder for key properties
        return false
    }

    /**
     * Retrieve a key from the Android Keystore
     *
     * @param alias Key alias
     * @return Key bytes or null if not found
     */
    fun getKey(alias: String): ByteArray? {
        // STUB: Would retrieve from KeyStore.getInstance(KEYSTORE_PROVIDER)
        return null
    }

    /**
     * Delete a key from the Android Keystore
     *
     * @param alias Key alias
     * @return true on success
     */
    fun deleteKey(alias: String): Boolean {
        // STUB: Would delete from KeyStore.getInstance(KEYSTORE_PROVIDER)
        return false
    }
}

// MARK: - Example Usage

/**
 * Example demonstrating MeowCrypto usage
 */
fun main() {
    println("🐱 MeowCrypto Android Stub Demo")
    println("=" .repeat(50))

    // Generate random values
    val salt = MeowCrypto.generateSalt()
    val nonce = MeowCrypto.generateNonce()
    println("Salt: ${salt.toHexString()}")
    println("Nonce: ${nonce.toHexString()}")

    // Derive key from password
    val password = "correct horse battery staple"
    val keyResult = MeowCrypto.deriveKey(password, salt)

    keyResult.fold(
        onSuccess = { key ->
            println("Derived key: ${key.toHexString()}")

            // Encrypt
            val plaintext = "Hello, Meow Decoder! 🐱".toByteArray(Charsets.UTF_8)
            val encryptResult = MeowCrypto.encrypt(plaintext, key, nonce)

            encryptResult.fold(
                onSuccess = { ciphertext ->
                    println("Ciphertext: ${ciphertext.toHexString()}")

                    // Decrypt
                    val decryptResult = MeowCrypto.decrypt(ciphertext, key, nonce)

                    decryptResult.fold(
                        onSuccess = { decrypted ->
                            println("Decrypted: ${String(decrypted, Charsets.UTF_8)}")
                            println("\n✅ Roundtrip successful!")
                        },
                        onError = { error ->
                            println("❌ Decryption failed: $error")
                        }
                    )
                },
                onError = { error ->
                    println("❌ Encryption failed: $error")
                }
            )

            // Secure cleanup
            MeowCrypto.secureZero(key)
        },
        onError = { error ->
            println("❌ Key derivation failed: $error")
        }
    )
}
