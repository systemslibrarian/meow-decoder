// MeowCrypto.swift - iOS Stub Implementation
// 🐱 Meow Decoder iOS Cryptographic Wrapper
//
// STATUS: STUB - Not yet connected to Rust crypto_core
//
// This file defines the API surface for the iOS crypto wrapper.
// Actual implementation will use C-FFI bindings to the Rust crypto_core.

import Foundation
import CryptoKit

/// Errors that can occur during cryptographic operations
public enum MeowCryptoError: Error {
    case invalidKeyLength
    case invalidNonceLength
    case invalidSaltLength
    case encryptionFailed
    case decryptionFailed
    case authenticationFailed
    case keyDerivationFailed
    case notImplemented
}

/// Main cryptographic interface for Meow Decoder
///
/// This is a STUB implementation using Apple's CryptoKit.
/// Production version will use the Rust crypto_core via FFI.
public final class MeowCrypto {
    
    // MARK: - Constants
    
    /// Expected key length in bytes (256 bits)
    public static let keyLength = 32
    
    /// Expected nonce length in bytes (96 bits)
    public static let nonceLength = 12
    
    /// Expected salt length in bytes (128 bits)
    public static let saltLength = 16
    
    /// GCM authentication tag length in bytes
    public static let tagLength = 16
    
    // MARK: - Singleton
    
    /// Shared instance
    public static let shared = MeowCrypto()
    
    private init() {}
    
    // MARK: - Key Derivation
    
    /// Derive encryption key from password using Argon2id
    ///
    /// - Parameters:
    ///   - password: User password
    ///   - salt: Random salt (16 bytes)
    /// - Returns: Derived key (32 bytes)
    /// - Throws: MeowCryptoError if derivation fails
    ///
    /// - Note: STUB - Uses PBKDF2. Production will use Argon2id via FFI.
    public func deriveKey(password: String, salt: Data) throws -> Data {
        guard salt.count == Self.saltLength else {
            throw MeowCryptoError.invalidSaltLength
        }
        
        // STUB: Using PBKDF2 as placeholder
        // Production: Call into Rust argon2_derive()
        guard let passwordData = password.data(using: .utf8) else {
            throw MeowCryptoError.keyDerivationFailed
        }
        
        let key = try deriveKeyPBKDF2(
            password: passwordData,
            salt: salt,
            iterations: 100_000,
            keyLength: Self.keyLength
        )
        
        return key
    }
    
    /// PBKDF2 key derivation (STUB - placeholder for Argon2id)
    private func deriveKeyPBKDF2(
        password: Data,
        salt: Data,
        iterations: Int,
        keyLength: Int
    ) throws -> Data {
        var derivedKey = Data(count: keyLength)
        
        let status = derivedKey.withUnsafeMutableBytes { derivedKeyBytes in
            password.withUnsafeBytes { passwordBytes in
                salt.withUnsafeBytes { saltBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.baseAddress?.assumingMemoryBound(to: Int8.self),
                        password.count,
                        saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        derivedKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        keyLength
                    )
                }
            }
        }
        
        guard status == kCCSuccess else {
            throw MeowCryptoError.keyDerivationFailed
        }
        
        return derivedKey
    }
    
    // MARK: - Encryption
    
    /// Encrypt data using AES-256-GCM
    ///
    /// - Parameters:
    ///   - plaintext: Data to encrypt
    ///   - key: 32-byte encryption key
    ///   - nonce: 12-byte nonce (must be unique per encryption)
    ///   - aad: Optional additional authenticated data
    /// - Returns: Ciphertext with appended authentication tag
    /// - Throws: MeowCryptoError if encryption fails
    public func encrypt(
        plaintext: Data,
        key: Data,
        nonce: Data,
        aad: Data? = nil
    ) throws -> Data {
        guard key.count == Self.keyLength else {
            throw MeowCryptoError.invalidKeyLength
        }
        guard nonce.count == Self.nonceLength else {
            throw MeowCryptoError.invalidNonceLength
        }
        
        // Use CryptoKit for encryption
        let symmetricKey = SymmetricKey(data: key)
        let nonceValue = try AES.GCM.Nonce(data: nonce)
        
        let sealedBox: AES.GCM.SealedBox
        if let aad = aad {
            sealedBox = try AES.GCM.seal(
                plaintext,
                using: symmetricKey,
                nonce: nonceValue,
                authenticating: aad
            )
        } else {
            sealedBox = try AES.GCM.seal(
                plaintext,
                using: symmetricKey,
                nonce: nonceValue
            )
        }
        
        // Return ciphertext + tag
        return sealedBox.ciphertext + sealedBox.tag
    }
    
    /// Decrypt data using AES-256-GCM
    ///
    /// - Parameters:
    ///   - ciphertext: Encrypted data with tag appended
    ///   - key: 32-byte encryption key
    ///   - nonce: 12-byte nonce used during encryption
    ///   - aad: Optional additional authenticated data (must match encryption)
    /// - Returns: Decrypted plaintext
    /// - Throws: MeowCryptoError if decryption or authentication fails
    public func decrypt(
        ciphertext: Data,
        key: Data,
        nonce: Data,
        aad: Data? = nil
    ) throws -> Data {
        guard key.count == Self.keyLength else {
            throw MeowCryptoError.invalidKeyLength
        }
        guard nonce.count == Self.nonceLength else {
            throw MeowCryptoError.invalidNonceLength
        }
        guard ciphertext.count >= Self.tagLength else {
            throw MeowCryptoError.decryptionFailed
        }
        
        let symmetricKey = SymmetricKey(data: key)
        let nonceValue = try AES.GCM.Nonce(data: nonce)
        
        // Split ciphertext and tag
        let ciphertextOnly = ciphertext.prefix(ciphertext.count - Self.tagLength)
        let tag = ciphertext.suffix(Self.tagLength)
        
        let sealedBox = try AES.GCM.SealedBox(
            nonce: nonceValue,
            ciphertext: ciphertextOnly,
            tag: tag
        )
        
        let plaintext: Data
        if let aad = aad {
            plaintext = try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: aad)
        } else {
            plaintext = try AES.GCM.open(sealedBox, using: symmetricKey)
        }
        
        return plaintext
    }
    
    // MARK: - Random Generation
    
    /// Generate cryptographically secure random nonce
    ///
    /// - Returns: 12-byte random nonce
    public func generateNonce() -> Data {
        var bytes = [UInt8](repeating: 0, count: Self.nonceLength)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes)
    }
    
    /// Generate cryptographically secure random salt
    ///
    /// - Returns: 16-byte random salt
    public func generateSalt() -> Data {
        var bytes = [UInt8](repeating: 0, count: Self.saltLength)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes)
    }
    
    // MARK: - HMAC
    
    /// Compute HMAC-SHA256
    ///
    /// - Parameters:
    ///   - key: HMAC key
    ///   - message: Message to authenticate
    /// - Returns: 32-byte HMAC tag
    public func hmacSha256(key: Data, message: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let mac = HMAC<SHA256>.authenticationCode(for: message, using: symmetricKey)
        return Data(mac)
    }
    
    // MARK: - Constant Time Comparison
    
    /// Compare two Data values in constant time
    ///
    /// - Parameters:
    ///   - a: First value
    ///   - b: Second value
    /// - Returns: true if equal
    ///
    /// - Important: This prevents timing attacks
    public func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        
        var result: UInt8 = 0
        for i in 0..<a.count {
            result |= a[i] ^ b[i]
        }
        
        return result == 0
    }
    
    // MARK: - Secure Memory
    
    /// Securely zero memory (best-effort in Swift)
    ///
    /// - Parameter data: Data to zero
    ///
    /// - Note: Swift's memory model makes true secure zeroing difficult.
    /// Production should use Rust crypto_core which uses zeroize crate.
    public func secureZero(_ data: inout Data) {
        data.withUnsafeMutableBytes { bytes in
            memset_s(bytes.baseAddress, bytes.count, 0, bytes.count)
        }
    }
}

// MARK: - CommonCrypto Import for PBKDF2

import CommonCrypto

// MARK: - Extension for Hex Encoding

extension Data {
    /// Hex string representation
    public var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
    
    /// Initialize from hex string
    public init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        
        var i = hexString.startIndex
        for _ in 0..<len {
            let j = hexString.index(i, offsetBy: 2)
            guard let byte = UInt8(hexString[i..<j], radix: 16) else {
                return nil
            }
            data.append(byte)
            i = j
        }
        
        self = data
    }
}
