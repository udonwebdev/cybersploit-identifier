import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

/// Container representing the parsed binary components of an encrypted vault payload.
class EncryptedVaultPayload {
  final Uint8List rawBytes;
  final Uint8List magic;
  final int version;
  final Uint8List nonce;
  final Uint8List tag;
  final Uint8List ciphertext;

  EncryptedVaultPayload({
    required this.rawBytes,
    required this.magic,
    required this.version,
    required this.nonce,
    required this.tag,
    required this.ciphertext,
  });

  /// Validates standard header size (at least 33 bytes) and magic bytes.
  bool get isValidHeader {
    if (rawBytes.length < 33) return false;
    final isSecv = rawBytes[0] == 0x53 && rawBytes[1] == 0x45 && rawBytes[2] == 0x43 && rawBytes[3] == 0x56;
    final isVaul = rawBytes[0] == 0x56 && rawBytes[1] == 0x41 && rawBytes[2] == 0x55 && rawBytes[3] == 0x4C;
    return (isSecv || isVaul) && (rawBytes[4] == 0x01);
  }
}

/// Abstract contract for AES-256-GCM vault encryption, decryption, and key derivation.
abstract class IVaultCryptoService {
  /// Encrypts in-memory [plaintext] bytes using AES-256-GCM.
  /// Returns binary container: `[Magic:4B 'SECV'] + [Version:1B 0x01] + [Nonce:12B] + [Tag:16B] + [Ciphertext:NB]`.
  Future<Uint8List> encryptBytes({
    required Uint8List plaintext,
    required SecretKey masterKey,
    Uint8List? additionalData,
  });

  /// Decrypts a binary container payload back into plaintext bytes.
  /// Throws [CryptographicIntegrityException] or [SecretBoxAuthenticationError] if corrupted/tampered.
  Future<Uint8List> decryptBytes({
    required Uint8List encryptedContainer,
    required SecretKey masterKey,
    Uint8List? additionalData,
  });

  /// Encrypts a source file at [sourcePath] and atomically writes the encrypted container to [destinationPath].
  /// Returns the parsed [EncryptedVaultPayload].
  Future<EncryptedVaultPayload> encryptFile({
    required String sourcePath,
    required String destinationPath,
    required SecretKey masterKey,
    Uint8List? additionalData,
  });

  /// Decrypts an encrypted file at [encryptedFilePath] and writes the restored plaintext to [decryptedDestinationPath].
  /// Returns the path of the restored decrypted file.
  Future<String> decryptFile({
    required String encryptedFilePath,
    required String decryptedDestinationPath,
    required SecretKey masterKey,
    Uint8List? additionalData,
  });

  /// Derives a 256-bit AES key from a user [passcode] and cryptographic [salt] using PBKDF2-HMAC-SHA256.
  Future<SecretKey> deriveKeyFromPasscode({
    required String passcode,
    required Uint8List salt,
    int iterations = 100000,
  });

  /// Generates a fresh, cryptographically secure 256-bit master key.
  Future<SecretKey> generateMasterKey();

  /// Parses a raw binary container into its constituent parts without decrypting.
  EncryptedVaultPayload parseContainer(Uint8List containerBytes);

  /// Securely overwrites a byte buffer with zeroes before memory disposal.
  void zeroFill(Uint8List buffer);
}
