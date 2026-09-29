import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:uuid/uuid.dart';

import '../../core/constants/security_constants.dart';
import '../../core/errors/security_exceptions.dart';
import '../models/vault_entry.dart';
import '../services/contracts/i_biometric_auth_service.dart';
import '../services/contracts/i_secure_storage_service.dart';
import '../services/contracts/i_vault_crypto_service.dart';

/// Repository managing biometric and passcode protected AES-256-GCM vault operations.
/// Enforces authentication gates before vault unlocking, file encryption/decryption,
/// and master key alterations.
class VaultRepository {
  final IVaultCryptoService cryptoService;
  final IBiometricAuthService biometricService;
  final ISecureStorageService storageService;
  final Uuid _uuid;

  SecretKey? _activeMasterKey;
  bool _isUnlocked = false;

  // In-memory catalog of vault entries, indexed by ID
  final Map<String, VaultEntry> _entriesIndex = {};

  VaultRepository({
    required this.cryptoService,
    required this.biometricService,
    required this.storageService,
    Uuid? uuid,
  }) : _uuid = uuid ?? const Uuid();

  /// Whether the vault is currently unlocked and key is available in memory.
  bool get isUnlocked => _isUnlocked && _activeMasterKey != null;

  /// Retrieves all vault entries currently indexed.
  List<VaultEntry> get entries => List.unmodifiable(_entriesIndex.values);

  /// Authenticates using biometrics (or falls back to passcode) and unlocks the vault.
  Future<bool> unlockVaultWithBiometrics({String reason = 'Authenticate to access secure vault'}) async {
    final authResult = await biometricService.authenticate(
      localizedReason: reason,
      biometricOnly: false,
    );

    if (!authResult.isSuccess) {
      if (authResult.isLockedOut) {
        throw AuthenticationRequiredException(
          'Biometrics locked out. Please use fallback passcode.',
          authResult.errorMessage,
        );
      }
      throw AuthenticationRequiredException(
        authResult.errorMessage ?? 'Biometric authentication failed.',
      );
    }

    await _ensureMasterKeyLoaded();
    _isUnlocked = true;
    return true;
  }

  /// Unlocks the vault using the fallback user passcode.
  Future<bool> unlockVaultWithPasscode(String passcode) async {
    final saltBase64 = await storageService.read(key: SecurityConstants.keyPasscodeSalt);
    if (saltBase64 == null) {
      throw const AuthenticationRequiredException('No fallback passcode salt found. Please setup vault first.');
    }

    final salt = base64Decode(saltBase64);
    final derivedKey = await cryptoService.deriveKeyFromPasscode(
      passcode: passcode,
      salt: salt,
    );

    // Retrieve the passcode-wrapped master key container
    final wrappedKeyBase64 = await storageService.read(key: SecurityConstants.keyPasscodeWrappedMasterKey) ??
        await storageService.read(key: SecurityConstants.keyMasterVaultKey);

    if (wrappedKeyBase64 == null) {
      // If neither wrapped key nor master key existed yet, the derived key becomes the master key
      _activeMasterKey = derivedKey;
      final rawKeyBytes = await derivedKey.extractBytes();
      await storageService.write(
        key: SecurityConstants.keyMasterVaultKey,
        value: base64Encode(rawKeyBytes),
      );
    } else {
      final storedKeyBytes = base64Decode(wrappedKeyBase64);

      if (storedKeyBytes.length == 32) {
        // Direct key comparison or unencrypted master key payload
        _activeMasterKey = derivedKey;
      } else {
        // Stored as encrypted container
        try {
          final decryptedMasterBytes = await cryptoService.decryptBytes(
            encryptedContainer: storedKeyBytes,
            masterKey: derivedKey,
          );
          _activeMasterKey = SecretKey(decryptedMasterBytes);

          // If raw master key wasn't in storage for biometrics, save it now so biometric unlock can also use it
          final existingRawKey = await storageService.read(key: SecurityConstants.keyMasterVaultKey);
          if (existingRawKey == null) {
            await storageService.write(
              key: SecurityConstants.keyMasterVaultKey,
              value: base64Encode(decryptedMasterBytes),
            );
          }
        } catch (e) {
          throw AuthenticationRequiredException('Invalid passcode.', e);
        }
      }
    }

    _isUnlocked = true;
    return true;
  }

  /// Locks the vault and wipes active key from memory.
  void lockVault() {
    _activeMasterKey = null;
    _isUnlocked = false;
  }

  /// Sets up a new vault master key and registers fallback passcode with fresh salt.
  Future<void> setupVault({required String fallbackPasscode}) async {
    if (fallbackPasscode.length < 4) {
      throw ArgumentError('Passcode must be at least 4 characters.');
    }

    // Check if a master key already exists in secure storage
    final existingStoredKey = await storageService.read(key: SecurityConstants.keyMasterVaultKey);
    Uint8List masterKeyBytes;
    SecretKey masterKey;

    if (existingStoredKey != null) {
      final existingBytes = base64Decode(existingStoredKey);
      if (existingBytes.length == 32) {
        masterKeyBytes = existingBytes;
        masterKey = SecretKey(masterKeyBytes);
      } else {
        // If not 32 bytes (e.g. unexpected format), generate fresh key
        masterKey = await cryptoService.generateMasterKey();
        final extracted = await masterKey.extractBytes();
        masterKeyBytes = Uint8List.fromList(extracted);
      }
    } else {
      // Generate fresh master key
      masterKey = await cryptoService.generateMasterKey();
      final extracted = await masterKey.extractBytes();
      masterKeyBytes = Uint8List.fromList(extracted);
    }

    // Generate random 16-byte salt for PBKDF2
    final salt = Uint8List(16);
    final secureRandom = await cryptoService.generateMasterKey();
    final randomBytes = await secureRandom.extractBytes();
    for (int i = 0; i < 16; i++) {
      salt[i] = randomBytes[i];
    }

    // Derive passcode key
    final passcodeKey = await cryptoService.deriveKeyFromPasscode(
      passcode: fallbackPasscode,
      salt: salt,
    );

    // Wrap (encrypt) the master key using the passcode key
    final wrappedMasterKeyContainer = await cryptoService.encryptBytes(
      plaintext: Uint8List.fromList(masterKeyBytes),
      masterKey: passcodeKey,
    );

    // Save raw master key (hardware-backed KeyStore for biometrics),
    // wrapped master key (for passcode fallback), and salt to secure storage.
    await storageService.write(
      key: SecurityConstants.keyMasterVaultKey,
      value: base64Encode(masterKeyBytes),
    );
    await storageService.write(
      key: SecurityConstants.keyPasscodeWrappedMasterKey,
      value: base64Encode(wrappedMasterKeyContainer),
    );
    await storageService.write(
      key: SecurityConstants.keyPasscodeSalt,
      value: base64Encode(salt),
    );

    _activeMasterKey = masterKey;
    _isUnlocked = true;
  }

  /// Encrypts and adds a file to the secure vault.
  /// Throws [AuthenticationRequiredException] if vault is locked.
  Future<VaultEntry> encryptAndAddFile({
    required String sourceFilePath,
    required String destinationVaultDir,
    required String title,
    required String originalFileName,
    required String mimeType,
    String? tag,
  }) async {
    _enforceUnlocked();

    final sourceFile = File(sourceFilePath);
    if (!await sourceFile.exists()) {
      throw SecurityException('Source file does not exist: $sourceFilePath');
    }

    final fileId = _uuid.v4();
    final destFilePath = '$destinationVaultDir/$fileId.secv';

    final aad = Uint8List.fromList(utf8.encode(originalFileName));
    await cryptoService.encryptFile(
      sourcePath: sourceFilePath,
      destinationPath: destFilePath,
      masterKey: _activeMasterKey!,
      additionalData: aad,
    );

    final encFile = File(destFilePath);
    final fileSize = await encFile.length();

    final entry = VaultEntry(
      id: fileId,
      title: title,
      originalFileName: originalFileName,
      mimeType: mimeType,
      encryptedFilePath: destFilePath,
      fileSize: fileSize,
      createdAt: DateTime.now(),
      isEncrypted: true,
      tag: tag,
    );

    _entriesIndex[fileId] = entry;
    return entry;
  }

  /// Decrypts a vault file to [decryptedDestinationPath].
  /// Throws [AuthenticationRequiredException] if vault is locked.
  Future<String> decryptFile({
    required VaultEntry entry,
    required String decryptedDestinationPath,
  }) async {
    _enforceUnlocked();

    final aad = Uint8List.fromList(utf8.encode(entry.originalFileName));
    return await cryptoService.decryptFile(
      encryptedFilePath: entry.encryptedFilePath,
      decryptedDestinationPath: decryptedDestinationPath,
      masterKey: _activeMasterKey!,
      additionalData: aad,
    );
  }

  /// Directly encrypts byte array with master key (for in-memory payloads).
  Future<Uint8List> encryptBytes({
    required Uint8List plaintext,
    Uint8List? additionalData,
  }) async {
    _enforceUnlocked();
    return await cryptoService.encryptBytes(
      plaintext: plaintext,
      masterKey: _activeMasterKey!,
      additionalData: additionalData,
    );
  }

  /// Directly decrypts encrypted container bytes with master key.
  Future<Uint8List> decryptBytes({
    required Uint8List encryptedContainer,
    Uint8List? additionalData,
  }) async {
    _enforceUnlocked();
    return await cryptoService.decryptBytes(
      encryptedContainer: encryptedContainer,
      masterKey: _activeMasterKey!,
      additionalData: additionalData,
    );
  }

  /// Removes an entry from the vault and securely deletes the encrypted file from disk.
  Future<void> deleteEntry(String fileId) async {
    _enforceUnlocked();

    final entry = _entriesIndex.remove(fileId);
    if (entry != null) {
      final file = File(entry.encryptedFilePath);
      if (await file.exists()) {
        // Zero-fill file contents before deletion to prevent recovery
        final length = await file.length();
        final zeroes = Uint8List(length);
        await file.writeAsBytes(zeroes, flush: true);
        await file.delete();
      }
    }
  }

  void _enforceUnlocked() {
    if (!_isUnlocked || _activeMasterKey == null) {
      throw const AuthenticationRequiredException(
        'Vault is locked. Authentication is required before performing operations.',
      );
    }
  }

  Future<void> _ensureMasterKeyLoaded() async {
    if (_activeMasterKey != null) return;

    final storedKey = await storageService.read(key: SecurityConstants.keyMasterVaultKey);
    if (storedKey != null) {
      final bytes = base64Decode(storedKey);
      if (bytes.length == 32) {
        _activeMasterKey = SecretKey(bytes);
        return;
      }
      // If a non-32-byte key is stored under keyMasterVaultKey (e.g., legacy wrapped container),
      // do NOT overwrite it! An overwrite would permanently destroy access to existing encrypted files.
      throw const AuthenticationRequiredException(
        'Vault master key is wrapped by passcode. Please unlock with fallback passcode.',
      );
    }

    // Check if passcode-wrapped master key exists before generating a new key
    final wrappedKey = await storageService.read(key: SecurityConstants.keyPasscodeWrappedMasterKey);
    if (wrappedKey != null) {
      // Passcode-wrapped master key exists, so a master key already exists.
      // Do NOT overwrite it with a freshly generated key!
      throw const AuthenticationRequiredException(
        'Vault master key is locked with passcode. Please unlock with fallback passcode.',
      );
    }

    // Only if no master key or wrapped key exists anywhere in storage, generate a fresh key
    final newKey = await cryptoService.generateMasterKey();
    final newBytes = await newKey.extractBytes();
    await storageService.write(
      key: SecurityConstants.keyMasterVaultKey,
      value: base64Encode(newBytes),
    );
    _activeMasterKey = newKey;
  }
}
