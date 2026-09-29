import 'dart:io';
import 'package:flutter/foundation.dart';

import '../../core/errors/security_exceptions.dart';
import '../../data/models/vault_entry.dart';
import '../../data/repositories/vault_repository.dart';

/// ViewModel managing biometric and passcode protected AES-256-GCM vault interactions.
/// Zero direct UI rendering logic.
class VaultViewModel extends ChangeNotifier {
  final VaultRepository vaultRepository;

  bool _isProcessing = false;
  String? _errorMessage;

  VaultViewModel({required this.vaultRepository});

  /// Whether the vault is currently unlocked with active master key.
  bool get isUnlocked => vaultRepository.isUnlocked;

  /// Whether a cryptographic or auth operation is currently executing.
  bool get isProcessing => _isProcessing;

  /// Error message from failed operations or authentication challenges.
  String? get errorMessage => _errorMessage;

  /// List of files currently stored and encrypted in the vault.
  List<VaultEntry> get entries => vaultRepository.entries;

  /// Unlocks the vault using device biometrics.
  Future<bool> unlockWithBiometrics() async {
    _isProcessing = true;
    _errorMessage = null;
    notifyListeners();

    try {
      final success = await vaultRepository.unlockVaultWithBiometrics();
      _isProcessing = false;
      notifyListeners();
      return success;
    } on AuthenticationRequiredException catch (e) {
      _errorMessage = e.message;
      _isProcessing = false;
      notifyListeners();
      return false;
    } catch (e) {
      _errorMessage = 'Biometric unlock failed: $e';
      _isProcessing = false;
      notifyListeners();
      return false;
    }
  }

  /// Unlocks the vault using user-defined fallback passcode.
  Future<bool> unlockWithPasscode(String passcode) async {
    _isProcessing = true;
    _errorMessage = null;
    notifyListeners();

    try {
      final success = await vaultRepository.unlockVaultWithPasscode(passcode);
      _isProcessing = false;
      notifyListeners();
      return success;
    } on AuthenticationRequiredException catch (e) {
      _errorMessage = e.message;
      _isProcessing = false;
      notifyListeners();
      return false;
    } catch (e) {
      _errorMessage = 'Passcode unlock failed: $e';
      _isProcessing = false;
      notifyListeners();
      return false;
    }
  }

  /// Locks the vault and zeros out active key in memory.
  Future<void> lockVault() async {
    vaultRepository.lockVault();
    _errorMessage = null;
    notifyListeners();
  }

  /// Encrypts an external file and stores it into the vault.
  Future<VaultEntry?> importAndEncryptFile({
    required String sourcePath,
    required String fileName,
    String? mimeType,
    String? destinationVaultDir,
  }) async {
    if (!isUnlocked) {
      _errorMessage = 'Vault is locked. Authentication required before importing files.';
      notifyListeners();
      return null;
    }

    _isProcessing = true;
    _errorMessage = null;
    notifyListeners();

    try {
      final destDir = destinationVaultDir ?? File(sourcePath).parent.path;
      final entry = await vaultRepository.encryptAndAddFile(
        sourceFilePath: sourcePath,
        destinationVaultDir: destDir,
        title: fileName,
        originalFileName: fileName,
        mimeType: mimeType ?? 'application/octet-stream',
      );

      _isProcessing = false;
      notifyListeners();
      return entry;
    } catch (e) {
      _errorMessage = 'Failed to import and encrypt file: $e';
      _isProcessing = false;
      notifyListeners();
      return null;
    }
  }

  /// Decrypts a vault file to destination path.
  Future<String?> decryptAndExportFile({
    required String entryId,
    required String destinationPath,
  }) async {
    if (!isUnlocked) {
      _errorMessage = 'Vault is locked. Authentication required before decrypting files.';
      notifyListeners();
      return null;
    }

    _isProcessing = true;
    _errorMessage = null;
    notifyListeners();

    try {
      final entry = entries.firstWhere(
        (e) => e.id == entryId,
        orElse: () => throw SecurityException('Vault entry not found: $entryId'),
      );

      final decryptedPath = await vaultRepository.decryptFile(
        entry: entry,
        decryptedDestinationPath: destinationPath,
      );

      _isProcessing = false;
      notifyListeners();
      return decryptedPath;
    } catch (e) {
      _errorMessage = 'Failed to decrypt and export file: $e';
      _isProcessing = false;
      notifyListeners();
      return null;
    }
  }

  /// Removes an entry and securely deletes the encrypted file from storage.
  Future<bool> deleteEntry(String entryId) async {
    if (!isUnlocked) {
      _errorMessage = 'Vault is locked. Authentication required.';
      notifyListeners();
      return false;
    }

    _isProcessing = true;
    _errorMessage = null;
    notifyListeners();

    try {
      await vaultRepository.deleteEntry(entryId);
      _isProcessing = false;
      notifyListeners();
      return true;
    } catch (e) {
      _errorMessage = 'Failed to delete vault entry: $e';
      _isProcessing = false;
      notifyListeners();
      return false;
    }
  }
}
