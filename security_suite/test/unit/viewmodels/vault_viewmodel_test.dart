import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:security_suite/core/di/service_locator.dart';
import 'package:security_suite/data/repositories/vault_repository.dart';
import 'package:security_suite/data/services/contracts/i_biometric_auth_service.dart';
import 'package:security_suite/data/services/fakes/fake_biometric_auth_service.dart';
import 'package:security_suite/ui/viewmodels/vault_viewmodel.dart';

void main() {
  late FakeBiometricAuthService fakeBiometricService;
  late VaultRepository vaultRepo;
  late VaultViewModel viewModel;
  late Directory tempDir;

  setUp(() async {
    tempDir = await Directory.systemTemp.createTemp('sec_vault_vm_test_');

    fakeBiometricService = FakeBiometricAuthService(
      isHardwareAvailable: true,
      isEnrolled: true,
      shouldSucceed: true,
      availableTypes: [BiometricType.fingerprint],
    );

    await setupServiceLocator(
      useFakes: true,
      customBiometricService: fakeBiometricService,
    );

    vaultRepo = sl<VaultRepository>();
    // Set up initial vault with fallback passcode
    await vaultRepo.setupVault(fallbackPasscode: 'supersecretpin');
    // Lock vault so initial state is locked
    vaultRepo.lockVault();

    viewModel = VaultViewModel(vaultRepository: vaultRepo);
  });

  tearDown(() async {
    viewModel.dispose();
    await resetServiceLocator();
    if (await tempDir.exists()) {
      await tempDir.delete(recursive: true);
    }
  });

  group('VaultViewModel Unit Tests', () {
    test('initial state is locked with zero entries and no error', () {
      expect(viewModel.isUnlocked, isFalse);
      expect(viewModel.isProcessing, isFalse);
      expect(viewModel.errorMessage, isNull);
      expect(viewModel.entries, isEmpty);
    });

    test('enforces locked state operations when locked', () async {
      final sampleFile = File('${tempDir.path}/secret.txt');
      await sampleFile.writeAsString('sensitive data');

      final imported = await viewModel.importAndEncryptFile(
        sourcePath: sampleFile.path,
        fileName: 'secret.txt',
      );
      expect(imported, isNull);
      expect(viewModel.errorMessage, contains('Vault is locked'));

      final exported = await viewModel.decryptAndExportFile(
        entryId: 'nonexistent',
        destinationPath: '${tempDir.path}/out.txt',
      );
      expect(exported, isNull);
      expect(viewModel.errorMessage, contains('Vault is locked'));

      final deleted = await viewModel.deleteEntry('nonexistent');
      expect(deleted, isFalse);
      expect(viewModel.errorMessage, contains('Vault is locked'));
    });

    test('unlockWithBiometrics succeeds and unlocks vault', () async {
      fakeBiometricService.shouldSucceed = true;

      final unlocked = await viewModel.unlockWithBiometrics();

      expect(unlocked, isTrue);
      expect(viewModel.isUnlocked, isTrue);
      expect(viewModel.errorMessage, isNull);
    });

    test('unlockWithBiometrics sets error message on biometric failure', () async {
      fakeBiometricService.shouldSucceed = false;

      final unlocked = await viewModel.unlockWithBiometrics();

      expect(unlocked, isFalse);
      expect(viewModel.isUnlocked, isFalse);
      expect(viewModel.errorMessage, isNotNull);
    });

    test('unlockWithPasscode succeeds with correct passcode', () async {
      final unlocked = await viewModel.unlockWithPasscode('supersecretpin');

      expect(unlocked, isTrue);
      expect(viewModel.isUnlocked, isTrue);
      expect(viewModel.errorMessage, isNull);
    });

    test('unlockWithPasscode fails with invalid passcode', () async {
      final unlocked = await viewModel.unlockWithPasscode('wrongpassword');

      expect(unlocked, isFalse);
      expect(viewModel.isUnlocked, isFalse);
      expect(viewModel.errorMessage, contains('Invalid passcode'));
    });

    test('lockVault relocks the vault and clears active master key', () async {
      await viewModel.unlockWithPasscode('supersecretpin');
      expect(viewModel.isUnlocked, isTrue);

      await viewModel.lockVault();
      expect(viewModel.isUnlocked, isFalse);
    });

    test('import, decrypt export, and delete lifecycle when unlocked', () async {
      await viewModel.unlockWithPasscode('supersecretpin');

      final sourceFile = File('${tempDir.path}/data.txt');
      await sourceFile.writeAsString('Top secret document contents');

      final entry = await viewModel.importAndEncryptFile(
        sourcePath: sourceFile.path,
        fileName: 'data.txt',
        destinationVaultDir: tempDir.path,
      );

      expect(entry, isNotNull);
      expect(viewModel.entries.length, 1);
      expect(viewModel.entries.first.title, 'data.txt');

      // Decrypt & export
      final exportPath = '${tempDir.path}/exported_data.txt';
      final decrypted = await viewModel.decryptAndExportFile(
        entryId: entry!.id,
        destinationPath: exportPath,
      );

      expect(decrypted, equals(exportPath));
      final exportedContent = await File(exportPath).readAsString();
      expect(exportedContent, equals('Top secret document contents'));

      // Delete entry
      final deleted = await viewModel.deleteEntry(entry.id);
      expect(deleted, isTrue);
      expect(viewModel.entries, isEmpty);
    });
  });
}
