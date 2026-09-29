import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';

import 'package:security_suite/core/di/service_locator.dart';
import 'package:security_suite/core/errors/security_exceptions.dart';
import 'package:security_suite/data/models/vault_entry.dart';
import 'package:security_suite/data/repositories/vault_repository.dart';
import 'package:security_suite/data/services/contracts/i_biometric_auth_service.dart';
import 'package:security_suite/data/services/contracts/i_vault_crypto_service.dart';
import 'package:security_suite/data/services/fakes/fake_biometric_auth_service.dart';
import 'package:security_suite/data/services/fakes/fake_secure_storage_service.dart';
import 'package:security_suite/data/services/fakes/fake_vault_crypto_service.dart';
import 'package:security_suite/data/services/implementations/aes_gcm_vault_crypto_service.dart';
import 'package:security_suite/data/services/implementations/local_auth_biometric_service.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late AesGcmVaultCryptoService prodCryptoService;
  late FakeBiometricAuthService fakeBiometricService;
  late FakeSecureStorageService fakeSecureStorage;
  late VaultRepository vaultRepository;
  late Directory tempTestDir;

  setUp(() async {
    prodCryptoService = AesGcmVaultCryptoService();
    fakeBiometricService = FakeBiometricAuthService();
    fakeSecureStorage = FakeSecureStorageService();

    vaultRepository = VaultRepository(
      cryptoService: prodCryptoService,
      biometricService: fakeBiometricService,
      storageService: fakeSecureStorage,
    );

    tempTestDir = await Directory.systemTemp.createTemp('sec_vault_test_');
  });

  tearDown(() async {
    if (await tempTestDir.exists()) {
      await tempTestDir.delete(recursive: true);
    }
  });

  group('VaultEntry Model Serialization', () {
    test('roundtrips VaultEntry through toMap and fromMap', () {
      final now = DateTime.now();
      final entry = VaultEntry(
        id: 'vault-uuid-1',
        title: 'Secret Token',
        originalFileName: 'token.txt',
        mimeType: 'text/plain',
        encryptedFilePath: '/vault/token.secv',
        fileSize: 1024,
        createdAt: now,
        isEncrypted: true,
        tag: 'financial',
      );

      final map = entry.toMap();
      final reconstructed = VaultEntry.fromMap(map);

      expect(reconstructed.id, equals(entry.id));
      expect(reconstructed.title, equals(entry.title));
      expect(reconstructed.originalFileName, equals(entry.originalFileName));
      expect(reconstructed.mimeType, equals(entry.mimeType));
      expect(reconstructed.encryptedFilePath, equals(entry.encryptedFilePath));
      expect(reconstructed.fileSize, equals(entry.fileSize));
      expect(reconstructed.isEncrypted, isTrue);
      expect(reconstructed.tag, equals('financial'));
      expect(reconstructed, equals(entry));
    });

    test('roundtrips VaultEntry through toJson and fromJson', () {
      final now = DateTime.now();
      final entry = VaultEntry(
        id: 'vault-uuid-2',
        title: 'Passport Scan',
        originalFileName: 'passport.pdf',
        mimeType: 'application/pdf',
        encryptedFilePath: '/vault/passport.secv',
        fileSize: 204800,
        createdAt: now,
      );

      final jsonStr = entry.toJson();
      final reconstructed = VaultEntry.fromJson(jsonStr);

      expect(reconstructed.id, equals(entry.id));
      expect(reconstructed.fileSize, equals(204800));
      expect(reconstructed.isEncrypted, isTrue);
      expect(reconstructed.tag, isNull);
    });

    test('copyWith updates specified fields correctly', () {
      final now = DateTime.now();
      final entry = VaultEntry(
        id: 'entry-1',
        title: 'Old Title',
        originalFileName: 'file.txt',
        mimeType: 'text/plain',
        encryptedFilePath: '/path/file.secv',
        fileSize: 10,
        createdAt: now,
      );

      final updated = entry.copyWith(title: 'New Title', fileSize: 50);
      expect(updated.title, equals('New Title'));
      expect(updated.fileSize, equals(50));
      expect(updated.id, equals('entry-1'));
    });
  });

  group('AES-256-GCM Encryption & Decryption Round-Trip', () {
    test('encrypts and decrypts UTF-8 plaintext accurately', () async {
      final masterKey = await prodCryptoService.generateMasterKey();
      const originalText = 'Confidential System Diagnostics & Credentials 2026';
      final plaintextBytes = Uint8List.fromList(utf8.encode(originalText));

      final container = await prodCryptoService.encryptBytes(
        plaintext: plaintextBytes,
        masterKey: masterKey,
      );

      expect(container.length, greaterThan(33));

      final decryptedBytes = await prodCryptoService.decryptBytes(
        encryptedContainer: container,
        masterKey: masterKey,
      );

      expect(utf8.decode(decryptedBytes), equals(originalText));
    });

    test('encrypts and decrypts with Additional Authenticated Data (AAD)', () async {
      final masterKey = await prodCryptoService.generateMasterKey();
      final plaintext = Uint8List.fromList(utf8.encode('Secret Document Payload'));
      final aad = Uint8List.fromList(utf8.encode('doc_id=12345;user=admin'));

      final container = await prodCryptoService.encryptBytes(
        plaintext: plaintext,
        masterKey: masterKey,
        additionalData: aad,
      );

      final decrypted = await prodCryptoService.decryptBytes(
        encryptedContainer: container,
        masterKey: masterKey,
        additionalData: aad,
      );

      expect(utf8.decode(decrypted), equals('Secret Document Payload'));
    });

    test('decryption fails if AAD does not match', () async {
      final masterKey = await prodCryptoService.generateMasterKey();
      final plaintext = Uint8List.fromList(utf8.encode('Secret Document Payload'));
      final aad = Uint8List.fromList(utf8.encode('doc_id=12345;user=admin'));
      final wrongAad = Uint8List.fromList(utf8.encode('doc_id=12345;user=attacker'));

      final container = await prodCryptoService.encryptBytes(
        plaintext: plaintext,
        masterKey: masterKey,
        additionalData: aad,
      );

      expect(
        () async => await prodCryptoService.decryptBytes(
          encryptedContainer: container,
          masterKey: masterKey,
          additionalData: wrongAad,
        ),
        throwsA(isA<CryptographicIntegrityException>()),
      );
    });

    test('generates unique 12-byte nonce on every encryption call with identical key & data', () async {
      final masterKey = await prodCryptoService.generateMasterKey();
      final plaintext = Uint8List.fromList(utf8.encode('Same Repeated String'));

      final container1 = await prodCryptoService.encryptBytes(
        plaintext: plaintext,
        masterKey: masterKey,
      );
      final container2 = await prodCryptoService.encryptBytes(
        plaintext: plaintext,
        masterKey: masterKey,
      );

      final parsed1 = prodCryptoService.parseContainer(container1);
      final parsed2 = prodCryptoService.parseContainer(container2);

      // Nonces must be unique 12-byte sequences
      expect(parsed1.nonce.length, equals(12));
      expect(parsed2.nonce.length, equals(12));
      expect(parsed1.nonce, isNot(equals(parsed2.nonce)));
      expect(parsed1.ciphertext, isNot(equals(parsed2.ciphertext)));
    });
  });

  group('Binary Container Structure & Tamper Detection', () {
    test('validates 5-part header layout: Magic (4B) + Version (1B) + Nonce (12B) + Tag (16B) + Ciphertext', () async {
      final masterKey = await prodCryptoService.generateMasterKey();
      final plaintext = Uint8List.fromList(utf8.encode('Container Format Check'));

      final container = await prodCryptoService.encryptBytes(
        plaintext: plaintext,
        masterKey: masterKey,
      );

      final parsed = prodCryptoService.parseContainer(container);
      expect(parsed.rawBytes.length, equals(33 + plaintext.length));
      expect(parsed.magic, equals(AesGcmVaultCryptoService.magicSecv));
      expect(parsed.version, equals(0x01));
      expect(parsed.nonce.length, equals(12));
      expect(parsed.tag.length, equals(16));
      expect(parsed.ciphertext.length, equals(plaintext.length));
      expect(parsed.isValidHeader, isTrue);
    });

    test('rejects truncated container shorter than 33 bytes', () async {
      final truncatedBytes = Uint8List(20);
      expect(
        () => prodCryptoService.parseContainer(truncatedBytes),
        throwsA(isA<CryptographicIntegrityException>()),
      );
    });

    test('rejects corrupted magic bytes', () async {
      final masterKey = await prodCryptoService.generateMasterKey();
      final container = await prodCryptoService.encryptBytes(
        plaintext: Uint8List.fromList([1, 2, 3, 4]),
        masterKey: masterKey,
      );

      final corrupted = Uint8List.fromList(container);
      corrupted[0] = 0x00; // Corrupt magic

      expect(
        () => prodCryptoService.parseContainer(corrupted),
        throwsA(isA<CryptographicIntegrityException>()),
      );
    });

    test('rejects unsupported format version', () async {
      final masterKey = await prodCryptoService.generateMasterKey();
      final container = await prodCryptoService.encryptBytes(
        plaintext: Uint8List.fromList([1, 2, 3, 4]),
        masterKey: masterKey,
      );

      final corrupted = Uint8List.fromList(container);
      corrupted[4] = 0x02; // Version 2

      expect(
        () => prodCryptoService.parseContainer(corrupted),
        throwsA(isA<CryptographicIntegrityException>()),
      );
    });

    test('detects tampered ciphertext byte and throws CryptographicIntegrityException', () async {
      final masterKey = await prodCryptoService.generateMasterKey();
      final container = await prodCryptoService.encryptBytes(
        plaintext: Uint8List.fromList(utf8.encode('Highly Secure Information')),
        masterKey: masterKey,
      );

      final tampered = Uint8List.fromList(container);
      tampered[tampered.length - 1] ^= 0x01; // Bit flip in ciphertext

      expect(
        () async => await prodCryptoService.decryptBytes(
          encryptedContainer: tampered,
          masterKey: masterKey,
        ),
        throwsA(isA<CryptographicIntegrityException>()),
      );
    });

    test('detects tampered authentication tag byte and throws CryptographicIntegrityException', () async {
      final masterKey = await prodCryptoService.generateMasterKey();
      final container = await prodCryptoService.encryptBytes(
        plaintext: Uint8List.fromList(utf8.encode('Highly Secure Information')),
        masterKey: masterKey,
      );

      final tampered = Uint8List.fromList(container);
      // Tag is located at indices 17 to 32
      tampered[20] ^= 0xFF;

      expect(
        () async => await prodCryptoService.decryptBytes(
          encryptedContainer: tampered,
          masterKey: masterKey,
        ),
        throwsA(isA<CryptographicIntegrityException>()),
      );
    });
  });

  group('PBKDF2 Key Derivation & Salt Sensitivity', () {
    test('derives identical 256-bit key when passcode and salt match', () async {
      final salt = Uint8List.fromList(List.generate(16, (i) => i * 3));
      const passcode = 'MySecureVaultPassword2026!';

      final key1 = await prodCryptoService.deriveKeyFromPasscode(
        passcode: passcode,
        salt: salt,
        iterations: 1000,
      );
      final key2 = await prodCryptoService.deriveKeyFromPasscode(
        passcode: passcode,
        salt: salt,
        iterations: 1000,
      );

      final bytes1 = await key1.extractBytes();
      final bytes2 = await key2.extractBytes();

      expect(bytes1.length, equals(32));
      expect(bytes1, equals(bytes2));
    });

    test('derives different key when single character in passcode differs', () async {
      final salt = Uint8List.fromList(List.generate(16, (i) => i));

      final key1 = await prodCryptoService.deriveKeyFromPasscode(
        passcode: 'SecretPass1',
        salt: salt,
        iterations: 1000,
      );
      final key2 = await prodCryptoService.deriveKeyFromPasscode(
        passcode: 'SecretPass2',
        salt: salt,
        iterations: 1000,
      );

      final bytes1 = await key1.extractBytes();
      final bytes2 = await key2.extractBytes();

      expect(bytes1, isNot(equals(bytes2)));
    });

    test('derives different key when salt differs', () async {
      final salt1 = Uint8List.fromList(List.generate(16, (i) => i));
      final salt2 = Uint8List.fromList(List.generate(16, (i) => i + 1));

      final key1 = await prodCryptoService.deriveKeyFromPasscode(
        passcode: 'IdenticalPass',
        salt: salt1,
        iterations: 1000,
      );
      final key2 = await prodCryptoService.deriveKeyFromPasscode(
        passcode: 'IdenticalPass',
        salt: salt2,
        iterations: 1000,
      );

      final bytes1 = await key1.extractBytes();
      final bytes2 = await key2.extractBytes();

      expect(bytes1, isNot(equals(bytes2)));
    });
  });

  group('File Operations, Atomic Writing & Buffer Shredding', () {
    test('encryptFile writes atomic container to disk and decryptFile restores exact file', () async {
      final sourceFile = File('${tempTestDir.path}/original.txt');
      await sourceFile.writeAsString('Nuclear Launch Codes & Banking Secrets');

      final encryptedDestPath = '${tempTestDir.path}/encrypted.secv';
      final decryptedDestPath = '${tempTestDir.path}/restored.txt';

      final masterKey = await prodCryptoService.generateMasterKey();
      final payload = await prodCryptoService.encryptFile(
        sourcePath: sourceFile.path,
        destinationPath: encryptedDestPath,
        masterKey: masterKey,
      );

      expect(payload.isValidHeader, isTrue);
      expect(await File(encryptedDestPath).exists(), isTrue);

      final restoredPath = await prodCryptoService.decryptFile(
        encryptedFilePath: encryptedDestPath,
        decryptedDestinationPath: decryptedDestPath,
        masterKey: masterKey,
      );

      expect(restoredPath, equals(decryptedDestPath));
      final restoredContent = await File(decryptedDestPath).readAsString();
      expect(restoredContent, equals('Nuclear Launch Codes & Banking Secrets'));
    });

    test('zeroFill securely overwrites buffer with zeroes', () {
      final buffer = Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
      expect(buffer.every((b) => b == 0), isFalse);

      prodCryptoService.zeroFill(buffer);
      expect(buffer.every((b) => b == 0), isTrue);
    });
  });

  group('Biometric Gate Enforcement & Fallback Unlock in VaultRepository', () {
    test('operations fail when vault is locked', () async {
      expect(vaultRepository.isUnlocked, isFalse);

      expect(
        () async => await vaultRepository.encryptBytes(
          plaintext: Uint8List.fromList([1, 2, 3]),
        ),
        throwsA(isA<AuthenticationRequiredException>()),
      );

      expect(
        () async => await vaultRepository.encryptAndAddFile(
          sourceFilePath: '${tempTestDir.path}/file.txt',
          destinationVaultDir: tempTestDir.path,
          title: 'Title',
          originalFileName: 'file.txt',
          mimeType: 'text/plain',
        ),
        throwsA(isA<AuthenticationRequiredException>()),
      );
    });

    test('unlocks vault via biometrics and performs file operations', () async {
      fakeBiometricService.isHardwareAvailable = true;
      fakeBiometricService.isEnrolled = true;
      fakeBiometricService.shouldSucceed = true;

      final unlocked = await vaultRepository.unlockVaultWithBiometrics();
      expect(unlocked, isTrue);
      expect(vaultRepository.isUnlocked, isTrue);

      // Create test file
      final testFile = File('${tempTestDir.path}/secret_doc.txt');
      await testFile.writeAsString('Top secret research data');

      final entry = await vaultRepository.encryptAndAddFile(
        sourceFilePath: testFile.path,
        destinationVaultDir: tempTestDir.path,
        title: 'Research',
        originalFileName: 'secret_doc.txt',
        mimeType: 'text/plain',
        tag: 'research',
      );

      expect(entry.isEncrypted, isTrue);
      expect(vaultRepository.entries.length, equals(1));

      // Decrypt file back
      final decryptedPath = '${tempTestDir.path}/decrypted_doc.txt';
      await vaultRepository.decryptFile(
        entry: entry,
        decryptedDestinationPath: decryptedPath,
      );

      final decryptedContent = await File(decryptedPath).readAsString();
      expect(decryptedContent, equals('Top secret research data'));

      // Relock vault
      vaultRepository.lockVault();
      expect(vaultRepository.isUnlocked, isFalse);
    });

    test('biometric failure prevents unlocking vault', () async {
      fakeBiometricService.shouldSucceed = false;

      expect(
        () async => await vaultRepository.unlockVaultWithBiometrics(),
        throwsA(isA<AuthenticationRequiredException>()),
      );
      expect(vaultRepository.isUnlocked, isFalse);
    });

    test('biometric lockout raises specific lockout exception', () async {
      fakeBiometricService.isLockedOut = true;

      expect(
        () async => await vaultRepository.unlockVaultWithBiometrics(),
        throwsA(predicate((e) =>
            e is AuthenticationRequiredException &&
            e.message.contains('Biometrics locked out'))),
      );
    });

    test('unlocks vault via fallback passcode after setupVault', () async {
      await vaultRepository.setupVault(fallbackPasscode: 'VaultPass2026');
      expect(vaultRepository.isUnlocked, isTrue);

      // Lock vault
      vaultRepository.lockVault();
      expect(vaultRepository.isUnlocked, isFalse);

      // Wrong passcode fails
      expect(
        () async => await vaultRepository.unlockVaultWithPasscode('WrongPasscode'),
        throwsA(isA<AuthenticationRequiredException>()),
      );
      expect(vaultRepository.isUnlocked, isFalse);

      // Correct passcode succeeds
      final unlocked = await vaultRepository.unlockVaultWithPasscode('VaultPass2026');
      expect(unlocked, isTrue);
      expect(vaultRepository.isUnlocked, isTrue);
    });

    test('dual unlock pathways restore active master key and decrypt files across unlocks without clobbering', () async {
      // 1. Setup vault with passcode
      await vaultRepository.setupVault(fallbackPasscode: 'DualUnlockKey!2026');
      expect(vaultRepository.isUnlocked, isTrue);

      // 2. Encrypt a file while unlocked after setup
      final file1 = File('${tempTestDir.path}/passcode_encrypted.txt');
      await file1.writeAsString('PasscodeSecretData12345');
      final entry1 = await vaultRepository.encryptAndAddFile(
        sourceFilePath: file1.path,
        destinationVaultDir: tempTestDir.path,
        title: 'File 1',
        originalFileName: 'passcode_encrypted.txt',
        mimeType: 'text/plain',
      );

      // 3. Lock vault
      vaultRepository.lockVault();
      expect(vaultRepository.isUnlocked, isFalse);

      // 4. Unlock with biometrics - MUST restore the SAME master key and not clobber it
      fakeBiometricService.shouldSucceed = true;
      final biometricUnlocked = await vaultRepository.unlockVaultWithBiometrics();
      expect(biometricUnlocked, isTrue);
      expect(vaultRepository.isUnlocked, isTrue);

      // Decrypt the file encrypted before lock
      final decryptedPath1 = '${tempTestDir.path}/decrypted_after_biometrics.txt';
      await vaultRepository.decryptFile(
        entry: entry1,
        decryptedDestinationPath: decryptedPath1,
      );
      expect(await File(decryptedPath1).readAsString(), equals('PasscodeSecretData12345'));

      // Encrypt a second file while unlocked via biometrics
      final file2 = File('${tempTestDir.path}/biometric_encrypted.txt');
      await file2.writeAsString('BiometricSecretData67890');
      final entry2 = await vaultRepository.encryptAndAddFile(
        sourceFilePath: file2.path,
        destinationVaultDir: tempTestDir.path,
        title: 'File 2',
        originalFileName: 'biometric_encrypted.txt',
        mimeType: 'text/plain',
      );

      // 5. Lock vault again
      vaultRepository.lockVault();
      expect(vaultRepository.isUnlocked, isFalse);

      // 6. Unlock with fallback passcode
      final passcodeUnlocked = await vaultRepository.unlockVaultWithPasscode('DualUnlockKey!2026');
      expect(passcodeUnlocked, isTrue);
      expect(vaultRepository.isUnlocked, isTrue);

      // Decrypt both files - proves master key was never clobbered or regenerated!
      final decryptedPath2 = '${tempTestDir.path}/decrypted_after_passcode_2.txt';
      await vaultRepository.decryptFile(
        entry: entry2,
        decryptedDestinationPath: decryptedPath2,
      );
      expect(await File(decryptedPath2).readAsString(), equals('BiometricSecretData67890'));

      final decryptedPath1Again = '${tempTestDir.path}/decrypted_after_passcode_1.txt';
      await vaultRepository.decryptFile(
        entry: entry1,
        decryptedDestinationPath: decryptedPath1Again,
      );
      expect(await File(decryptedPath1Again).readAsString(), equals('PasscodeSecretData12345'));
    });

    test('deleteEntry wipes file from disk before deletion', () async {
      fakeBiometricService.shouldSucceed = true;
      await vaultRepository.unlockVaultWithBiometrics();

      final sourceFile = File('${tempTestDir.path}/to_delete.txt');
      await sourceFile.writeAsString('Data to wipe completely');

      final entry = await vaultRepository.encryptAndAddFile(
        sourceFilePath: sourceFile.path,
        destinationVaultDir: tempTestDir.path,
        title: 'Temporary',
        originalFileName: 'to_delete.txt',
        mimeType: 'text/plain',
      );

      expect(await File(entry.encryptedFilePath).exists(), isTrue);
      expect(vaultRepository.entries.length, equals(1));

      await vaultRepository.deleteEntry(entry.id);
      expect(vaultRepository.entries.length, equals(0));
      expect(await File(entry.encryptedFilePath).exists(), isFalse);
    });
  });

  group('Dependency Injection & Service Locator Registration', () {
    test('setupServiceLocator registers fakes properly when useFakes is true', () async {
      await setupServiceLocator(useFakes: true);

      expect(sl.isRegistered<IVaultCryptoService>(), isTrue);
      expect(sl.isRegistered<IBiometricAuthService>(), isTrue);
      expect(sl.isRegistered<VaultRepository>(), isTrue);

      expect(sl<IVaultCryptoService>(), isA<FakeVaultCryptoService>());
      expect(sl<IBiometricAuthService>(), isA<FakeBiometricAuthService>());
    });

    test('setupServiceLocator registers production services when useFakes is false', () async {
      await setupServiceLocator(useFakes: false);

      expect(sl.isRegistered<IVaultCryptoService>(), isTrue);
      expect(sl.isRegistered<IBiometricAuthService>(), isTrue);
      expect(sl.isRegistered<VaultRepository>(), isTrue);

      expect(sl<IVaultCryptoService>(), isA<AesGcmVaultCryptoService>());
      expect(sl<IBiometricAuthService>(), isA<LocalAuthBiometricService>());
    });
  });
}
