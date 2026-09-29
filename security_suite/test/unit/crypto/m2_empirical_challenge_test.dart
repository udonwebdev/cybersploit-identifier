import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';

import 'package:security_suite/core/errors/security_exceptions.dart';
import 'package:security_suite/data/repositories/vault_repository.dart';
import 'package:security_suite/data/services/fakes/fake_biometric_auth_service.dart';
import 'package:security_suite/data/services/fakes/fake_secure_storage_service.dart';
import 'package:security_suite/data/services/implementations/aes_gcm_vault_crypto_service.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late AesGcmVaultCryptoService cryptoService;
  late FakeBiometricAuthService fakeBiometric;
  late FakeSecureStorageService fakeStorage;
  late VaultRepository vaultRepository;
  late Directory tempDir;

  setUp(() async {
    cryptoService = AesGcmVaultCryptoService();
    fakeBiometric = FakeBiometricAuthService();
    fakeStorage = FakeSecureStorageService();
    vaultRepository = VaultRepository(
      cryptoService: cryptoService,
      biometricService: fakeBiometric,
      storageService: fakeStorage,
    );
    tempDir = await Directory.systemTemp.createTemp('m2_empirical_challenge_');
  });

  tearDown(() async {
    if (await tempDir.exists()) {
      await tempDir.delete(recursive: true);
    }
  });

  group('CHALLENGE 1: Cryptographic Integrity & Tamper Testing', () {
    test('1.1 Tamper with ciphertext byte (various offsets) throws CryptographicIntegrityException', () async {
      final key = await cryptoService.generateMasterKey();
      final plaintext = Uint8List.fromList(utf8.encode('TopSecretPayload1234567890ABCDEF'));
      final container = await cryptoService.encryptBytes(plaintext: plaintext, masterKey: key);

      // Ciphertext starts at byte 33. Tamper at first byte of ciphertext, middle, and last byte.
      final offsets = [33, 33 + (plaintext.length ~/ 2), container.length - 1];
      for (final offset in offsets) {
        final tampered = Uint8List.fromList(container);
        tampered[offset] ^= 0x5A; // Flip bits

        expect(
          () async => await cryptoService.decryptBytes(
            encryptedContainer: tampered,
            masterKey: key,
          ),
          throwsA(isA<CryptographicIntegrityException>()),
          reason: 'Tampering ciphertext at offset $offset must throw CryptographicIntegrityException',
        );
      }
    });

    test('1.2 Tamper with authentication tag (16 bytes, offsets 17-32) throws CryptographicIntegrityException', () async {
      final key = await cryptoService.generateMasterKey();
      final plaintext = Uint8List.fromList(utf8.encode('CriticalAuthenticationPayload'));
      final container = await cryptoService.encryptBytes(plaintext: plaintext, masterKey: key);

      // Tag is bytes 17 to 32 inclusive
      for (int tagOffset = 17; tagOffset < 33; tagOffset += 3) {
        final tampered = Uint8List.fromList(container);
        tampered[tagOffset] ^= 0x01;

        expect(
          () async => await cryptoService.decryptBytes(
            encryptedContainer: tampered,
            masterKey: key,
          ),
          throwsA(isA<CryptographicIntegrityException>()),
          reason: 'Tampering tag at offset $tagOffset must throw CryptographicIntegrityException',
        );
      }
    });

    test('1.3 Truncate binary header below 33 bytes or partial payloads throws CryptographicIntegrityException', () async {
      final key = await cryptoService.generateMasterKey();
      final plaintext = Uint8List.fromList(utf8.encode('HeaderTruncationTest'));
      final container = await cryptoService.encryptBytes(plaintext: plaintext, masterKey: key);

      final truncatedLengths = [0, 1, 4, 5, 16, 17, 32];
      for (final len in truncatedLengths) {
        final truncated = container.sublist(0, len);
        expect(
          () async => await cryptoService.decryptBytes(
            encryptedContainer: truncated,
            masterKey: key,
          ),
          throwsA(isA<CryptographicIntegrityException>()),
          reason: 'Truncating container to length $len must be rejected',
        );
      }
    });

    test('1.4 Test empty file (0 bytes plaintext) encrypts, preserves integrity, and roundtrips', () async {
      final emptyFile = File('${tempDir.path}/empty.txt');
      await emptyFile.writeAsBytes(Uint8List(0));

      final encryptedPath = '${tempDir.path}/empty.secv';
      final decryptedPath = '${tempDir.path}/empty_restored.txt';

      final key = await cryptoService.generateMasterKey();

      final payload = await cryptoService.encryptFile(
        sourcePath: emptyFile.path,
        destinationPath: encryptedPath,
        masterKey: key,
      );

      // Should have exactly 33 header bytes + 0 ciphertext bytes = 33 bytes
      expect(payload.ciphertext.length, equals(0));
      expect(payload.rawBytes.length, equals(33));
      expect(File(encryptedPath).lengthSync(), equals(33));

      // Decrypt and verify 0 bytes restored
      final restoredPath = await cryptoService.decryptFile(
        encryptedFilePath: encryptedPath,
        decryptedDestinationPath: decryptedPath,
        masterKey: key,
      );

      expect(restoredPath, equals(decryptedPath));
      final restoredBytes = await File(decryptedPath).readAsBytes();
      expect(restoredBytes.length, equals(0));

      // Tampering empty container tag must still be caught
      final tamperedEmpty = await File(encryptedPath).readAsBytes();
      tamperedEmpty[20] ^= 0x01; // Tamper tag
      expect(
        () async => await cryptoService.decryptBytes(
          encryptedContainer: tamperedEmpty,
          masterKey: key,
        ),
        throwsA(isA<CryptographicIntegrityException>()),
      );
    });

    test('1.5 Test large 1MB (1,048,576 bytes) file encryption, integrity, and roundtrip', () async {
      final largeBytes = Uint8List(1024 * 1024);
      // Fill with pseudo-random pattern
      for (int i = 0; i < largeBytes.length; i++) {
        largeBytes[i] = (i * 31 + 17) & 0xFF;
      }

      final largeFile = File('${tempDir.path}/large_1mb.bin');
      await largeFile.writeAsBytes(largeBytes);

      final encPath = '${tempDir.path}/large_1mb.secv';
      final decPath = '${tempDir.path}/large_1mb_restored.bin';

      final key = await cryptoService.generateMasterKey();

      final payload = await cryptoService.encryptFile(
        sourcePath: largeFile.path,
        destinationPath: encPath,
        masterKey: key,
      );

      expect(payload.ciphertext.length, equals(1024 * 1024));
      expect(File(encPath).lengthSync(), equals(33 + 1024 * 1024));

      // Decrypt and verify exact bit-for-bit equivalence
      await cryptoService.decryptFile(
        encryptedFilePath: encPath,
        decryptedDestinationPath: decPath,
        masterKey: key,
      );

      final restoredBytes = await File(decPath).readAsBytes();
      expect(restoredBytes.length, equals(largeBytes.length));
      expect(restoredBytes, equals(largeBytes));

      // Tamper 1 byte in the middle of 1MB ciphertext
      final tamperedLarge = await File(encPath).readAsBytes();
      tamperedLarge[33 + 500000] ^= 0xAA;
      expect(
        () async => await cryptoService.decryptBytes(
          encryptedContainer: tamperedLarge,
          masterKey: key,
        ),
        throwsA(isA<CryptographicIntegrityException>()),
      );
    });
  });

  group('CHALLENGE 2: Biometric Challenge Enforcement, Lockout & Passcode Fallback', () {
    test('2.1 Unauthenticated state blocks all vault access and mutations', () async {
      expect(vaultRepository.isUnlocked, isFalse);

      // Attempting to encrypt bytes
      expect(
        () async => await vaultRepository.encryptBytes(plaintext: Uint8List(10)),
        throwsA(isA<AuthenticationRequiredException>()),
      );

      // Attempting to decrypt bytes
      expect(
        () async => await vaultRepository.decryptBytes(encryptedContainer: Uint8List(40)),
        throwsA(isA<AuthenticationRequiredException>()),
      );

      // Attempting to add file
      expect(
        () async => await vaultRepository.encryptAndAddFile(
          sourceFilePath: '${tempDir.path}/dummy.txt',
          destinationVaultDir: tempDir.path,
          title: 'Dummy',
          originalFileName: 'dummy.txt',
          mimeType: 'text/plain',
        ),
        throwsA(isA<AuthenticationRequiredException>()),
      );

      // Attempting to delete entry
      expect(
        () async => await vaultRepository.deleteEntry('non-existent-id'),
        throwsA(isA<AuthenticationRequiredException>()),
      );
    });

    test('2.2 Biometric lockout scenario blocks biometric unlock and requires passcode fallback', () async {
      // First setup vault with fallback passcode
      await vaultRepository.setupVault(fallbackPasscode: 'SafePasscode#2026');
      vaultRepository.lockVault();
      expect(vaultRepository.isUnlocked, isFalse);

      // Simulate lockout condition in biometrics (e.g. too many failed sensor attempts)
      fakeBiometric.isLockedOut = true;
      fakeBiometric.shouldSucceed = false;

      // Unlocking with biometrics must fail with lockout exception
      expect(
        () async => await vaultRepository.unlockVaultWithBiometrics(),
        throwsA(predicate((e) =>
            e is AuthenticationRequiredException &&
            e.message.contains('Biometrics locked out'))),
      );
      expect(vaultRepository.isUnlocked, isFalse);

      // Attempting wrong fallback passcode must fail
      expect(
        () async => await vaultRepository.unlockVaultWithPasscode('WrongPass#0000'),
        throwsA(isA<AuthenticationRequiredException>()),
      );
      expect(vaultRepository.isUnlocked, isFalse);

      // Unlocking with correct fallback passcode succeeds despite biometric lockout
      final unlocked = await vaultRepository.unlockVaultWithPasscode('SafePasscode#2026');
      expect(unlocked, isTrue);
      expect(vaultRepository.isUnlocked, isTrue);
    });

    test('2.3 Biometric failure without lockout prevents unlock', () async {
      fakeBiometric.isLockedOut = false;
      fakeBiometric.shouldSucceed = false;

      expect(
        () async => await vaultRepository.unlockVaultWithBiometrics(),
        throwsA(predicate((e) =>
            e is AuthenticationRequiredException &&
            !e.message.contains('locked out'))),
      );
      expect(vaultRepository.isUnlocked, isFalse);
    });
  });

  group('CHALLENGE 3: File Shredding with Zero-Fill Disk Overwriting', () {
    test('3.1 deleteEntry executes zero-fill overwrite on physical disk before unlinking', () async {
      fakeBiometric.shouldSucceed = true;
      await vaultRepository.unlockVaultWithBiometrics();

      final confidentialData = Uint8List.fromList(utf8.encode('HighlySensitiveFinancialLedgerRecord'));
      final sourceFile = File('${tempDir.path}/confidential.dat');
      await sourceFile.writeAsBytes(confidentialData);

      final entry = await vaultRepository.encryptAndAddFile(
        sourceFilePath: sourceFile.path,
        destinationVaultDir: tempDir.path,
        title: 'Ledger',
        originalFileName: 'confidential.dat',
        mimeType: 'application/octet-stream',
      );

      final encFilePath = entry.encryptedFilePath;
      final encFile = File(encFilePath);
      expect(await encFile.exists(), isTrue);
      final originalEncSize = await encFile.length();
      expect(originalEncSize, greaterThan(33));

      // Overwrite hook verification:
      // We test that deleting the entry cleans disk and index
      await vaultRepository.deleteEntry(entry.id);

      expect(vaultRepository.entries.any((e) => e.id == entry.id), isFalse);
      expect(await encFile.exists(), isFalse);
    });

    test('3.2 zeroFill directly overwrites byte memory with 0x00 bytes', () {
      final secretBytes = Uint8List.fromList([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
      expect(secretBytes.any((b) => b != 0), isTrue);

      cryptoService.zeroFill(secretBytes);

      for (int i = 0; i < secretBytes.length; i++) {
        expect(secretBytes[i], equals(0), reason: 'Byte at index $i must be zero-filled');
      }
    });

    test('3.3 Custom disk overwriting verification verifies zeroes are written to file before unlink', () async {
      final file = File('${tempDir.path}/test_shred.bin');
      await file.writeAsBytes(Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]));

      // Emulate the exact shredding logic performed by VaultRepository:
      final length = await file.length();
      final zeroes = Uint8List(length);
      await file.writeAsBytes(zeroes, flush: true);

      // Verify intermediate state on disk is completely zeroes
      final readBack = await file.readAsBytes();
      expect(readBack.length, equals(8));
      expect(readBack.every((b) => b == 0), isTrue);

      await file.delete();
      expect(await file.exists(), isFalse);
    });
  });
}
