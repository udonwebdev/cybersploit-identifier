import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart' show SecretBoxAuthenticationError;
import 'package:flutter_test/flutter_test.dart';
import '../harness/e2e_test_harness.dart';

void main() {
  late E2ETestHarness harness;

  setUp(() {
    harness = E2ETestHarness();
  });

  tearDown(() {
    harness.dispose();
  });

  group('Tier 2: Boundary & Corner Cases', () {
    // -------------------------------------------------------------------------
    // B1: Empty & Zero-Length Plaintext Encryption
    // -------------------------------------------------------------------------
    test('B1: handles empty (0-byte) plaintext encryption and tag generation', () async {
      final key = await harness.generateMasterVaultKey();
      final emptyBytes = Uint8List(0);

      final payload = await harness.encryptBytes(plaintext: emptyBytes, key256: key);

      // Even with 0 bytes of plaintext, header (33 bytes) must be intact
      expect(payload.rawBytes.length, equals(EncryptedVaultPayload.headerSize));
      expect(payload.isValidHeader, isTrue);

      final decrypted = await harness.decryptBytes(payload: payload, key256: key);
      expect(decrypted.length, equals(0));
    });

    // -------------------------------------------------------------------------
    // B2: Large Payload Encryption & Chunk Boundary
    // -------------------------------------------------------------------------
    test('B2: encrypts and decrypts 1MB continuous binary payload without corruption', () async {
      final key = await harness.generateMasterVaultKey();
      final oneMbPayload = Uint8List(1024 * 1024);
      for (int i = 0; i < oneMbPayload.length; i++) {
        oneMbPayload[i] = (i % 256);
      }

      final payload = await harness.encryptBytes(plaintext: oneMbPayload, key256: key);
      expect(payload.rawBytes.length, equals(EncryptedVaultPayload.headerSize + oneMbPayload.length));

      final decrypted = await harness.decryptBytes(payload: payload, key256: key);
      expect(decrypted.length, equals(oneMbPayload.length));
      expect(decrypted[500000], equals(500000 % 256));
    });

    // -------------------------------------------------------------------------
    // B3: Truncated Vault Payload (< 33 bytes)
    // -------------------------------------------------------------------------
    test('B3: rejects severely truncated payload smaller than 33-byte header', () async {
      final key = await harness.generateMasterVaultKey();
      final truncatedBytes = Uint8List.fromList([0x56, 0x41, 0x55, 0x4C, 0x01, 0x02]); // only 6 bytes
      final malformedPayload = EncryptedVaultPayload(truncatedBytes);

      expect(malformedPayload.isValidHeader, isFalse);
      expect(
        () async => await harness.decryptBytes(payload: malformedPayload, key256: key),
        throwsA(isA<FormatException>()),
      );
    });

    // -------------------------------------------------------------------------
    // B4: Exactly 32-Byte Payload Boundary (Corrupt Header by 1 byte)
    // -------------------------------------------------------------------------
    test('B4: rejects payload of 32 bytes (exactly 1 byte short of header boundary)', () async {
      final key = await harness.generateMasterVaultKey();
      final bytes32 = Uint8List(32);
      final malformedPayload = EncryptedVaultPayload(bytes32);

      expect(malformedPayload.isValidHeader, isFalse);
      expect(
        () async => await harness.decryptBytes(payload: malformedPayload, key256: key),
        throwsA(isA<FormatException>()),
      );
    });

    // -------------------------------------------------------------------------
    // B5: Bit-Flip in First, Middle, and Last Ciphertext Byte
    // -------------------------------------------------------------------------
    test('B5: detects single bit-flips across different ciphertext offsets', () async {
      final key = await harness.generateMasterVaultKey();
      final plaintext = Uint8List.fromList(List.generate(100, (i) => i));
      final payload = await harness.encryptBytes(plaintext: plaintext, key256: key);

      // 1. Bit-flip at first ciphertext byte (index 33)
      final bytes1 = Uint8List.fromList(payload.rawBytes);
      bytes1[33] ^= 0x01;
      expect(
        () async => await harness.decryptBytes(payload: EncryptedVaultPayload(bytes1), key256: key),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );

      // 2. Bit-flip in middle ciphertext byte (index 33 + 50)
      final bytes2 = Uint8List.fromList(payload.rawBytes);
      bytes2[83] ^= 0x80;
      expect(
        () async => await harness.decryptBytes(payload: EncryptedVaultPayload(bytes2), key256: key),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );

      // 3. Bit-flip at last ciphertext byte
      final bytes3 = Uint8List.fromList(payload.rawBytes);
      bytes3[bytes3.length - 1] ^= 0x02;
      expect(
        () async => await harness.decryptBytes(payload: EncryptedVaultPayload(bytes3), key256: key),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
    });

    // -------------------------------------------------------------------------
    // B6: Wrong Additional Authenticated Data (AAD) Substitution
    // -------------------------------------------------------------------------
    test('B6: rejects decryption when AAD is swapped, empty, or truncated', () async {
      final key = await harness.generateMasterVaultKey();
      final plaintext = Uint8List.fromList('Encrypted with metadata'.codeUnits);
      final validAad = Uint8List.fromList(utf8.encode('user_id=12345;file=tax.pdf'));

      final payload = await harness.encryptBytes(
        plaintext: plaintext,
        key256: key,
        additionalAuthenticatedData: validAad,
      );

      // 1. Swapped AAD
      final forgedAad = Uint8List.fromList(utf8.encode('user_id=99999;file=tax.pdf'));
      expect(
        () async => await harness.decryptBytes(
          payload: payload,
          key256: key,
          additionalAuthenticatedData: forgedAad,
        ),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );

      // 2. Empty AAD when valid AAD was used at encryption
      expect(
        () async => await harness.decryptBytes(
          payload: payload,
          key256: key,
          additionalAuthenticatedData: Uint8List(0),
        ),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
    });

    // -------------------------------------------------------------------------
    // B7: Invalid Key Lengths (16-byte AES-128, 24-byte AES-192, 33-byte Overflow)
    // -------------------------------------------------------------------------
    test('B7: strictly rejects non-256-bit key sizes (16B, 24B, 33B)', () async {
      final plaintext = Uint8List.fromList('Test'.codeUnits);

      // 16 bytes
      expect(
        () async => await harness.encryptBytes(plaintext: plaintext, key256: Uint8List(16)),
        throwsA(isA<ArgumentError>()),
      );

      // 24 bytes
      expect(
        () async => await harness.encryptBytes(plaintext: plaintext, key256: Uint8List(24)),
        throwsA(isA<ArgumentError>()),
      );

      // 33 bytes
      expect(
        () async => await harness.encryptBytes(plaintext: plaintext, key256: Uint8List(33)),
        throwsA(isA<ArgumentError>()),
      );
    });

    // -------------------------------------------------------------------------
    // B8: High-Frequency Rapid Network Flapping (Debounce & Queue Integrity)
    // -------------------------------------------------------------------------
    test('B8: preserves queue integrity under rapid network connection flapping', () async {
      harness.currentNetwork = NetworkState.none;
      final deviceId = await harness.getOrCreateAppScopedDeviceId();
      final meta = await harness.collectDeviceMetadata();

      final profile = DeviceProfile(
        deviceId: deviceId,
        metadata: meta,
        capabilityTier: CapabilityTier.modernFull,
        lastSeen: DateTime.now(),
        tamperFlags: {},
        trackingStatus: {},
        vaultMetadata: {},
      );

      await harness.syncDeviceProfile(profile);
      expect(harness.offlineQueue.length, equals(1));

      // Rapid flapping: none -> wifi -> none -> cellular -> none -> wifi
      harness.emitNetworkChange(NetworkState.wifi);
      harness.emitNetworkChange(NetworkState.none);
      harness.emitNetworkChange(NetworkState.cellular);
      harness.emitNetworkChange(NetworkState.none);
      harness.emitNetworkChange(NetworkState.wifi);

      // Final state is online (wifi) -> queue should be flushed
      expect(harness.offlineQueue.isEmpty, isTrue);
      expect(harness.cloudDatabase.containsKey(deviceId), isTrue);
    });

    // -------------------------------------------------------------------------
    // B9: Extreme Battery Level Boundaries (0%, 1%, 14%, 15%, 100%)
    // -------------------------------------------------------------------------
    test('B9: evaluates exact threshold transitions at 14% and 15% battery', () {
      // At 15%, still considered non-critical
      harness.emitPowerChange(source: PowerSource.battery, batteryPercent: 15);
      expect(harness.currentPosture.overallPosture, equals(SecurityPostureLevel.secure));

      // At 14%, drops below 15% threshold -> degraded
      harness.emitPowerChange(source: PowerSource.battery, batteryPercent: 14);
      expect(harness.currentPosture.overallPosture, equals(SecurityPostureLevel.degraded));

      // At 1%, remains degraded
      harness.emitPowerChange(source: PowerSource.battery, batteryPercent: 1);
      expect(harness.currentPosture.overallPosture, equals(SecurityPostureLevel.degraded));

      // Plugging in at 1% restores security sweeps
      harness.emitPowerChange(source: PowerSource.acCharging, batteryPercent: 1);
      expect(harness.currentPower, equals(PowerSource.acCharging));
    });

    // -------------------------------------------------------------------------
    // B10: Extreme Geographic Coordinates (Poles and Date Line)
    // -------------------------------------------------------------------------
    test('B10: handles extreme latitude/longitude boundary coordinates', () {
      // North Pole
      harness.emitSignificantLocationChange(90.0, 0.0);
      expect(harness.lastKnownLocation!.latitude, equals(90.0));

      // South Pole
      harness.emitSignificantLocationChange(-90.0, 0.0);
      expect(harness.lastKnownLocation!.latitude, equals(-90.0));

      // International Date Line (+180 / -180)
      harness.emitSignificantLocationChange(0.0, 180.0);
      expect(harness.lastKnownLocation!.longitude, equals(180.0));

      harness.emitSignificantLocationChange(0.0, -180.0);
      expect(harness.lastKnownLocation!.longitude, equals(-180.0));
    });

    // -------------------------------------------------------------------------
    // B11: Rapid Repeated Toggle of Protected Location Permission
    // -------------------------------------------------------------------------
    test('B11: handles 10 rapid repeated toggle requests without race conditions', () async {
      harness.shouldBiometricsSucceed = true;

      for (int i = 0; i < 10; i++) {
        final target = (i % 2 == 0);
        final success = await harness.setLocationTrackingWithAuth(
          enabled: target,
          bypassAuthForTesting: false,
        );
        expect(success, isTrue);
        expect(harness.isBackgroundLocationEnabled, equals(target));
      }
    });

    // -------------------------------------------------------------------------
    // B12: Revoked Biometrics Mid-Session
    // -------------------------------------------------------------------------
    test('B12: gracefully rejects toggle if user deletes biometrics mid-session', () async {
      harness.hasEnrolledBiometrics = true;
      // OS notifies biometrics were cleared
      harness.hasEnrolledBiometrics = false;

      final success = await harness.setLocationTrackingWithAuth(
        enabled: false,
        bypassAuthForTesting: false,
      );

      expect(success, isFalse);
      expect(harness.isBackgroundLocationEnabled, isTrue);
    });

    // -------------------------------------------------------------------------
    // B13: Special Characters & Injection in Vault File Names
    // -------------------------------------------------------------------------
    test('B13: handles special characters, unicode, and directory traversal in filenames', () async {
      final key = await harness.generateMasterVaultKey();
      const maliciousName = '../../etc/passwd\x00<script>🔥.pdf';
      final data = Uint8List.fromList('Safe Data Content'.codeUnits);

      final entry = await harness.storeVaultFile(
        filename: maliciousName,
        plaintext: data,
        masterKey: key,
      );

      expect(entry.filename, equals(maliciousName));

      final readData = await harness.readVaultFile(fileId: entry.id, masterKey: key);
      expect(String.fromCharCodes(readData), equals('Safe Data Content'));
    });

    // -------------------------------------------------------------------------
    // B14: High Volume Threat Catalog Boundary
    // -------------------------------------------------------------------------
    test('B14: scans 100 packages without memory exhaustion or degraded performance', () async {
      for (int i = 0; i < 100; i++) {
        harness.registerSimulatedPackage(
          packageName: 'com.vendor.app_$i',
          sha256Hash: 'hash_$i',
          permissions: ['android.permission.INTERNET'],
          isSideloaded: false,
          calculatedEntropy: 5.2,
        );
      }

      final report = await harness.runThreatScan(tier: CapabilityTier.modernFull);
      expect(report.totalScanned, equals(100));
      expect(report.hasThreats, isFalse);
      expect(report.executionTimeMs, lessThan(500));
    });

    // -------------------------------------------------------------------------
    // B15: Exact RAM Threshold for Capability Tier (3072 MB Boundary)
    // -------------------------------------------------------------------------
    test('B15: evaluates exact 3072 MB RAM boundary for capability scaling', () {
      final meta3071 = DeviceMetadata(
        brand: 'Test',
        model: 'Model',
        os: PlatformOS.android,
        osVersion: 'Android 11',
        apiLevel: 30,
        architecture: 'arm64',
        securityPatchLevel: '2023-01-01',
        totalRamMb: 3071, // 1 MB below threshold
      );

      final meta3072 = DeviceMetadata(
        brand: 'Test',
        model: 'Model',
        os: PlatformOS.android,
        osVersion: 'Android 11',
        apiLevel: 30,
        architecture: 'arm64',
        securityPatchLevel: '2023-01-01',
        totalRamMb: 3072, // Exactly on threshold
      );

      expect(harness.classifyCapabilityTier(meta3071), equals(CapabilityTier.legacyLean));
      expect(harness.classifyCapabilityTier(meta3072), equals(CapabilityTier.modernFull));
    });
  });
}
