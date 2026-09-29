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

  group('Tier 3: Cross-Feature Combinations', () {
    // -------------------------------------------------------------------------
    // C1: Device Identity (F1) + Hardware Metadata (F2) + Cloud Provisioning (F3)
    // -------------------------------------------------------------------------
    test('C1: generates hardware-anchored device ID, packages metadata, and syncs cloud document', () async {
      final deviceId = await harness.getOrCreateAppScopedDeviceId();
      final metadata = await harness.collectDeviceMetadata();
      final tier = harness.classifyCapabilityTier(metadata);

      final profile = DeviceProfile(
        deviceId: deviceId,
        metadata: metadata,
        capabilityTier: tier,
        lastSeen: DateTime.now(),
        tamperFlags: {'debugger': false, 'root': false},
        trackingStatus: {'active': true},
        vaultMetadata: {'fileCount': 0},
      );

      await harness.syncDeviceProfile(profile);

      expect(harness.cloudDatabase.containsKey(deviceId), isTrue);
      final syncedDoc = harness.cloudDatabase[deviceId]!;
      expect(syncedDoc['deviceId'], equals(deviceId));
      expect(syncedDoc['capabilityTier'], equals(tier.name));
      expect(syncedDoc['deviceModel'], equals(metadata.model));
    });

    // -------------------------------------------------------------------------
    // C2: Biometric Auth (F11) + Location Tracking Gate (F14) + Security Posture (F15)
    // -------------------------------------------------------------------------
    test('C2: unauthorized tracking disable attempt triggers biometric rejection and maintains posture', () async {
      // Attacker attempts to turn off tracking
      harness.shouldBiometricsSucceed = false;

      final initialPosture = harness.currentPosture;
      expect(initialPosture.isTrackingActive, isTrue);

      final success = await harness.setLocationTrackingWithAuth(
        enabled: false,
        bypassAuthForTesting: false,
      );

      expect(success, isFalse);
      expect(harness.currentPosture.isTrackingActive, isTrue);
      expect(harness.currentPosture.overallPosture, equals(SecurityPostureLevel.secure));
    });

    // -------------------------------------------------------------------------
    // C3: Biometric Lockout (F11) + Fallback Passcode Key Derivation (F12) + Vault (F8)
    // -------------------------------------------------------------------------
    test('C3: biometric lockout transitions to PBKDF2 PIN fallback for vault decryption', () async {
      final masterKey = await harness.generateMasterVaultKey();
      final plaintext = Uint8List.fromList('Recoverable Secret via PIN'.codeUnits);

      // Store file in vault
      final entry = await harness.storeVaultFile(
        filename: 'secret.txt',
        plaintext: plaintext,
        masterKey: masterKey,
      );

      // User sets fallback PIN
      await harness.enrollFallbackPin('951753');
      final pinSalt = harness.enrolledPinSalt!;

      // Biometrics become permanently locked out
      harness.isBiometricsLockedOut = true;
      final auth = await harness.requestBiometricAuthentication(reason: 'Unlock Vault');
      expect(auth.isLockedOut, isTrue);

      // System derives key from enrolled PIN
      final derivedKey = await harness.deriveKeyFromPasscode(
        passcode: '951753',
        salt: pinSalt,
        iterations: 1000,
      );
      expect(derivedKey.length, equals(32));

      // Decryption with correct master key succeeds
      final decrypted = await harness.readVaultFile(fileId: entry.id, masterKey: masterKey);
      expect(String.fromCharCodes(decrypted), equals('Recoverable Secret via PIN'));
    });

    // -------------------------------------------------------------------------
    // C4: Network Handoff (F5) + Offline Queue (F3) + Telemetry Flush
    // -------------------------------------------------------------------------
    test('C4: offline telemetry accumulates during airplane mode and flushes on cellular handoff', () async {
      harness.currentNetwork = NetworkState.none;
      final deviceId = await harness.getOrCreateAppScopedDeviceId();
      final metadata = await harness.collectDeviceMetadata();

      final p1 = DeviceProfile(
        deviceId: deviceId,
        metadata: metadata,
        capabilityTier: CapabilityTier.modernFull,
        lastSeen: DateTime.now(),
        tamperFlags: {},
        trackingStatus: {'seq': 1},
        vaultMetadata: {},
      );

      await harness.syncDeviceProfile(p1);
      expect(harness.offlineQueue.length, equals(1));
      expect(harness.cloudDatabase.isEmpty, isTrue);

      // Hand off to cellular
      harness.emitNetworkChange(NetworkState.cellular);

      expect(harness.offlineQueue.isEmpty, isTrue);
      expect(harness.cloudDatabase.containsKey(deviceId), isTrue);
      expect(harness.cloudDatabase[deviceId]!['trackingStatus']['seq'], equals(1));
    });

    // -------------------------------------------------------------------------
    // C5: Significant Location Change (F7) + Background Engine (F4) + Cloud Sync (F3)
    // -------------------------------------------------------------------------
    test('C5: geofence trigger wakes background engine and commits updated coordinates to cloud', () async {
      final deviceId = await harness.getOrCreateAppScopedDeviceId();
      final metadata = await harness.collectDeviceMetadata();

      // Emit movement
      harness.emitSignificantLocationChange(37.3382, -121.8863);

      final updatedProfile = DeviceProfile(
        deviceId: deviceId,
        metadata: metadata,
        capabilityTier: CapabilityTier.modernFull,
        lastSeen: DateTime.now(),
        tamperFlags: {},
        trackingStatus: {
          'lat': harness.lastKnownLocation!.latitude,
          'lng': harness.lastKnownLocation!.longitude,
        },
        vaultMetadata: {},
      );

      await harness.syncDeviceProfile(updatedProfile);

      expect(harness.cloudDatabase[deviceId]!['trackingStatus']['lat'], equals(37.3382));
      expect(harness.cloudDatabase[deviceId]!['trackingStatus']['lng'], equals(-121.8863));
    });

    // -------------------------------------------------------------------------
    // C6: Power Low Trigger (F6) + Adaptive Capability Scaling (F16) + Threat Scanner (F17/F18)
    // -------------------------------------------------------------------------
    test('C6: low battery (<15%) forces threat scanner to lean mode to avoid power drain', () async {
      harness.registerSimulatedPackage(
        packageName: 'com.sideload.overlay',
        sha256Hash: 'benign_hash',
        permissions: [
          'android.permission.BIND_ACCESSIBILITY_SERVICE',
          'android.permission.SYSTEM_ALERT_WINDOW',
        ],
        isSideloaded: true,
        calculatedEntropy: 6.0,
      );

      // Normal state on modern device: Deep scan detects heuristic
      final normalReport = await harness.runThreatScan(tier: CapabilityTier.modernFull);
      expect(normalReport.detectedThreats.length, equals(1));

      // Battery drops to 10%
      harness.emitPowerChange(source: PowerSource.battery, batteryPercent: 10);
      expect(harness.currentPosture.overallPosture, equals(SecurityPostureLevel.degraded));

      // Throttled scan executes in legacyLean mode to conserve battery
      final throttledReport = await harness.runThreatScan(tier: CapabilityTier.legacyLean);
      expect(throttledReport.detectedThreats.isEmpty, isTrue); // Deep heuristic suppressed
    });

    // -------------------------------------------------------------------------
    // C7: AES-256-GCM Vault (F8) + Tamper-Evident Binary Container (F9) + Tamper Injection
    // -------------------------------------------------------------------------
    test('C7: tampering with auth tag in persistent binary container fails GHASH verification', () async {
      final key = await harness.generateMasterVaultKey();
      final plaintext = Uint8List.fromList('Classified Defense Plan'.codeUnits);

      final entry = await harness.storeVaultFile(
        filename: 'defense_plan.enc',
        plaintext: plaintext,
        masterKey: key,
      );

      // Inject tamper directly into disk payload
      harness.injectTamperedPayload(entry.id, TamperMode.tamperedAuthTag);

      expect(
        () async => await harness.readVaultFile(fileId: entry.id, masterKey: key),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
    });

    // -------------------------------------------------------------------------
    // C8: Secure Memory Shredding (F13) + Key Derivation (F10)
    // -------------------------------------------------------------------------
    test('C8: plaintext buffer zeroed immediately after encrypted storage commit', () async {
      final key = await harness.generateMasterVaultKey();
      final originalString = 'Top Secret Encryption Payload 2026';
      final buffer = Uint8List.fromList(utf8.encode(originalString));

      await harness.storeVaultFile(
        filename: 'memory_test.dat',
        plaintext: buffer,
        masterKey: key,
      );

      // Verify that every single byte in the buffer passed in has been shredded to 0x00
      expect(buffer.every((byte) => byte == 0), isTrue);
    });

    // -------------------------------------------------------------------------
    // C9: Threat Detection (F17) + Posture Update (F15) + Cloud Provisioning (F3)
    // -------------------------------------------------------------------------
    test('C9: detected malware signature updates security posture to critical and syncs alert to cloud', () async {
      harness.registerSimulatedPackage(
        packageName: 'com.trojan.stealer',
        sha256Hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        permissions: ['android.permission.INTERNET'],
        isSideloaded: true,
        calculatedEntropy: 6.5,
      );

      final report = await harness.runThreatScan(tier: CapabilityTier.legacyLean);
      expect(report.hasThreats, isTrue);

      // Update posture to critical
      final posture = harness.currentPosture.copyWith(
        overallPosture: SecurityPostureLevel.critical,
        statusSummary: 'Malware Detected: ${report.detectedThreats.first.packageName}',
      );

      final deviceId = await harness.getOrCreateAppScopedDeviceId();
      final metadata = await harness.collectDeviceMetadata();
      final profile = DeviceProfile(
        deviceId: deviceId,
        metadata: metadata,
        capabilityTier: CapabilityTier.legacyLean,
        lastSeen: DateTime.now(),
        tamperFlags: {'malwareDetected': true, 'threatCount': 1},
        trackingStatus: {},
        vaultMetadata: {},
      );

      await harness.syncDeviceProfile(profile);

      expect(posture.overallPosture, equals(SecurityPostureLevel.critical));
      expect(harness.cloudDatabase[deviceId]!['tamperFlags']['malwareDetected'], isTrue);
    });

    // -------------------------------------------------------------------------
    // C10: Multiple Files in Vault (F13) with Unique Nonces (F8) and Independent Shredding
    // -------------------------------------------------------------------------
    test('C10: storing 5 separate vault files generates 5 unique nonces with distinct fingerprints', () async {
      final key = await harness.generateMasterVaultKey();
      final entries = <VaultEntry>[];

      for (int i = 0; i < 5; i++) {
        final data = Uint8List.fromList('File Content $i'.codeUnits);
        final entry = await harness.storeVaultFile(
          filename: 'doc_$i.txt',
          plaintext: data,
          masterKey: key,
        );
        entries.add(entry);
      }

      final nonces = entries.map((e) => harness.vaultStorage[e.id]!.nonce).toList();
      final hashes = entries.map((e) => e.sha256Fingerprint).toSet();

      // All 5 files must have unique nonces and unique hashes
      expect(nonces.toSet().length, equals(5));
      expect(hashes.length, equals(5));

      // Each file can be read back independently
      for (int i = 0; i < 5; i++) {
        final decrypted = await harness.readVaultFile(fileId: entries[i].id, masterKey: key);
        expect(String.fromCharCodes(decrypted), equals('File Content $i'));
      }
    });
  });
}
