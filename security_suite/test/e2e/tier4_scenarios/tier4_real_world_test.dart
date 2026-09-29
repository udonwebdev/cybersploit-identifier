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

  group('Tier 4: Realistic Real-World Application Scenarios', () {
    // =========================================================================
    // SCENARIO 1: Anti-Theft Device Tracking Handoff & Unauthorized Tamper Attempt
    // =========================================================================
    test('Scenario 1: Anti-theft lifecycle across network handoff, offline movement, and biometric defense', () async {
      // Step 1: Device boots up and securely registers identity
      final deviceId = await harness.getOrCreateAppScopedDeviceId();
      final meta = await harness.collectDeviceMetadata();
      final tier = harness.classifyCapabilityTier(meta);

      expect(deviceId.length, equals(64));
      expect(tier, equals(CapabilityTier.modernFull));

      // Step 2: Sync initial profile over Wi-Fi
      harness.currentNetwork = NetworkState.wifi;
      final initialProfile = DeviceProfile(
        deviceId: deviceId,
        metadata: meta,
        capabilityTier: tier,
        lastSeen: DateTime.now(),
        tamperFlags: {'root': false},
        trackingStatus: {'trackingEnabled': true, 'lat': 37.7749, 'lng': -122.4194},
        vaultMetadata: {},
      );
      await harness.syncDeviceProfile(initialProfile);
      expect(harness.cloudDatabase.containsKey(deviceId), isTrue);

      // Step 3: Device enters subway / airplane mode (Offline handoff)
      harness.emitNetworkChange(NetworkState.none);
      expect(harness.currentNetwork, equals(NetworkState.none));

      // Step 4: Motion detected while offline
      harness.emitSignificantLocationChange(37.7833, -122.4167);
      final offlineProfile = DeviceProfile(
        deviceId: deviceId,
        metadata: meta,
        capabilityTier: tier,
        lastSeen: DateTime.now(),
        tamperFlags: {'root': false},
        trackingStatus: {
          'trackingEnabled': true,
          'lat': harness.lastKnownLocation!.latitude,
          'lng': harness.lastKnownLocation!.longitude,
        },
        vaultMetadata: {},
      );
      await harness.syncDeviceProfile(offlineProfile);
      // Verify update is queued offline
      expect(harness.offlineQueue.length, equals(1));

      // Step 5: Thief attempts to turn off background location tracking in the UI
      harness.shouldBiometricsSucceed = false; // Thief does not have owner's fingerprint
      final toggleSuccess = await harness.setLocationTrackingWithAuth(
        enabled: false,
        bypassAuthForTesting: false,
      );

      // Anti-theft gate strictly denies the modification
      expect(toggleSuccess, isFalse);
      expect(harness.isBackgroundLocationEnabled, isTrue); // Maintained active
      expect(harness.currentPosture.overallPosture, equals(SecurityPostureLevel.secure));

      // Step 6: Device emerges from subway and connects to Cellular tower
      harness.emitNetworkChange(NetworkState.cellular);

      // Offline queue automatically flushes to Cloud Firestore
      expect(harness.offlineQueue.isEmpty, isTrue);
      final cloudData = harness.cloudDatabase[deviceId]!;
      expect(cloudData['trackingStatus']['lat'], equals(37.7833));
      expect(cloudData['trackingStatus']['lng'], equals(-122.4167));
    });

    // =========================================================================
    // SCENARIO 2: Offline Encrypted Vault Lifecycle, Key Recovery & Tamper Resilience
    // =========================================================================
    test('Scenario 2: Complete encrypted vault lifecycle with biometric lockout, PIN fallback, and disk tamper detection', () async {
      // Step 1: User generates master vault key backed by hardware KeyStore
      final masterKey = await harness.generateMasterVaultKey();
      expect(masterKey.length, equals(32));

      // Step 2: User enrolls fallback 6-digit PIN for biometric failure resilience
      await harness.enrollFallbackPin('246810');
      final pinSalt = harness.enrolledPinSalt!;

      // Step 3: User encrypts sensitive contract document
      final rawDocument = Uint8List.fromList(utf8.encode('CONFIDENTIAL ACQUISITION AGREEMENT 2026'));
      final entry = await harness.storeVaultFile(
        filename: 'acquisition_agreement.pdf',
        plaintext: rawDocument,
        masterKey: masterKey,
      );

      // Step 4: Verify memory buffer is zero-filled (shredded)
      expect(rawDocument.every((b) => b == 0), isTrue);

      // Step 5: Device experiences physical shock / sensor failure causing Biometric lockout
      harness.isBiometricsLockedOut = true;
      final bioResult = await harness.requestBiometricAuthentication(reason: 'Unlock Vault');
      expect(bioResult.isLockedOut, isTrue);

      // Step 6: User enters recovery PIN -> system derives key with PBKDF2
      final derivedKey = await harness.deriveKeyFromPasscode(
        passcode: '246810',
        salt: pinSalt,
        iterations: 1000,
      );
      expect(derivedKey.length, equals(32));

      // Step 7: Decrypt and read document using valid master key
      final decryptedData = await harness.readVaultFile(fileId: entry.id, masterKey: masterKey);
      expect(utf8.decode(decryptedData), equals('CONFIDENTIAL ACQUISITION AGREEMENT 2026'));

      // Step 8: Malicious process attempts to tamper with the encrypted payload on disk
      harness.injectTamperedPayload(entry.id, TamperMode.tamperedCiphertext);

      // Step 9: Vault attempts decryption -> GHASH authentication fails cleanly without leaking plaintext
      expect(
        () async => await harness.readVaultFile(fileId: entry.id, masterKey: masterKey),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
    });

    // =========================================================================
    // SCENARIO 3: Adaptive Threat Detection Under Hostile Environment & Resource Constraints
    // =========================================================================
    test('Scenario 3: Adaptive security scaling across Legacy Android 8 and Modern Android 14 environments', () async {
      // Step 1: Configure Legacy Android 8.1 device (2GB RAM)
      harness.deviceBrand = 'Motorola';
      harness.deviceModel = 'Moto G6';
      harness.apiLevel = 27;
      harness.totalRamMb = 2048;
      harness.osVersion = 'Android 8.1';

      final legacyMeta = await harness.collectDeviceMetadata();
      final legacyTier = harness.classifyCapabilityTier(legacyMeta);
      expect(legacyTier, equals(CapabilityTier.legacyLean));

      // Register a benign app and a Trojan dropper
      harness.registerSimulatedPackage(
        packageName: 'com.clean.notes',
        sha256Hash: 'clean_notes_sha256',
        permissions: [],
        isSideloaded: false,
        calculatedEntropy: 4.5,
      );
      harness.registerSimulatedPackage(
        packageName: 'com.stealth.dropper',
        sha256Hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        permissions: ['android.permission.INTERNET'],
        isSideloaded: true,
        calculatedEntropy: 6.8,
      );

      // Step 2: Run scan on Legacy tier -> signature scan catches malware under 35MB cap
      final legacyReport = await harness.runThreatScan(tier: legacyTier);
      expect(legacyReport.hasThreats, isTrue);
      expect(legacyReport.detectedThreats.first.packageName, equals('com.stealth.dropper'));
      expect(legacyReport.detectedThreats.first.detectionType, equals('signature'));

      // Step 3: Promote to Modern Android 14 flagship (Pixel 8, 8GB RAM)
      harness.deviceBrand = 'Google';
      harness.deviceModel = 'Pixel 8';
      harness.apiLevel = 34;
      harness.totalRamMb = 8192;
      harness.osVersion = 'Android 14';

      final modernMeta = await harness.collectDeviceMetadata();
      final modernTier = harness.classifyCapabilityTier(modernMeta);
      expect(modernTier, equals(CapabilityTier.modernFull));

      // Add a sophisticated zero-day banking overlay Trojan (no known signature, but dangerous permissions)
      harness.registerSimulatedPackage(
        packageName: 'com.fake.bank.trojan',
        sha256Hash: 'zero_day_unknown_hash',
        permissions: [
          'android.permission.BIND_ACCESSIBILITY_SERVICE',
          'android.permission.SYSTEM_ALERT_WINDOW',
        ],
        isSideloaded: true,
        calculatedEntropy: 7.2,
      );

      // Step 4: Run scan on Modern tier -> deep heuristic catches banking overlay anomaly
      final modernReport = await harness.runThreatScan(tier: modernTier);
      expect(modernReport.detectedThreats.length, equals(2)); // Dropper (sig) + Bank Overlay (heuristic)
      expect(
        modernReport.detectedThreats.any((t) => t.packageName == 'com.fake.bank.trojan'),
        isTrue,
      );
      expect(
        modernReport.detectedThreats.firstWhere((t) => t.packageName == 'com.fake.bank.trojan').detectionType,
        equals('heuristic_accessibility'),
      );
    });
  });
}
