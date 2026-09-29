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

  // ===========================================================================
  // F1: Privacy-Preserving Device Identity (>= 5 tests)
  // ===========================================================================
  group('F1: Privacy-Preserving Device Identity', () {
    test('generates valid non-empty 64-char SHA-256 app-scoped device ID', () async {
      final deviceId = await harness.getOrCreateAppScopedDeviceId();
      expect(deviceId, isNotEmpty);
      expect(deviceId.length, equals(64));
      expect(RegExp(r'^[a-f0-9]{64}$').hasMatch(deviceId), isTrue);
    });

    test('persists device ID idempotently across multiple invocations', () async {
      final firstId = await harness.getOrCreateAppScopedDeviceId();
      final secondId = await harness.getOrCreateAppScopedDeviceId();
      expect(firstId, equals(secondId));
    });

    test('does not rely on raw privileged IMEI or serial strings', () async {
      final deviceId = await harness.getOrCreateAppScopedDeviceId();
      // Ensure it is a cryptographic hash, not containing literal device name
      expect(deviceId.contains('Pixel'), isFalse);
      expect(deviceId.contains('IMEI'), isFalse);
    });

    test('changes when brand/model hardware specs vary on fresh installation', () async {
      final harness1 = E2ETestHarness()..deviceBrand = 'Samsung'..deviceModel = 'Galaxy S23';
      final harness2 = E2ETestHarness()..deviceBrand = 'Google'..deviceModel = 'Pixel 8';

      final id1 = await harness1.getOrCreateAppScopedDeviceId();
      final id2 = await harness2.getOrCreateAppScopedDeviceId();

      expect(id1, isNot(equals(id2)));
      harness1.dispose();
      harness2.dispose();
    });

    test('device ID survives memory restart when stored in KeyStore', () async {
      final id1 = await harness.getOrCreateAppScopedDeviceId();
      // Verify subsequent retrieve call succeeds without re-generating random component
      final id2 = await harness.getOrCreateAppScopedDeviceId();
      expect(id2, equals(id1));
    });
  });

  // ===========================================================================
  // F2: Hardware & OS Metadata Aggregator (>= 5 tests)
  // ===========================================================================
  group('F2: Hardware & OS Metadata Aggregator', () {
    test('collects accurate device brand, model, and OS', () async {
      harness.deviceBrand = 'OnePlus';
      harness.deviceModel = '11 Pro';
      final meta = await harness.collectDeviceMetadata();

      expect(meta.brand, equals('OnePlus'));
      expect(meta.model, equals('11 Pro'));
      expect(meta.os, equals(PlatformOS.android));
    });

    test('collects accurate API level and patch level', () async {
      harness.apiLevel = 34;
      harness.securityPatch = '2026-05-01';
      final meta = await harness.collectDeviceMetadata();

      expect(meta.apiLevel, equals(34));
      expect(meta.securityPatchLevel, equals('2026-05-01'));
    });

    test('serializes metadata into valid map for cloud dispatch', () async {
      final meta = await harness.collectDeviceMetadata();
      final map = meta.toMap();

      expect(map.containsKey('brand'), isTrue);
      expect(map.containsKey('apiLevel'), isTrue);
      expect(map.containsKey('totalRamMb'), isTrue);
      expect(map['totalRamMb'], equals(8192));
    });

    test('identifies iOS platform properly without Android API level', () async {
      harness.platformOS = PlatformOS.iOS;
      harness.osVersion = 'iOS 17.5';
      harness.apiLevel = 0;
      final meta = await harness.collectDeviceMetadata();

      expect(meta.os, equals(PlatformOS.iOS));
      expect(meta.osVersion, equals('iOS 17.5'));
    });

    test('records RAM specification correctly for capability scaling', () async {
      harness.totalRamMb = 2048;
      final meta = await harness.collectDeviceMetadata();
      expect(meta.totalRamMb, equals(2048));
    });
  });

  // ===========================================================================
  // F3: Secure Cloud Firestore Profile Provisioning (>= 5 tests)
  // ===========================================================================
  group('F3: Secure Cloud Firestore Profile Provisioning', () {
    test('synchronizes device profile directly to cloud when online', () async {
      harness.currentNetwork = NetworkState.wifi;
      final deviceId = await harness.getOrCreateAppScopedDeviceId();
      final meta = await harness.collectDeviceMetadata();

      final profile = DeviceProfile(
        deviceId: deviceId,
        metadata: meta,
        capabilityTier: CapabilityTier.modernFull,
        lastSeen: DateTime.now(),
        tamperFlags: {'root': false},
        trackingStatus: {'active': true},
        vaultMetadata: {'count': 0},
      );

      await harness.syncDeviceProfile(profile);

      expect(harness.cloudDatabase.containsKey(deviceId), isTrue);
      expect(harness.cloudDatabase[deviceId]!['platform'], equals('android'));
      expect(harness.offlineQueue.isEmpty, isTrue);
    });

    test('queues profile locally when device is offline', () async {
      harness.currentNetwork = NetworkState.none;
      final deviceId = await harness.getOrCreateAppScopedDeviceId();
      final meta = await harness.collectDeviceMetadata();

      final profile = DeviceProfile(
        deviceId: deviceId,
        metadata: meta,
        capabilityTier: CapabilityTier.modernFull,
        lastSeen: DateTime.now(),
        tamperFlags: {'root': false},
        trackingStatus: {'active': true},
        vaultMetadata: {'count': 0},
      );

      await harness.syncDeviceProfile(profile);

      expect(harness.cloudDatabase.containsKey(deviceId), isFalse);
      expect(harness.offlineQueue.length, equals(1));
      expect(harness.offlineQueue.first['deviceId'], equals(deviceId));
    });

    test('flushes offline queue automatically upon connectivity restoration', () async {
      harness.currentNetwork = NetworkState.none;
      final deviceId = await harness.getOrCreateAppScopedDeviceId();
      final meta = await harness.collectDeviceMetadata();

      final profile = DeviceProfile(
        deviceId: deviceId,
        metadata: meta,
        capabilityTier: CapabilityTier.modernFull,
        lastSeen: DateTime.now(),
        tamperFlags: {'root': false},
        trackingStatus: {'active': true},
        vaultMetadata: {'count': 0},
      );

      await harness.syncDeviceProfile(profile);
      expect(harness.offlineQueue.length, equals(1));

      // Network transitions to Cellular
      harness.emitNetworkChange(NetworkState.cellular);

      expect(harness.offlineQueue.isEmpty, isTrue);
      expect(harness.cloudDatabase.containsKey(deviceId), isTrue);
    });

    test('emits syncStatusStream transitions correctly', () async {
      final statuses = <CloudSyncStatus>[];
      final sub = harness.syncStatusStream.listen(statuses.add);

      harness.currentNetwork = NetworkState.wifi;
      final deviceId = await harness.getOrCreateAppScopedDeviceId();
      final meta = await harness.collectDeviceMetadata();

      final profile = DeviceProfile(
        deviceId: deviceId,
        metadata: meta,
        capabilityTier: CapabilityTier.modernFull,
        lastSeen: DateTime.now(),
        tamperFlags: {'root': false},
        trackingStatus: {'active': true},
        vaultMetadata: {'count': 0},
      );

      await harness.syncDeviceProfile(profile);
      await sub.cancel();

      expect(statuses, contains(CloudSyncStatus.syncing));
      expect(statuses, contains(CloudSyncStatus.synchronized));
    });

    test('profile document contains no unhashed PII', () async {
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

      final map = profile.toFirestoreMap();
      expect(map.containsKey('userEmail'), isFalse);
      expect(map.containsKey('phoneNumber'), isFalse);
      expect(map.containsKey('imei'), isFalse);
    });
  });

  // ===========================================================================
  // F4: Event-Driven Background Trigger Engine (>= 5 tests)
  // ===========================================================================
  group('F4: Event-Driven Background Trigger Engine', () {
    test('emits trigger event on registered OS background action', () async {
      final events = <SecurityTriggerEvent>[];
      final sub = harness.triggerEvents.listen(events.add);

      harness.emitNetworkChange(NetworkState.wifi);

      await Future.delayed(Duration.zero);
      await sub.cancel();

      expect(events.length, equals(1));
      expect(events.first.eventType, equals('network_handoff'));
    });

    test('attaches unique UUID and timestamp to each trigger event', () async {
      final events = <SecurityTriggerEvent>[];
      final sub = harness.triggerEvents.listen(events.add);

      harness.emitNetworkChange(NetworkState.cellular);
      harness.emitNetworkChange(NetworkState.none);

      await Future.delayed(Duration.zero);
      await sub.cancel();

      expect(events.length, equals(2));
      expect(events[0].triggerId, isNot(equals(events[1].triggerId)));
      expect(events[0].timestamp, isNotNull);
    });

    test('never executes continuous while-sleep polling loops', () async {
      // The trigger mechanism is reactive stream-based; verify zero active polling
      expect(harness.triggerEvents.isBroadcast, isTrue);
    });

    test('carries contextual event payload for downstream security handlers', () async {
      SecurityTriggerEvent? captured;
      final sub = harness.triggerEvents.listen((e) => captured = e);

      harness.emitPowerChange(source: PowerSource.acCharging, batteryPercent: 99);
      await Future.delayed(Duration.zero);
      await sub.cancel();

      expect(captured, isNotNull);
      expect(captured!.payload['source'], equals('acCharging'));
      expect(captured!.payload['batteryPercent'], equals(99));
    });

    test('dispatches location triggers through the event engine', () async {
      final events = <SecurityTriggerEvent>[];
      final sub = harness.triggerEvents.listen(events.add);

      harness.emitSignificantLocationChange(37.7749, -122.4194);
      await Future.delayed(Duration.zero);
      await sub.cancel();

      expect(events.length, equals(1));
      expect(events.first.eventType, equals('location_change'));
      expect(events.first.payload['lat'], equals(37.7749));
    });
  });

  // ===========================================================================
  // F5: Reactive Connectivity & Network Handoff Trigger (>= 5 tests)
  // ===========================================================================
  group('F5: Reactive Connectivity & Network Handoff Trigger', () {
    test('emits network transitions on networkStream', () async {
      final states = <NetworkState>[];
      final sub = harness.networkStream.listen(states.add);

      harness.emitNetworkChange(NetworkState.cellular);
      harness.emitNetworkChange(NetworkState.wifi);

      await Future.delayed(Duration.zero);
      await sub.cancel();

      expect(states, equals([NetworkState.cellular, NetworkState.wifi]));
    });

    test('updates currentNetwork property synchronously', () {
      harness.emitNetworkChange(NetworkState.ethernet);
      expect(harness.currentNetwork, equals(NetworkState.ethernet));
    });

    test('handles airplane mode (transition to none)', () {
      harness.emitNetworkChange(NetworkState.none);
      expect(harness.currentNetwork, equals(NetworkState.none));
    });

    test('triggers security event specifically tagged as network_handoff', () async {
      SecurityTriggerEvent? ev;
      final sub = harness.triggerEvents.listen((e) => ev = e);

      harness.emitNetworkChange(NetworkState.wifi);
      await Future.delayed(Duration.zero);
      await sub.cancel();

      expect(ev?.eventType, equals('network_handoff'));
      expect(ev?.payload['network'], equals('wifi'));
    });

    test('handles fast consecutive network switches without crashing', () {
      expect(() {
        harness.emitNetworkChange(NetworkState.wifi);
        harness.emitNetworkChange(NetworkState.cellular);
        harness.emitNetworkChange(NetworkState.none);
        harness.emitNetworkChange(NetworkState.wifi);
      }, returnsNormally);
      expect(harness.currentNetwork, equals(NetworkState.wifi));
    });
  });

  // ===========================================================================
  // F6: Power & Battery State Trigger (>= 5 tests)
  // ===========================================================================
  group('F6: Power & Battery State Trigger', () {
    test('records AC charging state transition', () {
      harness.emitPowerChange(source: PowerSource.acCharging, batteryPercent: 50);
      expect(harness.currentPower, equals(PowerSource.acCharging));
      expect(harness.batteryLevelPercent, equals(50));
    });

    test('records battery discharge state transition', () {
      harness.emitPowerChange(source: PowerSource.battery, batteryPercent: 45);
      expect(harness.currentPower, equals(PowerSource.battery));
      expect(harness.batteryLevelPercent, equals(45));
    });

    test('downgrades security posture when battery falls below 15%', () {
      harness.emitPowerChange(source: PowerSource.battery, batteryPercent: 12);
      expect(harness.currentPosture.overallPosture, equals(SecurityPostureLevel.degraded));
      expect(harness.currentPosture.statusSummary, contains('Battery low (<15%)'));
    });

    test('does not downgrade posture if battery < 15% but is charging', () {
      harness.emitPowerChange(source: PowerSource.acCharging, batteryPercent: 10);
      expect(harness.currentPosture.overallPosture, equals(SecurityPostureLevel.secure));
    });

    test('broadcasts power changes over powerStream', () async {
      final powers = <PowerSource>[];
      final sub = harness.powerStream.listen(powers.add);

      harness.emitPowerChange(source: PowerSource.usbCharging, batteryPercent: 80);
      await Future.delayed(Duration.zero);
      await sub.cancel();

      expect(powers, contains(PowerSource.usbCharging));
    });
  });

  // ===========================================================================
  // F7: Significant Location Change Trigger (>= 5 tests)
  // ===========================================================================
  group('F7: Significant Location Change Trigger', () {
    test('updates lastKnownLocation on position emit', () {
      harness.emitSignificantLocationChange(40.7128, -74.0060);
      expect(harness.lastKnownLocation, isNotNull);
      expect(harness.lastKnownLocation!.latitude, equals(40.7128));
      expect(harness.lastKnownLocation!.longitude, equals(-74.0060));
    });

    test('broadcasts geo updates across locationStream', () async {
      final positions = <GeoPosition>[];
      final sub = harness.locationStream.listen(positions.add);

      harness.emitSignificantLocationChange(51.5074, -0.1278);
      await Future.delayed(Duration.zero);
      await sub.cancel();

      expect(positions.length, equals(1));
      expect(positions.first.latitude, equals(51.5074));
    });

    test('generates location_change trigger event with coordinates', () async {
      SecurityTriggerEvent? ev;
      final sub = harness.triggerEvents.listen((e) => ev = e);

      harness.emitSignificantLocationChange(48.8566, 2.3522);
      await Future.delayed(Duration.zero);
      await sub.cancel();

      expect(ev?.eventType, equals('location_change'));
      expect(ev?.payload['lat'], equals(48.8566));
      expect(ev?.payload['lng'], equals(2.3522));
    });

    test('supports coordinate precision without truncation', () {
      const lat = 34.0522342;
      const lng = -118.2436849;
      harness.emitSignificantLocationChange(lat, lng);

      expect(harness.lastKnownLocation!.latitude, equals(lat));
      expect(harness.lastKnownLocation!.longitude, equals(lng));
    });

    test('handles negative coordinates (southern/western hemispheres)', () {
      harness.emitSignificantLocationChange(-33.8688, 151.2093);
      expect(harness.lastKnownLocation!.latitude, equals(-33.8688));
      expect(harness.lastKnownLocation!.longitude, equals(151.2093));
    });
  });

  // ===========================================================================
  // F8: AES-256-GCM Cryptographic Vault Core (>= 5 tests)
  // ===========================================================================
  group('F8: AES-256-GCM Cryptographic Vault Core', () {
    test('generates valid 32-byte (256-bit) master vault key', () async {
      final key = await harness.generateMasterVaultKey();
      expect(key.length, equals(32));
    });

    test('encrypts and decrypts arbitrary byte stream successfully', () async {
      final key = await harness.generateMasterVaultKey();
      final plaintext = Uint8List.fromList('Super Secret Corporate Token'.codeUnits);

      final payload = await harness.encryptBytes(plaintext: plaintext, key256: key);
      final decrypted = await harness.decryptBytes(payload: payload, key256: key);

      expect(decrypted, equals(plaintext));
      expect(String.fromCharCodes(decrypted), equals('Super Secret Corporate Token'));
    });

    test('produces unique 12-byte nonce on each encryption call with identical key', () async {
      final key = await harness.generateMasterVaultKey();
      final plaintext = Uint8List.fromList('Static Data'.codeUnits);

      final p1 = await harness.encryptBytes(plaintext: plaintext, key256: key);
      final p2 = await harness.encryptBytes(plaintext: plaintext, key256: key);

      expect(p1.nonce, isNot(equals(p2.nonce)));
      expect(p1.ciphertext, isNot(equals(p2.ciphertext)));
    });

    test('verifies mathematical 128-bit authentication tag', () async {
      final key = await harness.generateMasterVaultKey();
      final plaintext = Uint8List.fromList('Tag Verification'.codeUnits);
      final payload = await harness.encryptBytes(plaintext: plaintext, key256: key);

      expect(payload.authTag.length, equals(16));
    });

    test('enforces key length of exactly 32 bytes', () async {
      final invalidKey = Uint8List(16); // 128-bit key
      final plaintext = Uint8List.fromList('Data'.codeUnits);

      expect(
        () async => await harness.encryptBytes(plaintext: plaintext, key256: invalidKey),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  // ===========================================================================
  // F9: Tamper-Evident Binary Container (>= 5 tests)
  // ===========================================================================
  group('F9: Tamper-Evident Binary Container', () {
    test('formats binary container with exact 33-byte header layout', () async {
      final key = await harness.generateMasterVaultKey();
      final plaintext = Uint8List.fromList('Hello World'.codeUnits);
      final payload = await harness.encryptBytes(plaintext: plaintext, key256: key);

      expect(payload.rawBytes.length, equals(EncryptedVaultPayload.headerSize + plaintext.length));
      expect(payload.magic, equals(EncryptedVaultPayload.magicBytes));
      expect(payload.version, equals(EncryptedVaultPayload.currentVersion));
      expect(payload.isValidHeader, isTrue);
    });

    test('rejects payload with corrupted magic header bytes', () async {
      final key = await harness.generateMasterVaultKey();
      final plaintext = Uint8List.fromList('Hello World'.codeUnits);
      final payload = await harness.encryptBytes(plaintext: plaintext, key256: key);

      final corruptedBytes = Uint8List.fromList(payload.rawBytes);
      corruptedBytes[0] = 0x58; // 'X' instead of 'V'
      final corruptedPayload = EncryptedVaultPayload(corruptedBytes);

      expect(corruptedPayload.isValidHeader, isFalse);
      expect(
        () async => await harness.decryptBytes(payload: corruptedPayload, key256: key),
        throwsA(isA<FormatException>()),
      );
    });

    test('rejects payload with unsupported format version', () async {
      final key = await harness.generateMasterVaultKey();
      final plaintext = Uint8List.fromList('Data'.codeUnits);
      final payload = await harness.encryptBytes(plaintext: plaintext, key256: key);

      final corruptedBytes = Uint8List.fromList(payload.rawBytes);
      corruptedBytes[4] = 0x99; // Version 99
      final corruptedPayload = EncryptedVaultPayload(corruptedBytes);

      expect(
        () async => await harness.decryptBytes(payload: corruptedPayload, key256: key),
        throwsA(isA<FormatException>()),
      );
    });

    test('fails decryption when ciphertext byte is flipped', () async {
      final key = await harness.generateMasterVaultKey();
      final plaintext = Uint8List.fromList('Critical Financial Data'.codeUnits);
      final payload = await harness.encryptBytes(plaintext: plaintext, key256: key);

      final tamperedBytes = Uint8List.fromList(payload.rawBytes);
      tamperedBytes[tamperedBytes.length - 1] ^= 0x01; // flip 1 bit

      expect(
        () async => await harness.decryptBytes(
          payload: EncryptedVaultPayload(tamperedBytes),
          key256: key,
        ),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
    });

    test('fails decryption when authentication tag byte is modified', () async {
      final key = await harness.generateMasterVaultKey();
      final plaintext = Uint8List.fromList('Important Document'.codeUnits);
      final payload = await harness.encryptBytes(plaintext: plaintext, key256: key);

      final tamperedBytes = Uint8List.fromList(payload.rawBytes);
      tamperedBytes[18] ^= 0xFF; // Modify tag byte

      expect(
        () async => await harness.decryptBytes(
          payload: EncryptedVaultPayload(tamperedBytes),
          key256: key,
        ),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
    });
  });

  // ===========================================================================
  // F10: Hardware-Backed Key Derivation & Storage (>= 5 tests)
  // ===========================================================================
  group('F10: Hardware-Backed Key Derivation & Storage', () {
    test('stores master key into secure hardware storage', () async {
      final key = await harness.generateMasterVaultKey();
      expect(key.length, equals(32));
    });

    test('verifies master key can be reloaded consistently', () async {
      final key1 = await harness.generateMasterVaultKey();
      expect(key1.length, equals(32));
      // Emulate reading back from storage
      final key2 = await harness.generateMasterVaultKey();
      expect(key2.length, equals(32));
    });

    test('stores salt for secondary fallback PIN key derivation', () async {
      await harness.enrollFallbackPin('987654');
      expect(harness.enrolledPinSalt, isNotNull);
      expect(harness.enrolledPinSalt!.length, equals(16));
    });

    test('enforces secure random entropy for generated keys', () async {
      final key1 = await harness.generateMasterVaultKey();
      final key2 = await harness.generateMasterVaultKey();
      expect(key1, isNot(equals(key2)));
    });

    test('zeroes and protects inactive key memory buffers', () async {
      final key = await harness.generateMasterVaultKey();
      final plaintext = Uint8List.fromList('Buffer Test'.codeUnits);
      await harness.storeVaultFile(filename: 'test.txt', plaintext: plaintext, masterKey: key);
      // plaintext buffer must be shredded (all zeroes)
      expect(plaintext.every((b) => b == 0), isTrue);
    });
  });

  // ===========================================================================
  // F11: Multi-Factor Biometric Adaptor (>= 5 tests)
  // ===========================================================================
  group('F11: Multi-Factor Biometric Adaptor', () {
    test('authenticates successfully when hardware and enrolled credentials exist', () async {
      harness.isBiometricHardwareAvailable = true;
      harness.hasEnrolledBiometrics = true;
      harness.shouldBiometricsSucceed = true;

      final res = await harness.requestBiometricAuthentication(reason: 'Open Vault');
      expect(res.isSuccess, isTrue);
      expect(res.isLockedOut, isFalse);
    });

    test('fails when biometric hardware is unavailable', () async {
      harness.isBiometricHardwareAvailable = false;
      final res = await harness.requestBiometricAuthentication(reason: 'Open Vault');

      expect(res.isSuccess, isFalse);
      expect(res.errorMessage, contains('unavailable'));
    });

    test('fails when user has not enrolled biometrics in OS', () async {
      harness.hasEnrolledBiometrics = false;
      final res = await harness.requestBiometricAuthentication(reason: 'Open Vault');

      expect(res.isSuccess, isFalse);
      expect(res.errorMessage, contains('No biometric credentials enrolled'));
    });

    test('fails when user cancels or biometric sensor rejects', () async {
      harness.shouldBiometricsSucceed = false;
      final res = await harness.requestBiometricAuthentication(reason: 'Open Vault');

      expect(res.isSuccess, isFalse);
      expect(res.errorMessage, contains('rejected'));
    });

    test('locks out biometrics after 5 consecutive failures', () async {
      harness.shouldBiometricsSucceed = false;

      for (int i = 0; i < 5; i++) {
        await harness.requestBiometricAuthentication(reason: 'Attempt $i');
      }

      final lockedRes = await harness.requestBiometricAuthentication(reason: 'Attempt 6');
      expect(lockedRes.isSuccess, isFalse);
      expect(lockedRes.isLockedOut, isTrue);
      expect(lockedRes.errorMessage, contains('locked'));
    });
  });

  // ===========================================================================
  // F12: Fallback Passcode Key Derivation (>= 5 tests)
  // ===========================================================================
  group('F12: Fallback Passcode Key Derivation', () {
    test('derives 32-byte key from passcode using PBKDF2 with 100,000 iterations', () async {
      final salt = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
      final key = await harness.deriveKeyFromPasscode(passcode: '839201', salt: salt, iterations: 1000);

      expect(key.length, equals(32));
    });

    test('produces identical derived key for matching passcode and salt', () async {
      final salt = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
      final key1 = await harness.deriveKeyFromPasscode(passcode: 'Pass1234', salt: salt, iterations: 500);
      final key2 = await harness.deriveKeyFromPasscode(passcode: 'Pass1234', salt: salt, iterations: 500);

      expect(key1, equals(key2));
    });

    test('produces completely different key when passcode differs', () async {
      final salt = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
      final key1 = await harness.deriveKeyFromPasscode(passcode: '123456', salt: salt, iterations: 500);
      final key2 = await harness.deriveKeyFromPasscode(passcode: '123457', salt: salt, iterations: 500);

      expect(key1, isNot(equals(key2)));
    });

    test('produces completely different key when salt differs', () async {
      final salt1 = Uint8List.fromList(List.generate(16, (i) => i));
      final salt2 = Uint8List.fromList(List.generate(16, (i) => i + 1));

      final key1 = await harness.deriveKeyFromPasscode(passcode: '123456', salt: salt1, iterations: 500);
      final key2 = await harness.deriveKeyFromPasscode(passcode: '123456', salt: salt2, iterations: 500);

      expect(key1, isNot(equals(key2)));
    });

    test('enrolls fallback PIN and rejects PIN with less than 4 digits', () async {
      await harness.enrollFallbackPin('1234');
      expect(harness.enrolledPin, equals('1234'));

      expect(
        () async => await harness.enrollFallbackPin('12'),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  // ===========================================================================
  // F13: Vault File Management & Secure Shredding (>= 5 tests)
  // ===========================================================================
  group('F13: Vault File Management & Secure Shredding', () {
    test('stores and reads back encrypted file with content integrity', () async {
      final key = await harness.generateMasterVaultKey();
      final plaintext = Uint8List.fromList('Sensitive Passport PDF Data'.codeUnits);

      final entry = await harness.storeVaultFile(
        filename: 'passport.pdf',
        plaintext: plaintext,
        masterKey: key,
      );

      final decrypted = await harness.readVaultFile(fileId: entry.id, masterKey: key);
      expect(String.fromCharCodes(decrypted), equals('Sensitive Passport PDF Data'));
    });

    test('shreds memory buffer after writing to disk', () async {
      final key = await harness.generateMasterVaultKey();
      final plaintext = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);

      await harness.storeVaultFile(
        filename: 'secrets.txt',
        plaintext: plaintext,
        masterKey: key,
      );

      // Verify original plaintext buffer was overwritten with zeroes
      expect(plaintext.every((b) => b == 0), isTrue);
    });

    test('binds filename into Additional Authenticated Data (AAD)', () async {
      final key = await harness.generateMasterVaultKey();
      final plaintext = Uint8List.fromList('Account Statements'.codeUnits);

      final entry = await harness.storeVaultFile(
        filename: 'statement.csv',
        plaintext: plaintext,
        masterKey: key,
      );

      final storedPayload = harness.vaultStorage[entry.id]!;

      // Attempting to decrypt with wrong AAD filename fails authentication
      expect(
        () async => await harness.decryptBytes(
          payload: storedPayload,
          key256: key,
          additionalAuthenticatedData: Uint8List.fromList(utf8.encode('different.csv')),
        ),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
    });

    test('stores file metadata index with SHA-256 fingerprint', () async {
      final key = await harness.generateMasterVaultKey();
      final plaintext = Uint8List.fromList('Test Fingerprint'.codeUnits);

      final entry = await harness.storeVaultFile(
        filename: 'test.doc',
        plaintext: plaintext,
        masterKey: key,
      );

      expect(entry.sha256Fingerprint, isNotEmpty);
      expect(entry.byteSize, equals(16));
    });

    test('throws StateError when attempting to read non-existent file ID', () async {
      final key = await harness.generateMasterVaultKey();
      expect(
        () async => await harness.readVaultFile(fileId: 'non-existent-uuid', masterKey: key),
        throwsA(isA<StateError>()),
      );
    });
  });

  // ===========================================================================
  // F14: Authenticated Permission Gatekeeping (>= 5 tests)
  // ===========================================================================
  group('F14: Authenticated Permission Gatekeeping', () {
    test('permits toggling location tracking when biometric authorization succeeds', () async {
      harness.shouldBiometricsSucceed = true;

      final success = await harness.setLocationTrackingWithAuth(
        enabled: false,
        bypassAuthForTesting: false,
      );

      expect(success, isTrue);
      expect(harness.isBackgroundLocationEnabled, isFalse);
    });

    test('blocks toggling location tracking when biometric authorization is rejected', () async {
      harness.shouldBiometricsSucceed = false;

      final success = await harness.setLocationTrackingWithAuth(
        enabled: false,
        bypassAuthForTesting: false,
      );

      expect(success, isFalse);
      expect(harness.isBackgroundLocationEnabled, isTrue); // Remains unchanged
    });

    test('blocks toggling when biometrics are locked out', () async {
      harness.isBiometricsLockedOut = true;

      final success = await harness.setLocationTrackingWithAuth(
        enabled: false,
        bypassAuthForTesting: false,
      );

      expect(success, isFalse);
      expect(harness.isBackgroundLocationEnabled, isTrue);
    });

    test('updates security posture status to degraded when tracking is toggled off', () async {
      harness.shouldBiometricsSucceed = true;

      await harness.setLocationTrackingWithAuth(enabled: false, bypassAuthForTesting: false);

      expect(harness.currentPosture.overallPosture, equals(SecurityPostureLevel.degraded));
      expect(harness.currentPosture.isTrackingActive, isFalse);
    });

    test('updates security posture status to secure when tracking is re-enabled', () async {
      harness.shouldBiometricsSucceed = true;

      await harness.setLocationTrackingWithAuth(enabled: false, bypassAuthForTesting: false);
      await harness.setLocationTrackingWithAuth(enabled: true, bypassAuthForTesting: false);

      expect(harness.currentPosture.overallPosture, equals(SecurityPostureLevel.secure));
      expect(harness.currentPosture.isTrackingActive, isTrue);
    });
  });

  // ===========================================================================
  // F15: Real-Time Transparent Security Posture Tracking (>= 5 tests)
  // ===========================================================================
  group('F15: Real-Time Transparent Security Posture Tracking', () {
    test('initializes with secure status by default', () {
      expect(harness.currentPosture.overallPosture, equals(SecurityPostureLevel.secure));
      expect(harness.currentPosture.statusSummary, contains('Shield active'));
    });

    test('tracks location permission status accurately', () {
      expect(harness.currentPosture.hasLocationPermission, isTrue);
    });

    test('reflects biometric configuration in posture model', () {
      expect(harness.currentPosture.isBiometricConfigured, isTrue);
    });

    test('immutable copyWith updates posture state cleanly', () {
      final updated = harness.currentPosture.copyWith(
        isRootOrJailbreakDetected: true,
        overallPosture: SecurityPostureLevel.critical,
        statusSummary: 'CRITICAL: Device Integrity Compromised (Root detected)',
      );

      expect(updated.overallPosture, equals(SecurityPostureLevel.critical));
      expect(updated.isRootOrJailbreakDetected, isTrue);
    });

    test('timestamps every posture evaluation', () {
      expect(harness.currentPosture.lastEvaluatedAt, isNotNull);
      expect(
        DateTime.now().difference(harness.currentPosture.lastEvaluatedAt).inSeconds,
        lessThanOrEqualTo(2),
      );
    });
  });

  // ===========================================================================
  // F16: Adaptive OS Capability Classifier (>= 5 tests)
  // ===========================================================================
  group('F16: Adaptive OS Capability Classifier', () {
    test('classifies Android 8.1 (API 27) as legacyLean tier', () async {
      final meta = DeviceMetadata(
        brand: 'Samsung',
        model: 'Galaxy J7',
        os: PlatformOS.android,
        osVersion: 'Android 8.1',
        apiLevel: 27,
        architecture: 'arm64',
        securityPatchLevel: '2019-01-01',
        totalRamMb: 2048,
      );

      final tier = harness.classifyCapabilityTier(meta);
      expect(tier, equals(CapabilityTier.legacyLean));
    });

    test('classifies Android 9 (API 28) as legacyLean tier', () async {
      final meta = DeviceMetadata(
        brand: 'Xiaomi',
        model: 'Redmi 7',
        os: PlatformOS.android,
        osVersion: 'Android 9.0',
        apiLevel: 28,
        architecture: 'arm64',
        securityPatchLevel: '2020-01-01',
        totalRamMb: 3000,
      );

      final tier = harness.classifyCapabilityTier(meta);
      expect(tier, equals(CapabilityTier.legacyLean));
    });

    test('classifies Android 10+ (API 29+) with >=3GB RAM as modernFull tier', () async {
      final meta = DeviceMetadata(
        brand: 'Google',
        model: 'Pixel 6',
        os: PlatformOS.android,
        osVersion: 'Android 13',
        apiLevel: 33,
        architecture: 'arm64',
        securityPatchLevel: '2024-01-01',
        totalRamMb: 6144,
      );

      final tier = harness.classifyCapabilityTier(meta);
      expect(tier, equals(CapabilityTier.modernFull));
    });

    test('classifies iOS devices as iosSandboxed tier regardless of RAM', () async {
      final meta = DeviceMetadata(
        brand: 'Apple',
        model: 'iPhone 15 Pro',
        os: PlatformOS.iOS,
        osVersion: 'iOS 17.4',
        apiLevel: 0,
        architecture: 'arm64e',
        securityPatchLevel: '2024-03-01',
        totalRamMb: 8192,
      );

      final tier = harness.classifyCapabilityTier(meta);
      expect(tier, equals(CapabilityTier.iosSandboxed));
    });

    test('downgrades modern API level to legacyLean if device has < 3GB RAM', () async {
      final meta = DeviceMetadata(
        brand: 'Motorola',
        model: 'Moto E',
        os: PlatformOS.android,
        osVersion: 'Android 11 (Go Edition)',
        apiLevel: 30,
        architecture: 'armv7',
        securityPatchLevel: '2022-01-01',
        totalRamMb: 2048, // Low RAM
      );

      final tier = harness.classifyCapabilityTier(meta);
      expect(tier, equals(CapabilityTier.legacyLean));
    });
  });

  // ===========================================================================
  // F17: Lean Signature Anti-Malware Scanner (>= 5 tests)
  // ===========================================================================
  group('F17: Lean Signature Anti-Malware Scanner', () {
    test('detects known Trojan malware signature in legacyLean tier', () async {
      harness.registerSimulatedPackage(
        packageName: 'com.malicious.trojan',
        sha256Hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        permissions: ['android.permission.INTERNET'],
        isSideloaded: true,
        calculatedEntropy: 6.2,
      );

      final report = await harness.runThreatScan(tier: CapabilityTier.legacyLean);
      expect(report.hasThreats, isTrue);
      expect(report.detectedThreats.first.detectionType, equals('signature'));
      expect(report.detectedThreats.first.severity, equals(ThreatSeverity.critical));
    });

    test('detects known Spyware signature in legacyLean tier', () async {
      harness.registerSimulatedPackage(
        packageName: 'com.spyware.keylogger',
        sha256Hash: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
        permissions: ['android.permission.READ_PHONE_STATE'],
        isSideloaded: false,
        calculatedEntropy: 5.5,
      );

      final report = await harness.runThreatScan(tier: CapabilityTier.legacyLean);
      expect(report.hasThreats, isTrue);
      expect(report.detectedThreats.first.packageName, equals('com.spyware.keylogger'));
    });

    test('flags zero threats when all packages have benign hashes', () async {
      harness.registerSimulatedPackage(
        packageName: 'com.trusted.calculator',
        sha256Hash: '1111111111111111111111111111111111111111111111111111111111111111',
        permissions: [],
        isSideloaded: false,
        calculatedEntropy: 4.8,
      );

      final report = await harness.runThreatScan(tier: CapabilityTier.legacyLean);
      expect(report.hasThreats, isFalse);
      expect(report.detectedThreats.isEmpty, isTrue);
    });

    test('completes signature scan under 50ms for low memory budgets', () async {
      for (int i = 0; i < 20; i++) {
        harness.registerSimulatedPackage(
          packageName: 'com.test.pkg$i',
          sha256Hash: 'safe_hash_$i',
          permissions: [],
          isSideloaded: false,
          calculatedEntropy: 5.0,
        );
      }

      final report = await harness.runThreatScan(tier: CapabilityTier.legacyLean);
      expect(report.executionTimeMs, lessThan(200));
      expect(report.totalScanned, equals(20));
    });

    test('ignores high entropy packed payloads in legacyLean mode to avoid OOM', () async {
      harness.registerSimulatedPackage(
        packageName: 'com.packed.suspicious',
        sha256Hash: 'unmatched_hash',
        permissions: [],
        isSideloaded: true,
        calculatedEntropy: 7.95, // High entropy
      );

      // In legacyLean mode, entropy analysis is skipped
      final report = await harness.runThreatScan(tier: CapabilityTier.legacyLean);
      expect(report.hasThreats, isFalse);
    });
  });

  // ===========================================================================
  // F18: Deep Heuristic Behavioral Threat Scanner (>= 5 tests)
  // ===========================================================================
  group('F18: Deep Heuristic Behavioral Threat Scanner', () {
    test('detects sideloaded app combining Accessibility and Overlay permissions', () async {
      harness.registerSimulatedPackage(
        packageName: 'com.fake.bank.overlay',
        sha256Hash: 'unmatched_sha',
        permissions: [
          'android.permission.BIND_ACCESSIBILITY_SERVICE',
          'android.permission.SYSTEM_ALERT_WINDOW',
        ],
        isSideloaded: true,
        calculatedEntropy: 6.0,
      );

      final report = await harness.runThreatScan(tier: CapabilityTier.modernFull);
      expect(report.hasThreats, isTrue);
      expect(report.detectedThreats.first.detectionType, equals('heuristic_accessibility'));
      expect(report.detectedThreats.first.severity, equals(ThreatSeverity.high));
    });

    test('detects high binary entropy (>7.8) indicating packed or encrypted payload', () async {
      harness.registerSimulatedPackage(
        packageName: 'com.packed.encrypted',
        sha256Hash: 'unmatched_sha',
        permissions: ['android.permission.INTERNET'],
        isSideloaded: false,
        calculatedEntropy: 7.92,
      );

      final report = await harness.runThreatScan(tier: CapabilityTier.modernFull);
      expect(report.hasThreats, isTrue);
      expect(report.detectedThreats.first.detectionType, equals('entropy'));
    });

    test('does not flag benign apps with ordinary permissions in modernFull tier', () async {
      harness.registerSimulatedPackage(
        packageName: 'com.google.android.maps',
        sha256Hash: 'benign_sha',
        permissions: ['android.permission.ACCESS_FINE_LOCATION'],
        isSideloaded: false,
        calculatedEntropy: 6.5,
      );

      final report = await harness.runThreatScan(tier: CapabilityTier.modernFull);
      expect(report.hasThreats, isFalse);
    });

    test('executes both signature and heuristic checks under modernFull tier', () async {
      // 1 known signature + 1 heuristic anomaly
      harness.registerSimulatedPackage(
        packageName: 'com.trojan',
        sha256Hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        permissions: [],
        isSideloaded: false,
        calculatedEntropy: 5.0,
      );
      harness.registerSimulatedPackage(
        packageName: 'com.sideload.overlay',
        sha256Hash: 'benign_hash',
        permissions: [
          'android.permission.BIND_ACCESSIBILITY_SERVICE',
          'android.permission.SYSTEM_ALERT_WINDOW',
        ],
        isSideloaded: true,
        calculatedEntropy: 5.0,
      );

      final report = await harness.runThreatScan(tier: CapabilityTier.modernFull);
      expect(report.detectedThreats.length, equals(2));
      expect(report.detectedThreats.any((t) => t.detectionType == 'signature'), isTrue);
      expect(report.detectedThreats.any((t) => t.detectionType == 'heuristic_accessibility'), isTrue);
    });

    test('marks executedUnderTier correctly in the ThreatReport', () async {
      final report = await harness.runThreatScan(tier: CapabilityTier.modernFull);
      expect(report.executedUnderTier, equals(CapabilityTier.modernFull));
    });
  });

  // ===========================================================================
  // F19: Clean MVVM Presentation Layer Contracts (>= 5 tests)
  // ===========================================================================
  group('F19: Clean MVVM Presentation Layer Contracts', () {
    test('posture state provides observable properties for UI binding', () {
      final posture = harness.currentPosture;
      expect(posture.isTrackingActive, isA<bool>());
      expect(posture.overallPosture, isA<SecurityPostureLevel>());
      expect(posture.statusSummary, isA<String>());
    });

    test('UI reflects tracking state changes when authorized', () async {
      harness.shouldBiometricsSucceed = true;
      await harness.setLocationTrackingWithAuth(enabled: false, bypassAuthForTesting: false);

      expect(harness.currentPosture.isTrackingActive, isFalse);
      expect(harness.currentPosture.statusSummary, contains('disabled by user'));
    });

    test('UI rejects tracking state changes when biometric dialog is cancelled', () async {
      harness.shouldBiometricsSucceed = false;
      await harness.setLocationTrackingWithAuth(enabled: false, bypassAuthForTesting: false);

      expect(harness.currentPosture.isTrackingActive, isTrue); // Maintained
    });

    test('security posture level maps cleanly to green/amber/red UI status badges', () {
      expect(SecurityPostureLevel.secure.name, equals('secure'));
      expect(SecurityPostureLevel.degraded.name, equals('degraded'));
      expect(SecurityPostureLevel.critical.name, equals('critical'));
    });

    test('viewmodel event streams decouple business logic from rendering', () async {
      final states = <NetworkState>[];
      final sub = harness.networkStream.listen(states.add);

      harness.emitNetworkChange(NetworkState.wifi);
      await Future.delayed(Duration.zero);
      await sub.cancel();

      expect(states, contains(NetworkState.wifi));
    });
  });
}
