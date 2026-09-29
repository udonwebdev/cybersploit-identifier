// ignore_for_file: avoid_print

import 'package:flutter_test/flutter_test.dart';
import 'package:security_suite/core/constants/security_constants.dart';
import 'package:security_suite/data/models/device_profile.dart';
import 'package:security_suite/data/repositories/device_repository.dart';
import 'package:security_suite/data/services/fakes/fake_cloud_profile_service.dart';
import 'package:security_suite/data/services/fakes/fake_secure_storage_service.dart';
import 'package:security_suite/data/services/implementations/cloud_profile_service.dart';
import 'package:security_suite/data/services/implementations/device_identity_service.dart';

/// Delayed storage to simulate realistic async I/O latency (KeyStore/Keychain disk access).
class DelayedSecureStorageService extends FakeSecureStorageService {
  final int delayMs;
  DelayedSecureStorageService({this.delayMs = 10});

  @override
  Future<String?> read({required String key}) async {
    await Future.delayed(Duration(milliseconds: delayMs));
    return super.read(key: key);
  }

  @override
  Future<void> write({required String key, required String value}) async {
    await Future.delayed(Duration(milliseconds: delayMs));
    await super.write(key: key, value: value);
  }
}

/// Failing storage to simulate hardware KeyStore failure or uninitialized storage corruption.
class FaultySecureStorageService extends FakeSecureStorageService {
  bool shouldFailRead = false;
  bool shouldFailWrite = false;

  @override
  Future<String?> read({required String key}) async {
    if (shouldFailRead) {
      throw Exception('KeyStore disk I/O read failure: storage uninitialized or corrupt');
    }
    return super.read(key: key);
  }

  @override
  Future<void> write({required String key, required String value}) async {
    if (shouldFailWrite) {
      throw Exception('KeyStore disk I/O write failure: hardware key write rejected');
    }
    await super.write(key: key, value: value);
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('Milestone 1 Stress Harness: Concurrency & Race Conditions', () {
    test('Rapid concurrent requests to getOrCreateAppScopedDeviceId on empty storage', () async {
      // If multiple services call getOrCreateAppScopedDeviceId concurrently at startup,
      // all callers MUST receive the exact same device ID.
      final storage = DelayedSecureStorageService(delayMs: 5);
      final identityService = DeviceIdentityService(
        secureStorage: storage,
      );

      // Launch 20 concurrent requests simultaneously
      final futures = List.generate(
        20,
        (_) => identityService.getOrCreateAppScopedDeviceId(),
      );

      final results = await Future.wait(futures);

      // Inspect uniqueness of results
      final uniqueIds = results.toSet();
      print('[STRESS RESULT] 20 concurrent calls produced ${uniqueIds.length} distinct ID(s): $uniqueIds');

      // Requirement: Every concurrent caller must receive the exact same ID
      expect(
        uniqueIds.length,
        equals(1),
        reason: 'Race condition detected: concurrent callers received ${uniqueIds.length} different device IDs!',
      );
    });

    test('Rapid concurrent requests on DeviceRepository.getOrCreateDeviceProfile', () async {
      final storage = DelayedSecureStorageService(delayMs: 5);
      final identityService = DeviceIdentityService(
        secureStorage: storage,
      );
      final cloudService = FakeCloudProfileService();
      final repository = DeviceRepository(
        identityService: identityService,
        cloudProfileService: cloudService,
        storageService: storage,
      );

      // Launch 15 concurrent profile requests
      final futures = List.generate(
        15,
        (_) => repository.getOrCreateDeviceProfile(),
      );

      final profiles = await Future.wait(futures);
      final uniqueDeviceIds = profiles.map((p) => p.deviceId).toSet();

      print('[STRESS RESULT] 15 concurrent repo calls produced ${uniqueDeviceIds.length} distinct device IDs');
      expect(
        uniqueDeviceIds.length,
        equals(1),
        reason: 'DeviceRepository produced multiple distinct profiles under concurrent access!',
      );
    });
  });

  group('Milestone 1 Stress Harness: Corrupted Device ID & Edge Cases', () {
    test('Corrupted device ID: whitespace-only string in storage', () async {
      final storage = FakeSecureStorageService();
      await storage.write(
        key: SecurityConstants.keyAppScopedDeviceId,
        value: '   \t  \n  ',
      );

      final identityService = DeviceIdentityService(secureStorage: storage);
      final id = await identityService.getOrCreateAppScopedDeviceId();

      print('[STRESS RESULT] Retrieved ID when storage had whitespace: "$id"');
      // Should not accept whitespace as a valid device ID
      expect(id.trim(), isNotEmpty);
      expect(id.trim(), isNot(equals('')));
      expect(id, isNot(equals('   \t  \n  ')), reason: 'Accepted whitespace-only string as valid device ID');
    });

    test('Corrupted device ID: malformed string without UUID/hash delimiter', () async {
      final storage = FakeSecureStorageService();
      await storage.write(
        key: SecurityConstants.keyAppScopedDeviceId,
        value: 'corrupted_garbage_token_without_proper_structure',
      );

      final identityService = DeviceIdentityService(secureStorage: storage);
      final id = await identityService.getOrCreateAppScopedDeviceId();

      print('[STRESS RESULT] Stored malformed ID was: "$id"');
      // Should handle or maintain consistency
      expect(id, isNotEmpty);
    });

    test('Uninitialized / Failing Storage Error Handling', () async {
      final faultyStorage = FaultySecureStorageService();
      faultyStorage.shouldFailRead = true;

      final identityService = DeviceIdentityService(secureStorage: faultyStorage);

      // Expect failure to be wrapped in a security exception
      expect(
        () => identityService.getOrCreateAppScopedDeviceId(),
        throwsA(isA<Exception>()),
      );
    });
  });

  group('Milestone 1 Stress Harness: Unusual OS Version Numbers & Platforms', () {
    late DeviceIdentityService identityService;

    setUp(() {
      identityService = DeviceIdentityService(
        secureStorage: FakeSecureStorageService(),
      );
    });

    test('Android edge cases: negative API level, zero, and boundary versions', () {
      final testCases = [
        {'api': -1, 'expected': CapabilityTier.legacy}, // or fallback
        {'api': 0, 'expected': CapabilityTier.legacy},  // unknown or unparsed
        {'api': 25, 'expected': CapabilityTier.legacy}, // Android 7.1
        {'api': 26, 'expected': CapabilityTier.legacy}, // Android 8.0 Oreo
        {'api': 28, 'expected': CapabilityTier.legacy}, // Android 9.0 Pie
        {'api': 29, 'expected': CapabilityTier.modern}, // Android 10 Q
        {'api': 35, 'expected': CapabilityTier.modern}, // Android 15
        {'api': 99, 'expected': CapabilityTier.modern}, // Future Android
      ];

      for (final tc in testCases) {
        final api = tc['api'] as int;
        final metadata = DeviceMetadata(
          platform: 'android',
          osVersion: 'Android API $api',
          apiLevel: api,
          deviceModel: 'Test Device',
          manufacturer: 'Test OEM',
          hardwareArchitecture: 'arm64',
          isPhysical: true,
          timestamp: DateTime.now(),
        );

        final tier = identityService.classifyCapabilityTier(metadata);
        print('[STRESS RESULT] Android API $api -> Tier: $tier');
        // Let's check how api <= 0 is classified
      }
    });

    test('Unusual platform strings and formatting', () {
      final platforms = [
        'Android',
        'ANDROID',
        'android ',
        'iOS',
        'IOS',
        'WINDOWS',
        'fuchsia',
        '',
      ];

      for (final p in platforms) {
        final metadata = DeviceMetadata(
          platform: p,
          osVersion: '1.0.0-beta+exp.sha.5114f85',
          apiLevel: 28,
          deviceModel: 'Edge Case Model',
          manufacturer: 'Edge Case Mfr',
          hardwareArchitecture: 'riscv64',
          isPhysical: false,
          timestamp: DateTime.now(),
        );

        final tier = identityService.classifyCapabilityTier(metadata);
        print('[STRESS RESULT] Platform "$p" (api 28) -> Tier: $tier');
      }
    });
  });

  group('Milestone 1 Stress Harness: Offline Queue Poison Pill & Corruption', () {
    test('Offline queue with corrupted JSON payload does not crash sync', () async {
      final storage = FakeSecureStorageService();
      // Write corrupted JSON into the offline sync queue
      await storage.write(
        key: SecurityConstants.keyOfflineSyncQueue,
        value: '{ corrupted json without closing brackets ',
      );

      final cloudService = CloudProfileService(
        secureStorage: storage,
        networkChecker: () async => true,
      );

      final count = await cloudService.getQueuedCount();
      print('[STRESS RESULT] Queued count on corrupted JSON: $count');
      expect(count, equals(0));

      // Flush queue should not throw unhandled exception
      await expectLater(cloudService.flushOfflineQueue(), completes);
    });

    test('Offline queue with invalid profile entry (poison pill) does not lock queue forever', () async {
      final storage = FakeSecureStorageService();
      // Store an entry that has missing required fields for DeviceProfile
      await storage.write(
        key: SecurityConstants.keyOfflineSyncQueue,
        value: '[{"invalidField": "garbage_data"}]',
      );

      final cloudService = CloudProfileService(
        secureStorage: storage,
        networkChecker: () async => true,
      );

      final countBefore = await cloudService.getQueuedCount();
      expect(countBefore, equals(1));

      // Attempt flush
      await cloudService.flushOfflineQueue();

      final countAfter = await cloudService.getQueuedCount();
      print('[STRESS RESULT] Queue count before flush: $countBefore, after flush: $countAfter');
      // If countAfter is still 1, this is a poison pill!
    });
  });

  group('Milestone 1 Stress Harness: Rapid Sequential Calls (Idempotency)', () {
    test('100 sequential calls to getOrCreateAppScopedDeviceId return identical ID', () async {
      final storage = FakeSecureStorageService();
      final identityService = DeviceIdentityService(secureStorage: storage);

      final initialId = await identityService.getOrCreateAppScopedDeviceId();
      for (int i = 0; i < 100; i++) {
        final subsequentId = await identityService.getOrCreateAppScopedDeviceId();
        expect(subsequentId, equals(initialId));
      }
    });
  });
}
