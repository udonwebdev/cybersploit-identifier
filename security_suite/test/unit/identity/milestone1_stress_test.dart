import 'package:flutter_test/flutter_test.dart';
import 'package:security_suite/core/constants/security_constants.dart';
import 'package:security_suite/data/models/device_profile.dart';
import 'package:security_suite/data/services/contracts/i_cloud_profile_service.dart';
import 'package:security_suite/data/services/fakes/fake_secure_storage_service.dart';
import 'package:security_suite/data/services/implementations/cloud_profile_service.dart';
import 'package:security_suite/data/services/implementations/device_identity_service.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('Milestone 1 Empirical Stress Tests: Offline Queue Handling', () {
    late FakeSecureStorageService fakeStorage;
    late CloudProfileService cloudService;
    bool isNetworkOnline = false;

    setUp(() {
      fakeStorage = FakeSecureStorageService();
      isNetworkOnline = false;
      cloudService = CloudProfileService(
        secureStorage: fakeStorage,
        networkChecker: () async => isNetworkOnline,
      );
    });

    tearDown(() {
      cloudService.dispose();
    });

    DeviceProfile createDummyProfile({
      required String deviceId,
      String model = 'Pixel 8',
      int apiLevel = 34,
      int battery = 100,
      DateTime? timestamp,
    }) {
      final now = timestamp ?? DateTime.now();
      return DeviceProfile(
        deviceId: deviceId,
        metadata: DeviceMetadata(
          platform: 'android',
          osVersion: 'Android 14',
          apiLevel: apiLevel,
          deviceModel: model,
          manufacturer: 'Google',
          hardwareArchitecture: 'arm64-v8a',
          isPhysical: true,
          timestamp: now,
        ),
        capabilityTier: CapabilityTier.modern,
        lastSeen: now,
        tamperFlags: {'rootDetected': false},
        trackingStatus: {'batteryLevel': battery, 'trackingEnabled': true},
        vaultMetadata: {'vaultVersion': 1, 'itemsCount': 0},
      );
    }

    test('1. Rapid offline sync enqueuing (bursts of profiles across multiple devices)', () async {
      isNetworkOnline = false;
      const count = 50;

      // Enqueue 50 distinct device profiles rapidly
      for (var i = 0; i < count; i++) {
        final profile = createDummyProfile(
          deviceId: 'device-burst-$i',
          battery: i,
        );
        await cloudService.syncDeviceProfile(profile);
      }

      final queuedCount = await cloudService.getQueuedCount();
      expect(queuedCount, equals(count),
          reason: 'All 50 rapid distinct device profiles should be buffered in offline queue');

      // Now restore network and flush
      isNetworkOnline = true;
      await cloudService.flushOfflineQueue();

      final flushedQueuedCount = await cloudService.getQueuedCount();
      expect(flushedQueuedCount, equals(0),
          reason: 'Queue should be empty after flushing');

      // Verify all 50 are present in remote store
      for (var i = 0; i < count; i++) {
        final remote = await cloudService.fetchDeviceProfile('device-burst-$i');
        expect(remote, isNotNull);
        expect(remote!.trackingStatus['batteryLevel'], equals(i));
      }
    });

    test('2. Deduplication: Rapid sequential updates to the same deviceId while offline preserves latest state and maintains queue length 1', () async {
      isNetworkOnline = false;
      const deviceId = 'dedup-device-target';

      // Push 20 successive posture/battery updates for the same deviceId while offline
      for (var i = 1; i <= 20; i++) {
        final profile = createDummyProfile(
          deviceId: deviceId,
          battery: i * 5,
        );
        await cloudService.syncDeviceProfile(profile);
      }

      // Deduplication check: queue length MUST be exactly 1, not 20
      final queueCount = await cloudService.getQueuedCount();
      expect(queueCount, equals(1),
          reason: 'Offline queue must deduplicate entries by deviceId so old states do not pile up');

      // Restore network and flush
      isNetworkOnline = true;
      await cloudService.flushOfflineQueue();

      final remote = await cloudService.fetchDeviceProfile(deviceId);
      expect(remote, isNotNull);
      // The latest battery state (20 * 5 = 100) must be stored
      expect(remote!.trackingStatus['batteryLevel'], equals(100),
          reason: 'Flushed profile must contain the latest state (batteryLevel = 100)');
    });

    test('3. Deduplication across multiple interleaved devices while offline', () async {
      isNetworkOnline = false;

      // Interleave updates between device-A, device-B, and device-C
      final devices = ['device-A', 'device-B', 'device-C'];
      for (var round = 1; round <= 10; round++) {
        for (final id in devices) {
          final profile = createDummyProfile(
            deviceId: id,
            battery: round * 10,
          );
          await cloudService.syncDeviceProfile(profile);
        }
      }

      // Total queued count should be exactly 3 (one per device)
      final queueCount = await cloudService.getQueuedCount();
      expect(queueCount, equals(3),
          reason: 'Interleaved updates across 3 devices should result in exactly 3 queued records');

      // Verify the latest value after flush
      isNetworkOnline = true;
      await cloudService.flushOfflineQueue();

      for (final id in devices) {
        final doc = await cloudService.fetchDeviceProfile(id);
        expect(doc, isNotNull);
        expect(doc!.trackingStatus['batteryLevel'], equals(100));
      }
    });

    test('4. Offline queue persistence across simulated application restart', () async {
      isNetworkOnline = false;

      // Enqueue 5 items in first cloud service instance
      for (var i = 0; i < 5; i++) {
        final profile = createDummyProfile(deviceId: 'restart-device-$i');
        await cloudService.syncDeviceProfile(profile);
      }

      expect(await cloudService.getQueuedCount(), equals(5));

      // Simulate app kill: dispose current service instance
      cloudService.dispose();

      // Verify the underlying secure storage contains the serialized queue
      final rawQueue = await fakeStorage.read(key: SecurityConstants.keyOfflineSyncQueue);
      expect(rawQueue, isNotNull);
      expect(rawQueue!.isNotEmpty, isTrue);

      // Simulate app restart: Instantiate a brand new CloudProfileService using the SAME secure storage
      final restartedCloudService = CloudProfileService(
        secureStorage: fakeStorage,
        networkChecker: () async => isNetworkOnline,
      );

      // Verify new service instance reads persisted queue
      final restoredCount = await restartedCloudService.getQueuedCount();
      expect(restoredCount, equals(5),
          reason: 'Restored service instance must read the 5 persisted items from secure storage');

      // Now bring network online and flush with the new service instance
      isNetworkOnline = true;
      await restartedCloudService.flushOfflineQueue();

      expect(await restartedCloudService.getQueuedCount(), equals(0));

      for (var i = 0; i < 5; i++) {
        final remote = await restartedCloudService.fetchDeviceProfile('restart-device-$i');
        expect(remote, isNotNull,
            reason: 'device restart-device-$i should be synced after flush in new instance');
      }

      restartedCloudService.dispose();
    });

    test('5. Network flapping stress test (rapid online/offline toggling during enqueuing and flushing)', () async {
      final statuses = <SyncStatus>[];
      final subscription = cloudService.syncStatusStream.listen(statuses.add);

      for (var cycle = 0; cycle < 10; cycle++) {
        // Step A: Offline burst
        isNetworkOnline = false;
        final p1 = createDummyProfile(
          deviceId: 'flap-dev-$cycle',
          battery: cycle,
        );
        await cloudService.syncDeviceProfile(p1);

        // Step B: Online toggle & flush
        isNetworkOnline = true;
        await cloudService.flushOfflineQueue();

        // Step C: Online direct sync
        final p2 = createDummyProfile(
          deviceId: 'flap-dev-direct-$cycle',
          battery: cycle + 50,
        );
        await cloudService.syncDeviceProfile(p2);

        // Step D: Network drops again
        isNetworkOnline = false;
      }

      await pumpEventQueue();

      // Finally bring online and flush everything
      isNetworkOnline = true;
      await cloudService.flushOfflineQueue();
      await pumpEventQueue();

      expect(await cloudService.getQueuedCount(), equals(0),
          reason: 'Offline queue should be fully drained after flapping resolution');

      // Check all 20 devices exist in remote store
      for (var cycle = 0; cycle < 10; cycle++) {
        final doc1 = await cloudService.fetchDeviceProfile('flap-dev-$cycle');
        expect(doc1, isNotNull, reason: 'flap-dev-$cycle must be in remote store');

        final doc2 = await cloudService.fetchDeviceProfile('flap-dev-direct-$cycle');
        expect(doc2, isNotNull, reason: 'flap-dev-direct-$cycle must be in remote store');
      }

      await subscription.cancel();
    });
  });

  group('Milestone 1 Empirical Stress Tests: Capability Tier Boundary Values', () {
    late DeviceIdentityService identityService;

    setUp(() {
      identityService = DeviceIdentityService(
        secureStorage: FakeSecureStorageService(),
      );
    });

    test('Boundary: Android API 25 (Android 7.1 Nougat - pre-minimum supported version)', () {
      final metadata = DeviceMetadata(
        platform: 'android',
        osVersion: 'Android 7.1.1',
        apiLevel: 25,
        deviceModel: 'Nexus 6P',
        manufacturer: 'Huawei',
        hardwareArchitecture: 'arm64-v8a',
        isPhysical: true,
        timestamp: DateTime.now(),
      );
      final tier = identityService.classifyCapabilityTier(metadata);
      expect(tier, equals(CapabilityTier.legacy),
          reason: 'API 25 is < 29, falls into legacy tier');
    });

    test('Boundary: Android API 26 (Android 8.0 Oreo - exact minimum supported version)', () {
      final metadata = DeviceMetadata(
        platform: 'android',
        osVersion: 'Android 8.0',
        apiLevel: 26,
        deviceModel: 'Pixel',
        manufacturer: 'Google',
        hardwareArchitecture: 'arm64-v8a',
        isPhysical: true,
        timestamp: DateTime.now(),
      );
      final tier = identityService.classifyCapabilityTier(metadata);
      expect(tier, equals(CapabilityTier.legacy),
          reason: 'Android 8.0 (API 26) is the lower boundary of legacy tier');
    });

    test('Boundary: Android API 28 (Android 9.0 Pie - exact upper boundary of legacy tier)', () {
      final metadata = DeviceMetadata(
        platform: 'android',
        osVersion: 'Android 9.0',
        apiLevel: 28,
        deviceModel: 'Pixel 3',
        manufacturer: 'Google',
        hardwareArchitecture: 'arm64-v8a',
        isPhysical: true,
        timestamp: DateTime.now(),
      );
      final tier = identityService.classifyCapabilityTier(metadata);
      expect(tier, equals(CapabilityTier.legacy),
          reason: 'Android 9.0 (API 28) must be legacy tier (< API 29)');
    });

    test('Boundary: Android API 29 (Android 10 Q - exact lower boundary of modern tier)', () {
      final metadata = DeviceMetadata(
        platform: 'android',
        osVersion: 'Android 10',
        apiLevel: 29,
        deviceModel: 'Pixel 4',
        manufacturer: 'Google',
        hardwareArchitecture: 'arm64-v8a',
        isPhysical: true,
        timestamp: DateTime.now(),
      );
      final tier = identityService.classifyCapabilityTier(metadata);
      expect(tier, equals(CapabilityTier.modern),
          reason: 'Android 10 (API 29) is the strict transition boundary to modern tier');
    });

    test('Boundary: Android API 30 (Android 11 - interior modern tier)', () {
      final metadata = DeviceMetadata(
        platform: 'android',
        osVersion: 'Android 11',
        apiLevel: 30,
        deviceModel: 'Pixel 5',
        manufacturer: 'Google',
        hardwareArchitecture: 'arm64-v8a',
        isPhysical: true,
        timestamp: DateTime.now(),
      );
      final tier = identityService.classifyCapabilityTier(metadata);
      expect(tier, equals(CapabilityTier.modern));
    });

    test('Boundary: Android API 34 (Android 14 - modern target tier)', () {
      final metadata = DeviceMetadata(
        platform: 'android',
        osVersion: 'Android 14',
        apiLevel: 34,
        deviceModel: 'Pixel 8 Pro',
        manufacturer: 'Google',
        hardwareArchitecture: 'arm64-v8a',
        isPhysical: true,
        timestamp: DateTime.now(),
      );
      final tier = identityService.classifyCapabilityTier(metadata);
      expect(tier, equals(CapabilityTier.modern));
    });

    test('Edge case: Android API Level 0 or negative (corrupt / unparsed sdkInt)', () {
      final metadataZero = DeviceMetadata(
        platform: 'android',
        osVersion: 'Android Custom',
        apiLevel: 0,
        deviceModel: 'Custom ROM',
        manufacturer: 'Unknown',
        hardwareArchitecture: 'arm64',
        isPhysical: true,
        timestamp: DateTime.now(),
      );
      // apiLevel <= 0 does not satisfy apiLevel > 0 && apiLevel < 29, so it falls through to modern
      final tierZero = identityService.classifyCapabilityTier(metadataZero);
      expect(tierZero, equals(CapabilityTier.modern));

      final metadataNeg = metadataZero.copyWith(apiLevel: -1);
      final tierNeg = identityService.classifyCapabilityTier(metadataNeg);
      expect(tierNeg, equals(CapabilityTier.modern));
    });

    test('Boundary: iOS versions (iOS 14, 15, 16, 17, 18)', () {
      final iosVersions = [
        {'version': 'iOS 14.8', 'major': 14},
        {'version': 'iOS 15.7', 'major': 15},
        {'version': 'iOS 16.6', 'major': 16},
        {'version': 'iOS 17.5', 'major': 17},
        {'version': 'iOS 18.0', 'major': 18},
      ];

      for (final entry in iosVersions) {
        final metadata = DeviceMetadata(
          platform: 'ios',
          osVersion: entry['version'] as String,
          apiLevel: entry['major'] as int,
          deviceModel: 'iPhone',
          manufacturer: 'Apple',
          hardwareArchitecture: 'arm64',
          isPhysical: true,
          timestamp: DateTime.now(),
        );
        final tier = identityService.classifyCapabilityTier(metadata);
        expect(tier, equals(CapabilityTier.modern),
            reason: '${entry['version']} must classify as modern');
      }
    });

    test('Platform case insensitivity: "Android", "ANDROID", "iOS", "IOS"', () {
      final p1 = DeviceMetadata(
        platform: 'Android',
        osVersion: '8.1',
        apiLevel: 27,
        deviceModel: 'M',
        manufacturer: 'O',
        hardwareArchitecture: 'arm',
        isPhysical: true,
        timestamp: DateTime.now(),
      );
      expect(identityService.classifyCapabilityTier(p1), equals(CapabilityTier.legacy));

      final p2 = p1.copyWith(platform: 'ANDROID', apiLevel: 31);
      expect(identityService.classifyCapabilityTier(p2), equals(CapabilityTier.modern));

      final p3 = p1.copyWith(platform: 'IOS', apiLevel: 16);
      expect(identityService.classifyCapabilityTier(p3), equals(CapabilityTier.modern));
    });
  });
}
