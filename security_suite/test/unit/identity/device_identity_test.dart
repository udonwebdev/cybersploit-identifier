import 'package:flutter_test/flutter_test.dart';
import 'package:security_suite/core/constants/security_constants.dart';
import 'package:security_suite/core/di/service_locator.dart';
import 'package:security_suite/data/models/device_profile.dart';
import 'package:security_suite/data/models/security_posture.dart';
import 'package:security_suite/data/repositories/device_repository.dart';
import 'package:security_suite/data/services/contracts/i_cloud_profile_service.dart';
import 'package:security_suite/data/services/contracts/i_device_identity_service.dart';
import 'package:security_suite/data/services/contracts/i_secure_storage_service.dart';
import 'package:security_suite/data/services/fakes/fake_cloud_profile_service.dart';
import 'package:security_suite/data/services/fakes/fake_device_identity_service.dart';
import 'package:security_suite/data/services/fakes/fake_secure_storage_service.dart';
import 'package:security_suite/data/services/implementations/cloud_profile_service.dart';
import 'package:security_suite/data/services/implementations/device_identity_service.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('Device Models & Serialization', () {
    test('DeviceMetadata serialization and deserialization roundtrip', () {
      final now = DateTime.now();
      final metadata = DeviceMetadata(
        platform: 'android',
        osVersion: 'Android 14',
        apiLevel: 34,
        deviceModel: 'Pixel 8 Pro',
        manufacturer: 'Google',
        hardwareArchitecture: 'arm64-v8a',
        isPhysical: true,
        timestamp: now,
      );

      final map = metadata.toMap();
      expect(map['platform'], equals('android'));
      expect(map['apiLevel'], equals(34));
      expect(map['deviceModel'], equals('Pixel 8 Pro'));

      final reconstructed = DeviceMetadata.fromMap(map);
      expect(reconstructed.platform, equals(metadata.platform));
      expect(reconstructed.osVersion, equals(metadata.osVersion));
      expect(reconstructed.apiLevel, equals(metadata.apiLevel));
      expect(reconstructed.deviceModel, equals(metadata.deviceModel));
      expect(reconstructed.manufacturer, equals(metadata.manufacturer));
      expect(reconstructed.hardwareArchitecture, equals(metadata.hardwareArchitecture));
      expect(reconstructed.isPhysical, equals(metadata.isPhysical));
    });

    test('DeviceProfile serialization and deserialization roundtrip', () {
      final now = DateTime.now();
      final profile = DeviceProfile(
        deviceId: 'test-device-uuid-1234',
        metadata: DeviceMetadata(
          platform: 'ios',
          osVersion: 'iOS 17.4',
          apiLevel: 17,
          deviceModel: 'iPhone 15 Pro',
          manufacturer: 'Apple',
          hardwareArchitecture: 'arm64',
          isPhysical: true,
          timestamp: now,
        ),
        capabilityTier: CapabilityTier.modern,
        lastSeen: now,
        tamperFlags: {'jailbreakDetected': false, 'debuggerAttached': false},
        trackingStatus: {'trackingEnabled': true, 'geofenceActive': false},
        vaultMetadata: {'vaultVersion': 1, 'itemsCount': 5},
      );

      final jsonString = profile.toJson();
      final reconstructed = DeviceProfile.fromJson(jsonString);

      expect(reconstructed.deviceId, equals('test-device-uuid-1234'));
      expect(reconstructed.capabilityTier, equals(CapabilityTier.modern));
      expect(reconstructed.tamperFlags['jailbreakDetected'], isFalse);
      expect(reconstructed.trackingStatus['trackingEnabled'], isTrue);
      expect(reconstructed.vaultMetadata['itemsCount'], equals(5));
    });

    test('SecurityPostureState initial factory and copyWith', () {
      final initial = SecurityPostureState.initial();
      expect(initial.overallPosture, equals(SecurityLevel.degraded));
      expect(initial.isTrackingActive, isFalse);
      expect(initial.isBiometricConfigured, isFalse);

      final updated = initial.copyWith(
        isTrackingActive: true,
        hasLocationPermission: true,
        isBiometricConfigured: true,
        overallPosture: SecurityLevel.high,
        statusSummary: 'All protections active',
      );

      expect(updated.isTrackingActive, isTrue);
      expect(updated.hasLocationPermission, isTrue);
      expect(updated.isBiometricConfigured, isTrue);
      expect(updated.overallPosture, equals(SecurityLevel.high));
      expect(updated.statusSummary, equals('All protections active'));
    });
  });

  group('DeviceIdentityService & Provisioning', () {
    late FakeSecureStorageService fakeStorage;
    late DeviceIdentityService identityService;

    setUp(() {
      fakeStorage = FakeSecureStorageService();
      identityService = DeviceIdentityService(
        secureStorage: fakeStorage,
      );
    });

    test('provisions a persistent app-scoped device ID on first launch', () async {
      final deviceId1 = await identityService.getOrCreateAppScopedDeviceId();
      expect(deviceId1, isNotEmpty);
      expect(deviceId1.contains('-'), isTrue);

      // Verify it was persisted in secure storage
      final storedId = await fakeStorage.read(
        key: SecurityConstants.keyAppScopedDeviceId,
      );
      expect(storedId, equals(deviceId1));

      // Verify fingerprint was also stored
      final storedFingerprint = await fakeStorage.read(
        key: SecurityConstants.keyDeviceFingerprint,
      );
      expect(storedFingerprint, isNotNull);
      expect(storedFingerprint!.length, equals(64)); // SHA-256 length

      // Subsequent call must return identical device ID (idempotency)
      final deviceId2 = await identityService.getOrCreateAppScopedDeviceId();
      expect(deviceId2, equals(deviceId1));
    });

    test('uses existing device ID if already provisioned in secure storage', () async {
      const existingId = 'pre-existing-hardened-device-uuid-9999';
      await fakeStorage.write(
        key: SecurityConstants.keyAppScopedDeviceId,
        value: existingId,
      );

      final retrievedId = await identityService.getOrCreateAppScopedDeviceId();
      expect(retrievedId, equals(existingId));
    });
  });

  group('Capability Tier Classification (R5)', () {
    late DeviceIdentityService identityService;

    setUp(() {
      identityService = DeviceIdentityService(
        secureStorage: FakeSecureStorageService(),
      );
    });

    test('classifies Android API 26 (Android 8.0 Oreo) as CapabilityTier.legacy', () {
      final metadata = DeviceMetadata(
        platform: 'android',
        osVersion: 'Android 8.0.0',
        apiLevel: 26,
        deviceModel: 'Nexus 5X',
        manufacturer: 'LG',
        hardwareArchitecture: 'arm64-v8a',
        isPhysical: true,
        timestamp: DateTime.now(),
      );

      final tier = identityService.classifyCapabilityTier(metadata);
      expect(tier, equals(CapabilityTier.legacy));
    });

    test('classifies Android API 28 (Android 9.0 Pie) as CapabilityTier.legacy', () {
      final metadata = DeviceMetadata(
        platform: 'android',
        osVersion: 'Android 9.0',
        apiLevel: 28,
        deviceModel: 'Pixel 2',
        manufacturer: 'Google',
        hardwareArchitecture: 'arm64-v8a',
        isPhysical: true,
        timestamp: DateTime.now(),
      );

      final tier = identityService.classifyCapabilityTier(metadata);
      expect(tier, equals(CapabilityTier.legacy));
    });

    test('classifies Android API 29 (Android 10 Q) as CapabilityTier.modern', () {
      final metadata = DeviceMetadata(
        platform: 'android',
        osVersion: 'Android 10',
        apiLevel: 29,
        deviceModel: 'Pixel 3',
        manufacturer: 'Google',
        hardwareArchitecture: 'arm64-v8a',
        isPhysical: true,
        timestamp: DateTime.now(),
      );

      final tier = identityService.classifyCapabilityTier(metadata);
      expect(tier, equals(CapabilityTier.modern));
    });

    test('classifies Android API 34 (Android 14) as CapabilityTier.modern', () {
      final metadata = DeviceMetadata(
        platform: 'android',
        osVersion: 'Android 14',
        apiLevel: 34,
        deviceModel: 'Pixel 8',
        manufacturer: 'Google',
        hardwareArchitecture: 'arm64-v8a',
        isPhysical: true,
        timestamp: DateTime.now(),
      );

      final tier = identityService.classifyCapabilityTier(metadata);
      expect(tier, equals(CapabilityTier.modern));
    });

    test('classifies iOS platforms as CapabilityTier.modern', () {
      final metadata = DeviceMetadata(
        platform: 'ios',
        osVersion: 'iOS 17.4',
        apiLevel: 17,
        deviceModel: 'iPhone 15 Pro',
        manufacturer: 'Apple',
        hardwareArchitecture: 'arm64',
        isPhysical: true,
        timestamp: DateTime.now(),
      );

      final tier = identityService.classifyCapabilityTier(metadata);
      expect(tier, equals(CapabilityTier.modern));
    });
  });

  group('CloudProfileService Synchronization & Offline Queueing (R1)', () {
    late FakeSecureStorageService fakeStorage;
    late CloudProfileService cloudService;
    bool isNetworkOnline = true;

    setUp(() {
      fakeStorage = FakeSecureStorageService();
      isNetworkOnline = true;
      cloudService = CloudProfileService(
        secureStorage: fakeStorage,
        networkChecker: () async => isNetworkOnline,
      );
    });

    tearDown(() {
      cloudService.dispose();
    });

    test('sanitizes coordinates and sensitive fields before sync', () {
      final profile = DeviceProfile(
        deviceId: 'clean-device-1',
        metadata: DeviceMetadata(
          platform: 'android',
          osVersion: 'Android 14',
          apiLevel: 34,
          deviceModel: r'Pixel 8 Pro$$$!@#',
          manufacturer: 'Google Inc. <test>',
          hardwareArchitecture: 'arm64-v8a',
          isPhysical: true,
          timestamp: DateTime.now(),
        ),
        capabilityTier: CapabilityTier.modern,
        lastSeen: DateTime.now(),
        tamperFlags: {
          'rootDetected': false,
          'invalidSecretFlag': 'malicious_injection',
          'debuggerAttached': true,
        },
        trackingStatus: {
          'latitude': 37.774929845729,
          'longitude': -122.41941551234,
          'unapprovedKey': 'leak',
          'geofenceActive': true,
        },
      );

      final sanitized = cloudService.sanitizeProfile(profile);

      // Model and manufacturer special characters sanitized
      expect(sanitized.metadata.deviceModel, equals('Pixel 8 Pro'));
      expect(sanitized.metadata.manufacturer, equals('Google Inc. test'));

      // Tamper flags filtered to allowed whitelist only
      expect(sanitized.tamperFlags.containsKey('invalidSecretFlag'), isFalse);
      expect(sanitized.tamperFlags['rootDetected'], isFalse);
      expect(sanitized.tamperFlags['debuggerAttached'], isTrue);

      // Coordinates truncated to 5 decimal places (~1 meter privacy precision)
      expect(sanitized.trackingStatus['latitude'], equals(37.77493));
      expect(sanitized.trackingStatus['longitude'], equals(-122.41942));
      expect(sanitized.trackingStatus.containsKey('unapprovedKey'), isFalse);
      expect(sanitized.trackingStatus['geofenceActive'], isTrue);
    });

    test('syncs profile online and saves to remote store', () async {
      final profile = DeviceProfile(
        deviceId: 'online-device-100',
        metadata: DeviceMetadata(
          platform: 'android',
          osVersion: 'Android 14',
          apiLevel: 34,
          deviceModel: 'Galaxy S24',
          manufacturer: 'Samsung',
          hardwareArchitecture: 'arm64-v8a',
          isPhysical: true,
          timestamp: DateTime.now(),
        ),
        capabilityTier: CapabilityTier.modern,
        lastSeen: DateTime.now(),
      );

      final statusEvents = <SyncStatus>[];
      final subscription = cloudService.syncStatusStream.listen(statusEvents.add);

      await cloudService.syncDeviceProfile(profile);
      await pumpEventQueue();

      expect(statusEvents, contains(SyncStatus.synced));

      final remoteDoc = await cloudService.fetchDeviceProfile('online-device-100');
      expect(remoteDoc, isNotNull);
      expect(remoteDoc!.deviceId, equals('online-device-100'));
      expect(remoteDoc.capabilityTier, equals(CapabilityTier.modern));

      final queueCount = await cloudService.getQueuedCount();
      expect(queueCount, equals(0));

      await subscription.cancel();
    });

    test('buffers profile into offline queue when offline and flushes when online', () async {
      isNetworkOnline = false; // Simulate offline launch

      final profile = DeviceProfile(
        deviceId: 'offline-device-200',
        metadata: DeviceMetadata(
          platform: 'ios',
          osVersion: 'iOS 17.4',
          apiLevel: 17,
          deviceModel: 'iPhone 15',
          manufacturer: 'Apple',
          hardwareArchitecture: 'arm64',
          isPhysical: true,
          timestamp: DateTime.now(),
        ),
        capabilityTier: CapabilityTier.modern,
        lastSeen: DateTime.now(),
      );

      final statusEvents = <SyncStatus>[];
      final subscription = cloudService.syncStatusStream.listen(statusEvents.add);

      await cloudService.syncDeviceProfile(profile);
      await pumpEventQueue();

      expect(statusEvents, contains(SyncStatus.offlineQueued));

      // Remotely not yet available
      final remoteDoc = await cloudService.fetchDeviceProfile('offline-device-200');
      expect(remoteDoc, isNull);

      // Offline queue count should be 1
      final queuedCount = await cloudService.getQueuedCount();
      expect(queuedCount, equals(1));

      // Now restore network and flush
      isNetworkOnline = true;
      await cloudService.flushOfflineQueue();
      await pumpEventQueue();

      expect(statusEvents, contains(SyncStatus.synced));

      final flushedDoc = await cloudService.fetchDeviceProfile('offline-device-200');
      expect(flushedDoc, isNotNull);
      expect(flushedDoc!.deviceId, equals('offline-device-200'));

      final finalQueueCount = await cloudService.getQueuedCount();
      expect(finalQueueCount, equals(0));

      await subscription.cancel();
    });
  });

  group('DeviceRepository Integration with Fakes', () {
    late FakeSecureStorageService fakeStorage;
    late FakeDeviceIdentityService fakeIdentity;
    late FakeCloudProfileService fakeCloud;
    late DeviceRepository repository;

    setUp(() {
      fakeStorage = FakeSecureStorageService();
      fakeIdentity = FakeDeviceIdentityService(
        storageService: fakeStorage,
        mockMetadata: DeviceMetadata(
          platform: 'android',
          osVersion: 'Android 14',
          apiLevel: 34,
          deviceModel: 'Pixel 8 Pro',
          manufacturer: 'Google',
          hardwareArchitecture: 'arm64-v8a',
          isPhysical: true,
          timestamp: DateTime.now(),
        ),
      );
      fakeCloud = FakeCloudProfileService();
      repository = DeviceRepository(
        identityService: fakeIdentity,
        cloudProfileService: fakeCloud,
        storageService: fakeStorage,
      );
    });

    tearDown(() {
      fakeCloud.dispose();
    });

    test('getOrCreateDeviceProfile provisions, caches, and syncs profile', () async {
      final profile = await repository.getOrCreateDeviceProfile();

      expect(profile.deviceId, isNotEmpty);
      expect(profile.capabilityTier, equals(CapabilityTier.modern));
      expect(profile.metadata.deviceModel, equals('Pixel 8 Pro'));

      // Check remote cloud store received profile
      final remote = await fakeCloud.fetchDeviceProfile(profile.deviceId);
      expect(remote, isNotNull);
      expect(remote!.deviceId, equals(profile.deviceId));

      // Subsequent call uses cache
      final cachedProfile = await repository.getOrCreateDeviceProfile(syncToCloud: false);
      expect(identical(profile, cachedProfile), isTrue);
    });

    test('updateTamperFlags updates state and syncs to cloud', () async {
      final profile = await repository.getOrCreateDeviceProfile();

      await repository.updateTamperFlags({'rootDetected': true});

      final updatedRemote = await fakeCloud.fetchDeviceProfile(profile.deviceId);
      expect(updatedRemote, isNotNull);
      expect(updatedRemote!.tamperFlags['rootDetected'], isTrue);
    });

    test('updateTrackingStatus updates state and syncs to cloud', () async {
      final profile = await repository.getOrCreateDeviceProfile();

      await repository.updateTrackingStatus({'trackingEnabled': true, 'batteryLevel': 85});

      final updatedRemote = await fakeCloud.fetchDeviceProfile(profile.deviceId);
      expect(updatedRemote, isNotNull);
      expect(updatedRemote!.trackingStatus['trackingEnabled'], isTrue);
      expect(updatedRemote.trackingStatus['batteryLevel'], equals(85));
    });

    test('offline buffering and flushing through repository', () async {
      fakeCloud.isOnline = false;

      final profile = await repository.getOrCreateDeviceProfile();
      expect(await repository.getOfflineQueuedCount(), equals(1));

      // Remote has not received it yet
      expect(await fakeCloud.fetchDeviceProfile(profile.deviceId), isNull);

      // Connect online and flush
      fakeCloud.isOnline = true;
      await repository.flushOfflineQueue();

      expect(await repository.getOfflineQueuedCount(), equals(0));
      expect(await fakeCloud.fetchDeviceProfile(profile.deviceId), isNotNull);
    });
  });

  group('Service Locator DI Configuration', () {
    tearDown(() async {
      await resetServiceLocator();
    });

    test('setupServiceLocator registers in-memory fakes when useFakes is true', () async {
      await setupServiceLocator(useFakes: true);

      expect(sl.isRegistered<ISecureStorageService>(), isTrue);
      expect(sl.isRegistered<IDeviceIdentityService>(), isTrue);
      expect(sl.isRegistered<ICloudProfileService>(), isTrue);
      expect(sl.isRegistered<DeviceRepository>(), isTrue);

      final repo = sl<DeviceRepository>();
      final profile = await repo.getOrCreateDeviceProfile();
      expect(profile.deviceId, isNotEmpty);
      expect(profile.capabilityTier, equals(CapabilityTier.modern));
    });
  });
}
