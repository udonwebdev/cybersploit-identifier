import 'dart:async';
import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:security_suite/core/di/service_locator.dart';
import 'package:security_suite/data/models/security_trigger_event.dart';
import 'package:security_suite/data/models/threat_report.dart';
import 'package:security_suite/data/repositories/background_security_repository.dart';
import 'package:security_suite/data/repositories/device_repository.dart';
import 'package:security_suite/data/services/contracts/i_background_trigger_service.dart';
import 'package:security_suite/data/services/contracts/i_location_platform_service.dart';
import 'package:security_suite/data/services/contracts/i_threat_scanner_service.dart';
import 'package:security_suite/data/services/fakes/fake_background_trigger_service.dart';
import 'package:security_suite/data/services/fakes/fake_cloud_profile_service.dart';
import 'package:security_suite/data/services/fakes/fake_device_identity_service.dart';
import 'package:security_suite/data/services/fakes/fake_location_platform_service.dart';
import 'package:security_suite/data/services/fakes/fake_secure_storage_service.dart';
import 'package:security_suite/data/services/fakes/fake_threat_scanner_service.dart';
import 'package:security_suite/data/services/implementations/adaptive_threat_scanner_service.dart';
import 'package:security_suite/data/services/implementations/event_driven_background_service.dart';
import 'package:security_suite/data/services/implementations/location_platform_service.dart';

void main() {
  group('SecurityTriggerEvent Model & Serialization Tests', () {
    test('constructs SecurityTriggerEvent with default UUID and false suspicious', () {
      final now = DateTime.now();
      final event = SecurityTriggerEvent(
        type: TriggerEventType.networkHandoff,
        timestamp: now,
        payload: {'network': 'wifi'},
      );

      expect(event.triggerId, isNotEmpty);
      expect(event.type, equals(TriggerEventType.networkHandoff));
      expect(event.timestamp, equals(now));
      expect(event.payload['network'], equals('wifi'));
      expect(event.isSuspicious, isFalse);
    });

    test('serializes and deserializes SecurityTriggerEvent correctly roundtrip', () {
      final now = DateTime.parse('2026-09-27T01:00:00.000Z');
      final event = SecurityTriggerEvent(
        triggerId: 'custom-trig-123',
        type: TriggerEventType.powerState,
        timestamp: now,
        payload: {'battery': 12, 'source': 'battery'},
        isSuspicious: true,
      );

      final jsonStr = event.toJson();
      final reconstituted = SecurityTriggerEvent.fromJson(jsonStr);

      expect(reconstituted.triggerId, equals('custom-trig-123'));
      expect(reconstituted.type, equals(TriggerEventType.powerState));
      expect(reconstituted.timestamp, equals(now));
      expect(reconstituted.payload['battery'], equals(12));
      expect(reconstituted.isSuspicious, isTrue);
      expect(reconstituted, equals(event));
    });

    test('copyWith produces correct modified copy', () {
      final event = SecurityTriggerEvent(
        type: TriggerEventType.scheduledJob,
        timestamp: DateTime.now(),
        isSuspicious: false,
      );

      final modified = event.copyWith(isSuspicious: true);
      expect(modified.isSuspicious, isTrue);
      expect(modified.type, equals(TriggerEventType.scheduledJob));
      expect(modified.triggerId, equals(event.triggerId));
    });
  });

  group('LocationSnapshot & Location Platform Services Tests', () {
    test('LocationSnapshot serialization roundtrip', () {
      final now = DateTime.now();
      final snapshot = LocationSnapshot(
        latitude: 37.7749,
        longitude: -122.4194,
        accuracy: 5.0,
        timestamp: now,
        isMockLocation: true,
      );

      final map = snapshot.toMap();
      final fromMap = LocationSnapshot.fromMap(map);

      expect(fromMap.latitude, equals(37.7749));
      expect(fromMap.longitude, equals(-122.4194));
      expect(fromMap.accuracy, equals(5.0));
      expect(fromMap.isMockLocation, isTrue);
      expect(fromMap, equals(snapshot));
    });

    test('FakeLocationPlatformService emits significant location changes', () async {
      final fakeLocation = FakeLocationPlatformService();
      final received = <LocationSnapshot>[];
      final sub = fakeLocation.significantLocationStream.listen(received.add);

      expect(await fakeLocation.requestLocationPermission(), isTrue);
      expect(await fakeLocation.isLocationTrackingEnabled(), isTrue);

      final snap1 = LocationSnapshot(
        latitude: 40.7128,
        longitude: -74.0060,
        accuracy: 10.0,
        timestamp: DateTime.now(),
      );
      fakeLocation.emitLocation(snap1);

      await Future<void>.delayed(Duration.zero);
      expect(received.length, equals(1));
      expect(received.first.latitude, equals(40.7128));
      expect(await fakeLocation.getCurrentLocationSnapshot(), equals(snap1));

      fakeLocation.setPermission(false);
      expect(await fakeLocation.isLocationTrackingEnabled(), isFalse);

      await sub.cancel();
      fakeLocation.dispose();
    });

    test('Production LocationPlatformService handles permission and callback stream', () async {
      final locationService = LocationPlatformService();
      expect(await locationService.isLocationTrackingEnabled(), isFalse);

      await locationService.requestLocationPermission();
      locationService.setTrackingEnabled(true);
      expect(await locationService.isLocationTrackingEnabled(), isTrue);

      final received = <LocationSnapshot>[];
      final sub = locationService.significantLocationStream.listen(received.add);

      final snap = LocationSnapshot(
        latitude: 51.5074,
        longitude: -0.1278,
        accuracy: 8.0,
        timestamp: DateTime.now(),
      );

      locationService.onSignificantLocationReceived(snap);
      await Future<void>.delayed(Duration.zero);

      expect(received.length, equals(1));
      expect(received.first, equals(snap));
      expect(await locationService.getCurrentLocationSnapshot(), equals(snap));

      await sub.cancel();
      locationService.dispose();
    });
  });

  group('EventDrivenBackgroundService (Zero Polling, Reactive Triggers)', () {
    late StreamController<List<ConnectivityResult>> connectivityController;
    late FakeLocationPlatformService fakeLocation;
    late EventDrivenBackgroundService backgroundService;

    setUp(() {
      connectivityController = StreamController<List<ConnectivityResult>>.broadcast();
      fakeLocation = FakeLocationPlatformService();
      backgroundService = EventDrivenBackgroundService(
        customConnectivityStream: connectivityController.stream,
        locationService: fakeLocation,
        networkDebounceDuration: const Duration(milliseconds: 50),
      );
    });

    tearDown(() async {
      backgroundService.dispose();
      await connectivityController.close();
      fakeLocation.dispose();
    });

    test('strictly does NOT emit events when unregistered', () async {
      final events = <SecurityTriggerEvent>[];
      final sub = backgroundService.triggerStream.listen(events.add);

      backgroundService.emitPowerState(source: 'battery', batteryPercent: 90);
      connectivityController.add([ConnectivityResult.wifi]);
      fakeLocation.emitLocation(LocationSnapshot(
        latitude: 0,
        longitude: 0,
        accuracy: 1,
        timestamp: DateTime.now(),
      ));

      await Future<void>.delayed(const Duration(milliseconds: 80));
      expect(events, isEmpty);

      await sub.cancel();
    });

    test('registers triggers and reactively receives debounced network events', () async {
      await backgroundService.registerEventTriggers();
      expect(backgroundService.isRegistered, isTrue);

      final events = <SecurityTriggerEvent>[];
      final sub = backgroundService.triggerStream.listen(events.add);

      // Rapid flapping: 3 updates in 10ms
      connectivityController.add([ConnectivityResult.wifi]);
      connectivityController.add([ConnectivityResult.mobile]);
      connectivityController.add([ConnectivityResult.wifi]);

      // Debounce window is 50ms, so before 50ms no event
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(events, isEmpty);

      // After 60ms, exactly 1 debounced event arrives
      await Future<void>.delayed(const Duration(milliseconds: 60));
      expect(events.length, equals(1));
      expect(events.first.type, equals(TriggerEventType.networkHandoff));
      expect(events.first.payload['connectivityResults'], contains('wifi'));

      await sub.cancel();
    });

    test('flags suspicious network event when transitioning to offline (none)', () async {
      await backgroundService.registerEventTriggers();
      final events = <SecurityTriggerEvent>[];
      final sub = backgroundService.triggerStream.listen(events.add);

      backgroundService.emitNetworkHandoff([ConnectivityResult.none], immediate: true);

      await Future<void>.delayed(Duration.zero);
      expect(events.length, equals(1));
      expect(events.first.type, equals(TriggerEventType.networkHandoff));
      expect(events.first.isSuspicious, isTrue);
      expect(events.first.payload['isOffline'], isTrue);

      await sub.cancel();
    });

    test('reactively emits location changes from location platform service', () async {
      await backgroundService.registerEventTriggers();
      final events = <SecurityTriggerEvent>[];
      final sub = backgroundService.triggerStream.listen(events.add);

      fakeLocation.emitLocation(LocationSnapshot(
        latitude: 34.0522,
        longitude: -118.2437,
        accuracy: 12.0,
        timestamp: DateTime.now(),
        isMockLocation: true,
      ));

      await Future<void>.delayed(Duration.zero);
      expect(events.length, equals(1));
      expect(events.first.type, equals(TriggerEventType.significantLocation));
      // Mock location is flagged as suspicious
      expect(events.first.isSuspicious, isTrue);
      expect(events.first.payload['latitude'], equals(34.0522));

      await sub.cancel();
    });

    test('evaluates power change and flags critical low battery (<15%) on battery power as suspicious', () async {
      await backgroundService.registerEventTriggers();
      final events = <SecurityTriggerEvent>[];
      final sub = backgroundService.triggerStream.listen(events.add);

      // Normal battery percent: not suspicious
      backgroundService.emitPowerState(source: 'battery', batteryPercent: 60);
      await Future<void>.delayed(Duration.zero);
      expect(events.last.isSuspicious, isFalse);

      // Low battery on battery power: suspicious (potential emergency beacon needed)
      backgroundService.emitPowerState(source: 'battery', batteryPercent: 10);
      await Future<void>.delayed(Duration.zero);
      expect(events.last.isSuspicious, isTrue);
      expect(events.last.payload['batteryPercent'], equals(10));

      // Low battery on AC charging: not suspicious
      backgroundService.emitPowerState(source: 'ac_charging', batteryPercent: 10);
      await Future<void>.delayed(Duration.zero);
      expect(events.last.isSuspicious, isFalse);

      await sub.cancel();
    });

    test('emits scheduled background job triggers and executes security checks without sleeping loops', () async {
      await backgroundService.registerEventTriggers();
      final events = <SecurityTriggerEvent>[];
      final sub = backgroundService.triggerStream.listen(events.add);

      backgroundService.emitScheduledJob(
        'periodic_integrity_job',
        payload: {'source': 'WorkManager', 'expedited': true},
        isSuspicious: false,
      );

      await Future<void>.delayed(Duration.zero);
      expect(events.length, equals(1));
      expect(events.first.type, equals(TriggerEventType.scheduledJob));
      expect(events.first.payload['jobId'], equals('periodic_integrity_job'));

      // Execute security check directly
      await backgroundService.executeSecurityCheck(events.first);
      expect(backgroundService.executedChecks.length, equals(1));
      expect(backgroundService.executedChecks.first, equals(events.first));

      await sub.cancel();
    });
  });

  group('BackgroundSecurityRepository Integration Tests', () {
    late FakeBackgroundTriggerService fakeTrigger;
    late FakeThreatScannerService fakeScanner;
    late FakeLocationPlatformService fakeLocation;
    late DeviceRepository deviceRepo;
    late FakeSecureStorageService fakeStorage;
    late FakeCloudProfileService fakeCloud;
    late FakeDeviceIdentityService fakeIdentity;
    late BackgroundSecurityRepository backgroundRepo;

    setUp(() {
      fakeTrigger = FakeBackgroundTriggerService();
      fakeScanner = FakeThreatScannerService();
      fakeLocation = FakeLocationPlatformService();
      fakeStorage = FakeSecureStorageService();
      fakeCloud = FakeCloudProfileService();
      fakeIdentity = FakeDeviceIdentityService(storageService: fakeStorage);
      deviceRepo = DeviceRepository(
        identityService: fakeIdentity,
        cloudProfileService: fakeCloud,
        storageService: fakeStorage,
      );

      backgroundRepo = BackgroundSecurityRepository(
        triggerService: fakeTrigger,
        threatScannerService: fakeScanner,
        locationService: fakeLocation,
        deviceRepository: deviceRepo,
      );
    });

    tearDown(() {
      backgroundRepo.dispose();
      fakeTrigger.dispose();
      fakeLocation.dispose();
    });

    test('startBackgroundMonitoring registers triggers and handles incoming events', () async {
      expect(backgroundRepo.isMonitoringActive, isFalse);
      expect(fakeTrigger.isRegistered, isFalse);

      await backgroundRepo.startBackgroundMonitoring();
      expect(backgroundRepo.isMonitoringActive, isTrue);
      expect(fakeTrigger.isRegistered, isTrue);

      final event = SecurityTriggerEvent(
        type: TriggerEventType.networkHandoff,
        timestamp: DateTime.now(),
        isSuspicious: false,
      );

      fakeTrigger.emitTrigger(event);
      await Future<void>.delayed(Duration.zero);

      expect(backgroundRepo.eventHistory.length, equals(1));
      expect(backgroundRepo.eventHistory.first, equals(event));
    });

    test('automatically dispatches threat scan and security check upon suspicious trigger event', () async {
      await backgroundRepo.startBackgroundMonitoring();

      final reports = <ThreatReport>[];
      final sub = backgroundRepo.threatReportStream.listen(reports.add);

      // Register malware in fake scanner
      fakeScanner.addKnownSignature('fake_sha', 'Test.Trojan');
      fakeScanner.registerSimulatedTarget(const SimulatedScanTarget(
        identifier: 'com.malicious.app',
        sha256: 'fake_sha',
      ));

      final suspiciousEvent = SecurityTriggerEvent(
        type: TriggerEventType.powerState,
        timestamp: DateTime.now(),
        payload: {'battery': 5, 'source': 'battery'},
        isSuspicious: true,
      );

      fakeTrigger.emitTrigger(suspiciousEvent);
      await Future<void>.delayed(const Duration(milliseconds: 50));

      // Security check executed
      expect(fakeTrigger.executedChecks.length, equals(1));
      expect(fakeTrigger.executedChecks.first, equals(suspiciousEvent));

      // Threat scan was dispatched automatically
      expect(reports.length, equals(1));
      expect(reports.first.threatsFound, equals(1));
      expect(backgroundRepo.latestThreatReport, equals(reports.first));

      await sub.cancel();
    });

    test('syncs location coordinates with DeviceRepository on significant location event', () async {
      await backgroundRepo.startBackgroundMonitoring();

      final locEvent = SecurityTriggerEvent(
        type: TriggerEventType.significantLocation,
        timestamp: DateTime.now(),
        payload: {
          'latitude': 37.7749,
          'longitude': -122.4194,
          'accuracy': 5.0,
        },
        isSuspicious: false,
      );

      fakeTrigger.emitTrigger(locEvent);
      await Future<void>.delayed(const Duration(milliseconds: 50));

      final profile = await deviceRepo.getOrCreateDeviceProfile(syncToCloud: false);
      expect(profile.trackingStatus['lastKnownCoordinates'], isNotNull);
      expect(
        profile.trackingStatus['lastKnownCoordinates']['lat'],
        equals(37.7749),
      );
    });

    test('caps eventHistory to 100 entries to prevent unbounded memory growth', () async {
      await backgroundRepo.startBackgroundMonitoring();

      for (int i = 0; i < 110; i++) {
        fakeTrigger.emitTrigger(SecurityTriggerEvent(
          type: TriggerEventType.scheduledJob,
          timestamp: DateTime.now(),
          payload: {'index': i},
          isSuspicious: false,
        ));
      }

      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(backgroundRepo.eventHistory.length, equals(100));
      // First 10 dropped; oldest should be index 10
      expect(backgroundRepo.eventHistory.first.payload['index'], equals(10));
      expect(backgroundRepo.eventHistory.last.payload['index'], equals(109));
    });

    test('stopBackgroundMonitoring unregisters triggers and stops event stream', () async {
      await backgroundRepo.startBackgroundMonitoring();
      expect(fakeTrigger.isRegistered, isTrue);

      await backgroundRepo.stopBackgroundMonitoring();
      expect(backgroundRepo.isMonitoringActive, isFalse);
      expect(fakeTrigger.isRegistered, isFalse);

      fakeTrigger.emitTrigger(SecurityTriggerEvent(
        type: TriggerEventType.networkHandoff,
        timestamp: DateTime.now(),
      ));

      await Future<void>.delayed(Duration.zero);
      expect(backgroundRepo.eventHistory, isEmpty);
    });
  });

  group('Service Locator M3 Registration Tests', () {
    tearDown(() async {
      await resetServiceLocator();
    });

    test('setupServiceLocator registers fakes correctly when useFakes is true', () async {
      await setupServiceLocator(useFakes: true);

      expect(sl<IBackgroundTriggerService>(), isA<FakeBackgroundTriggerService>());
      expect(sl<ILocationPlatformService>(), isA<FakeLocationPlatformService>());
      expect(sl<IThreatScannerService>(), isA<FakeThreatScannerService>());
      expect(sl<BackgroundSecurityRepository>(), isA<BackgroundSecurityRepository>());
    });

    test('setupServiceLocator registers production services when useFakes is false', () async {
      await setupServiceLocator(useFakes: false);

      expect(sl<IBackgroundTriggerService>(), isA<EventDrivenBackgroundService>());
      expect(sl<ILocationPlatformService>(), isA<LocationPlatformService>());
      expect(sl<IThreatScannerService>(), isA<AdaptiveThreatScannerService>());
      expect(sl<BackgroundSecurityRepository>(), isA<BackgroundSecurityRepository>());
    });
  });
}
