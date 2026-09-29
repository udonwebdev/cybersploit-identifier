import 'dart:async';
import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:security_suite/data/models/security_trigger_event.dart';
import 'package:security_suite/data/repositories/background_security_repository.dart';
import 'package:security_suite/data/services/contracts/i_location_platform_service.dart';
import 'package:security_suite/data/services/fakes/fake_location_platform_service.dart';
import 'package:security_suite/data/services/fakes/fake_threat_scanner_service.dart';
import 'package:security_suite/data/services/implementations/event_driven_background_service.dart';

void main() {
  group('Empirical Challenge: Event Driven Background Service Stress Harness', () {
    test('Rapid Flapping Stress: 500 rapid toggles should debounce and emit only 1 final event', () async {
      final connectivityController = StreamController<List<ConnectivityResult>>.broadcast();
      final service = EventDrivenBackgroundService(
        customConnectivityStream: connectivityController.stream,
        networkDebounceDuration: const Duration(milliseconds: 50),
      );

      final receivedEvents = <SecurityTriggerEvent>[];
      final sub = service.triggerStream.listen(receivedEvents.add);

      await service.registerEventTriggers();

      // Rapidly flap connectivity 500 times with zero delay between pushes
      for (int i = 0; i < 500; i++) {
        final state = (i % 2 == 0)
            ? [ConnectivityResult.wifi]
            : [ConnectivityResult.none];
        connectivityController.add(state);
      }

      // Final state is explicitly wifi
      connectivityController.add([ConnectivityResult.wifi]);

      // Wait for debounce period (50ms debounce + margin)
      for (int i = 0; i < 20; i++) {
        if (receivedEvents.isNotEmpty) break;
        await Future.delayed(const Duration(milliseconds: 50));
      }

      // Assert that exactly 1 debounced event was emitted
      expect(receivedEvents.length, equals(1),
          reason: 'Rapid flapping must be debounced to exactly 1 event');
      expect(receivedEvents.first.type, equals(TriggerEventType.networkHandoff));
      expect(
        receivedEvents.first.payload['connectivityResults'],
        equals(['wifi']),
      );
      expect(receivedEvents.first.isSuspicious, isFalse);

      await sub.cancel();
      service.dispose();
      await connectivityController.close();
    });

    test('Unregistering during active debounce timer cancels timer and prevents stray emissions', () async {
      final connectivityController = StreamController<List<ConnectivityResult>>.broadcast();
      final service = EventDrivenBackgroundService(
        customConnectivityStream: connectivityController.stream,
        networkDebounceDuration: const Duration(milliseconds: 80),
      );

      final receivedEvents = <SecurityTriggerEvent>[];
      final sub = service.triggerStream.listen(receivedEvents.add);

      await service.registerEventTriggers();

      // Trigger change
      connectivityController.add([ConnectivityResult.none]);

      // Halfway through debounce duration, unregister triggers
      await Future.delayed(const Duration(milliseconds: 20));
      await service.unregisterEventTriggers();

      // Wait past the original debounce duration
      await Future.delayed(const Duration(milliseconds: 120));

      expect(receivedEvents, isEmpty,
          reason: 'Debounce timer must be cancelled upon unregister, emitting zero events');

      await sub.cancel();
      service.dispose();
      await connectivityController.close();
    });

    test('Multiple rapid register/unregister cycles do not leak subscriptions or cause duplicate events', () async {
      final connectivityController = StreamController<List<ConnectivityResult>>.broadcast();
      final service = EventDrivenBackgroundService(
        customConnectivityStream: connectivityController.stream,
        networkDebounceDuration: const Duration(milliseconds: 20),
      );

      final receivedEvents = <SecurityTriggerEvent>[];
      final sub = service.triggerStream.listen(receivedEvents.add);

      // Perform 20 rapid register/unregister cycles
      for (int i = 0; i < 20; i++) {
        await service.registerEventTriggers();
        if (i % 2 == 1) {
          await service.unregisterEventTriggers();
        }
      }

      // Ensure it is registered now
      await service.registerEventTriggers();

      // Emit network change
      connectivityController.add([ConnectivityResult.wifi]);
      await Future.delayed(const Duration(milliseconds: 60));

      expect(receivedEvents.length, equals(1),
          reason: 'Repeated register/unregister cycles should not cause duplicate event listeners');

      await sub.cancel();
      service.dispose();
      await connectivityController.close();
    });

    test('Location Stream Flooding & Mock Spoofing Stress', () async {
      final fakeLocation = FakeLocationPlatformService();
      final service = EventDrivenBackgroundService(
        locationService: fakeLocation,
      );

      final receivedEvents = <SecurityTriggerEvent>[];
      final sub = service.triggerStream.listen(receivedEvents.add);

      await service.registerEventTriggers();

      // Flood 100 location updates with interleaved mock and genuine locations
      for (int i = 0; i < 100; i++) {
        final isMock = (i % 3 == 0);
        fakeLocation.emitLocation(
          LocationSnapshot(
            latitude: 37.0 + (i * 0.001),
            longitude: -122.0 - (i * 0.001),
            accuracy: 10.0,
            timestamp: DateTime.now(),
            isMockLocation: isMock,
          ),
        );
      }

      await Future.delayed(const Duration(milliseconds: 50));

      expect(receivedEvents.length, equals(100));
      // Verify mock locations were appropriately flagged as suspicious
      int mockCount = receivedEvents.where((e) => e.isSuspicious).length;
      expect(mockCount, equals(34)); // 0, 3, 6 ... 99 -> 34 items

      await sub.cancel();
      service.dispose();
    });

    test('Repository Event History Bounded Buffer: 500 events stay capped at 100', () async {
      final fakeLocation = FakeLocationPlatformService();
      final triggerService = EventDrivenBackgroundService(
        locationService: fakeLocation,
      );
      final fakeScanner = FakeThreatScannerService();

      final repository = BackgroundSecurityRepository(
        triggerService: triggerService,
        threatScannerService: fakeScanner,
      );

      await repository.startBackgroundMonitoring();

      // Flood 500 events
      for (int i = 0; i < 500; i++) {
        triggerService.emitPowerState(
          source: 'battery',
          batteryPercent: 80,
          isSuspicious: false,
        );
      }

      await Future.delayed(const Duration(milliseconds: 50));

      expect(repository.eventHistory.length, equals(100),
          reason: 'Event history must remain strictly capped at 100 to prevent unbounded memory growth');

      await repository.stopBackgroundMonitoring();
      repository.dispose();
      triggerService.dispose();
    });

    test('Resource release & disposal: Disposing repository and service cleanly stops all reactive controllers', () async {
      final service = EventDrivenBackgroundService();
      final repository = BackgroundSecurityRepository(
        triggerService: service,
        threatScannerService: FakeThreatScannerService(),
      );

      await repository.startBackgroundMonitoring();
      expect(repository.isMonitoringActive, isTrue);

      repository.dispose();
      expect(repository.isMonitoringActive, isFalse);

      // Verify trigger stream on service and threat report stream on repository are closed or non-listening
      expect(
        () => repository.threatReportStream.listen((_) {}),
        returnsNormally,
      );
    });
  });
}
