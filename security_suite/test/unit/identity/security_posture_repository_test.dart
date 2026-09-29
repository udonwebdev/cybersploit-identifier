import 'package:flutter_test/flutter_test.dart';
import 'package:security_suite/core/di/service_locator.dart';
import 'package:security_suite/data/models/security_posture.dart';
import 'package:security_suite/data/repositories/background_security_repository.dart';
import 'package:security_suite/data/repositories/device_repository.dart';
import 'package:security_suite/data/repositories/security_posture_repository.dart';
import 'package:security_suite/data/services/contracts/i_biometric_auth_service.dart';
import 'package:security_suite/data/services/contracts/i_location_platform_service.dart';
import 'package:security_suite/data/services/fakes/fake_biometric_auth_service.dart';
import 'package:security_suite/data/services/fakes/fake_location_platform_service.dart';

void main() {
  late DeviceRepository deviceRepo;
  late BackgroundSecurityRepository backgroundRepo;
  late FakeBiometricAuthService fakeBiometricService;
  late FakeLocationPlatformService fakeLocationService;
  late SecurityPostureRepository postureRepo;

  setUp(() async {
    fakeBiometricService = FakeBiometricAuthService(
      isHardwareAvailable: true,
      isEnrolled: true,
      shouldSucceed: true,
      availableTypes: [BiometricType.fingerprint],
    );

    fakeLocationService = FakeLocationPlatformService();
    fakeLocationService.setTrackingEnabled(true);

    await setupServiceLocator(
      useFakes: true,
      customBiometricService: fakeBiometricService,
      customLocationService: fakeLocationService,
    );

    deviceRepo = sl<DeviceRepository>();
    backgroundRepo = sl<BackgroundSecurityRepository>();

    postureRepo = SecurityPostureRepository(
      deviceRepository: deviceRepo,
      backgroundSecurityRepository: backgroundRepo,
      biometricService: fakeBiometricService,
      locationService: fakeLocationService,
    );
  });

  tearDown(() async {
    postureRepo.dispose();
    await resetServiceLocator();
  });

  group('SecurityPostureRepository Evaluation & Gatekeeping', () {
    test('gatekeeping: setLocationTrackingEnabled refuses when not biometrically authenticated', () async {
      final success = await postureRepo.setLocationTrackingEnabled(
        enabled: true,
        isBiometricallyAuthenticated: false,
      );

      expect(success, isFalse);
      expect(postureRepo.posture.value.isTrackingActive, isFalse);
    });

    test('gatekeeping: setLocationTrackingEnabled applies and starts monitoring when authenticated', () async {
      final success = await postureRepo.setLocationTrackingEnabled(
        enabled: true,
        isBiometricallyAuthenticated: true,
      );

      expect(success, isTrue);
      expect(postureRepo.posture.value.isTrackingActive, isTrue);
      expect(backgroundRepo.isMonitoringActive, isTrue);
    });

    test('evaluates posture as High when tracking, biometrics, and permissions are all active', () async {
      await postureRepo.setLocationTrackingEnabled(
        enabled: true,
        isBiometricallyAuthenticated: true,
      );

      expect(postureRepo.posture.value.overallPosture, equals(SecurityLevel.high));
      expect(postureRepo.posture.value.statusSummary, contains('All shields active'));
    });

    test('evaluates posture as Degraded when tracking is disabled', () async {
      await postureRepo.setLocationTrackingEnabled(
        enabled: false,
        isBiometricallyAuthenticated: true,
      );

      expect(postureRepo.posture.value.overallPosture, equals(SecurityLevel.degraded));
      expect(postureRepo.posture.value.statusSummary, contains('Tracking disabled'));
    });

    test('evaluates posture as Critical when root or tamper is detected', () async {
      await postureRepo.setLocationTrackingEnabled(
        enabled: true,
        isBiometricallyAuthenticated: true,
      );

      // Tamper device flags
      await deviceRepo.updateTamperFlags({'rootDetected': true});
      await postureRepo.refreshPosture();

      expect(postureRepo.posture.value.overallPosture, equals(SecurityLevel.critical));
      expect(postureRepo.posture.value.isTamperDetected, isTrue);
    });

    test('evaluates posture as Critical when mock location is emitted', () async {
      await postureRepo.setLocationTrackingEnabled(
        enabled: true,
        isBiometricallyAuthenticated: true,
      );

      // Emit mock location
      fakeLocationService.emitLocation(
        LocationSnapshot(
          latitude: 37.422,
          longitude: -122.084,
          accuracy: 5.0,
          timestamp: DateTime.now(),
          isMockLocation: true,
        ),
      );

      await Future<void>.delayed(const Duration(milliseconds: 50));

      expect(postureRepo.posture.value.overallPosture, equals(SecurityLevel.critical));
      expect(postureRepo.posture.value.statusSummary, contains('Mock location'));
    });

    test('postureStream emits events whenever posture changes', () async {
      final emittedStates = <SecurityPostureState>[];
      final sub = postureRepo.postureStream.listen(emittedStates.add);

      await postureRepo.setLocationTrackingEnabled(
        enabled: true,
        isBiometricallyAuthenticated: true,
      );

      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(emittedStates, isNotEmpty);
      expect(emittedStates.last.isTrackingActive, isTrue);

      await sub.cancel();
    });
  });
}
