import 'package:flutter_test/flutter_test.dart';
import 'package:security_suite/core/di/service_locator.dart';
import 'package:security_suite/data/models/security_trigger_event.dart';
import 'package:security_suite/data/repositories/background_security_repository.dart';
import 'package:security_suite/data/repositories/security_posture_repository.dart';
import 'package:security_suite/data/services/contracts/i_biometric_auth_service.dart';
import 'package:security_suite/data/services/fakes/fake_background_trigger_service.dart';
import 'package:security_suite/data/services/fakes/fake_biometric_auth_service.dart';
import 'package:security_suite/ui/viewmodels/dashboard_viewmodel.dart';

void main() {
  late FakeBiometricAuthService fakeBiometricService;
  late ISecurityPostureRepository postureRepository;
  late BackgroundSecurityRepository backgroundRepo;
  late DashboardViewModel viewModel;

  setUp(() async {
    fakeBiometricService = FakeBiometricAuthService(
      isHardwareAvailable: true,
      isEnrolled: true,
      shouldSucceed: true,
      availableTypes: [BiometricType.fingerprint],
    );

    await setupServiceLocator(
      useFakes: true,
      customBiometricService: fakeBiometricService,
    );

    postureRepository = sl<ISecurityPostureRepository>();
    backgroundRepo = sl<BackgroundSecurityRepository>();

    viewModel = DashboardViewModel(
      postureRepository: postureRepository,
      biometricService: fakeBiometricService,
      backgroundSecurityRepository: backgroundRepo,
    );
  });

  tearDown(() async {
    viewModel.dispose();
    await resetServiceLocator();
  });

  group('DashboardViewModel Unit Tests', () {
    test('initial state reflects security posture and idle processing', () async {
      await postureRepository.refreshPosture();
      expect(viewModel.isProcessing, isFalse);
      expect(viewModel.errorMessage, isNull);
      expect(viewModel.postureState, isNotNull);
      expect(viewModel.recentEvents, isEmpty);
    });

    test('toggleTrackingWithAuth successfully enables tracking when biometrics succeed', () async {
      fakeBiometricService.shouldSucceed = true;

      final result = await viewModel.toggleTrackingWithAuth(desiredState: true);

      expect(result, isTrue);
      expect(viewModel.errorMessage, isNull);
      expect(viewModel.isProcessing, isFalse);
      expect(viewModel.postureState.isTrackingActive, isTrue);
    });

    test('toggleTrackingWithAuth fails and preserves state when biometrics fail', () async {
      fakeBiometricService.shouldSucceed = false;

      final result = await viewModel.toggleTrackingWithAuth(desiredState: true);

      expect(result, isFalse);
      expect(viewModel.errorMessage, isNotNull);
      expect(viewModel.errorMessage, contains('rejected'));
      expect(viewModel.postureState.isTrackingActive, isFalse);
    });

    test('toggleTrackingWithAuth handles biometric lockout gracefully', () async {
      fakeBiometricService.isLockedOut = true;

      final result = await viewModel.toggleTrackingWithAuth(desiredState: true);

      expect(result, isFalse);
      expect(viewModel.errorMessage, contains('locked out'));
      expect(viewModel.postureState.isTrackingActive, isFalse);
    });

    test('refresh invokes posture re-evaluation without error', () async {
      expect(viewModel.isProcessing, isFalse);
      await viewModel.refresh();
      expect(viewModel.isProcessing, isFalse);
      expect(viewModel.errorMessage, isNull);
      expect(viewModel.postureState.lastEvaluatedAt, isNotNull);
    });

    test('notifies listeners when posture updates', () async {
      int notifyCount = 0;
      viewModel.addListener(() => notifyCount++);

      fakeBiometricService.shouldSucceed = true;
      await viewModel.toggleTrackingWithAuth(desiredState: true);

      expect(notifyCount, greaterThan(0));
    });

    test('notifies listeners when background trigger arrives', () async {
      int notifyCount = 0;
      viewModel.addListener(() => notifyCount++);

      await backgroundRepo.startBackgroundMonitoring();
      final fakeTriggerService = backgroundRepo.triggerService as FakeBackgroundTriggerService;
      fakeTriggerService.emitTrigger(
        SecurityTriggerEvent(
          type: TriggerEventType.networkHandoff,
          timestamp: DateTime.now(),
          payload: {'status': 'wifi_connected'},
        ),
      );

      await Future<void>.delayed(const Duration(milliseconds: 10));
      expect(notifyCount, greaterThan(0));
    });
  });
}
