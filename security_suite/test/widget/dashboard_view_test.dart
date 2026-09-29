import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:security_suite/core/di/service_locator.dart';
import 'package:security_suite/data/repositories/background_security_repository.dart';
import 'package:security_suite/data/repositories/security_posture_repository.dart';
import 'package:security_suite/data/services/contracts/i_biometric_auth_service.dart';
import 'package:security_suite/data/services/fakes/fake_biometric_auth_service.dart';
import 'package:security_suite/ui/viewmodels/dashboard_viewmodel.dart';
import 'package:security_suite/ui/views/dashboard_view.dart';

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

  Widget buildTestableWidget() {
    return MaterialApp(
      home: DashboardView(viewModel: viewModel),
    );
  }

  group('DashboardView Widget Tests', () {
    testWidgets('renders posture badge, summary card, and tracking switch', (tester) async {
      await tester.pumpWidget(buildTestableWidget());
      await tester.pumpAndSettle();

      expect(find.text('Security Posture'), findsOneWidget);
      expect(find.byKey(const Key('posture_badge')), findsOneWidget);
      expect(find.byKey(const Key('posture_summary_text')), findsOneWidget);
      expect(find.byKey(const Key('tracking_switch_tile')), findsOneWidget);
    });

    testWidgets('toggling tracking switch triggers biometric challenge and enables tracking on success',
        (tester) async {
      fakeBiometricService.shouldSucceed = true;

      await tester.pumpWidget(buildTestableWidget());
      await tester.pumpAndSettle();

      // Tap tracking switch
      await tester.tap(find.byKey(const Key('tracking_switch_tile')));
      await tester.pump();

      await tester.runAsync(() async {
        await Future.delayed(const Duration(milliseconds: 200));
      });
      await tester.pumpAndSettle();

      // Verify tracking became active
      expect(viewModel.postureState.isTrackingActive, isTrue);
      expect(find.byKey(const Key('dashboard_error_banner')), findsNothing);
    });

    testWidgets('toggling tracking switch displays error banner when authentication is cancelled or fails',
        (tester) async {
      fakeBiometricService.shouldSucceed = false;

      await tester.pumpWidget(buildTestableWidget());
      await tester.pumpAndSettle();

      // Tap tracking switch
      await tester.tap(find.byKey(const Key('tracking_switch_tile')));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 200));
      await tester.pump(const Duration(milliseconds: 200));

      // Verify tracking remained inactive and error banner appeared
      expect(viewModel.postureState.isTrackingActive, isFalse);
      expect(find.byKey(const Key('dashboard_error_banner')), findsOneWidget);
    });

    testWidgets('refresh button triggers posture refresh', (tester) async {
      await tester.pumpWidget(buildTestableWidget());
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('dashboard_refresh_button')));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 200));
      await tester.pump(const Duration(milliseconds: 200));

      expect(viewModel.postureState.lastEvaluatedAt, isNotNull);
    });
  });
}
