import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:security_suite/core/di/service_locator.dart';
import 'package:security_suite/data/repositories/background_security_repository.dart';
import 'package:security_suite/data/repositories/device_repository.dart';
import 'package:security_suite/ui/viewmodels/threat_scanner_viewmodel.dart';
import 'package:security_suite/ui/views/threat_scanner_view.dart';

void main() {
  late BackgroundSecurityRepository backgroundRepo;
  late DeviceRepository deviceRepo;
  late ThreatScannerViewModel viewModel;

  setUp(() async {
    await setupServiceLocator(useFakes: true);

    backgroundRepo = sl<BackgroundSecurityRepository>();
    deviceRepo = sl<DeviceRepository>();

    viewModel = ThreatScannerViewModel(
      backgroundSecurityRepository: backgroundRepo,
      deviceRepository: deviceRepo,
    );
  });

  tearDown(() async {
    viewModel.dispose();
    await resetServiceLocator();
  });

  Widget buildTestableWidget() {
    return MaterialApp(
      home: ThreatScannerView(viewModel: viewModel),
    );
  }

  group('ThreatScannerView Widget Tests', () {
    testWidgets('renders capability tier badge and scan trigger button', (tester) async {
      await tester.pumpWidget(buildTestableWidget());
      await tester.pumpAndSettle();

      expect(find.text('Adaptive Threat Scanner'), findsOneWidget);
      expect(find.byKey(const Key('capability_tier_badge')), findsOneWidget);
      expect(find.byKey(const Key('trigger_scan_button')), findsOneWidget);
    });

    testWidgets('tapping scan button dispatches scan and renders scan report card',
        (tester) async {
      await tester.pumpWidget(buildTestableWidget());
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('trigger_scan_button')));
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('scan_report_card')), findsOneWidget);
      expect(viewModel.latestReport, isNotNull);
    });
  });
}
