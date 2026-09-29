import 'package:flutter_test/flutter_test.dart';
import 'package:security_suite/core/di/service_locator.dart';
import 'package:security_suite/data/models/device_profile.dart';
import 'package:security_suite/data/repositories/background_security_repository.dart';
import 'package:security_suite/data/repositories/device_repository.dart';
import 'package:security_suite/ui/viewmodels/threat_scanner_viewmodel.dart';

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

  group('ThreatScannerViewModel Unit Tests', () {
    test('initializes with idle scan status and device capability tier', () async {
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(viewModel.isScanning, isFalse);
      expect(viewModel.errorMessage, isNull);
      expect(viewModel.currentTier, isNotNull);
    });

    test('triggerScan dispatches scan and updates latestReport', () async {
      final report = await viewModel.triggerScan();

      expect(report, isNotNull);
      expect(viewModel.isScanning, isFalse);
      expect(viewModel.latestReport, equals(report));
      expect(report.totalScanned, greaterThanOrEqualTo(0));
    });

    test('notifies listeners when background threat scan report is emitted', () async {
      int notifyCount = 0;
      viewModel.addListener(() => notifyCount++);

      // Dispatch scan directly through repository to simulate background engine
      final report = await backgroundRepo.dispatchThreatScan(overrideTier: CapabilityTier.modern);
      await Future<void>.delayed(const Duration(milliseconds: 10));

      expect(notifyCount, greaterThan(0));
      expect(viewModel.latestReport, equals(report));
    });

    test('notifies listeners during scan start and finish', () async {
      final states = <bool>[];
      viewModel.addListener(() {
        states.add(viewModel.isScanning);
      });

      await viewModel.triggerScan();

      // Should transition from scanning true to scanning false
      expect(states, contains(true));
      expect(states.last, isFalse);
    });
  });
}
