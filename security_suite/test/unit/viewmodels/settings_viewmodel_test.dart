import 'package:flutter_test/flutter_test.dart';
import 'package:security_suite/core/di/service_locator.dart';
import 'package:security_suite/data/repositories/device_repository.dart';
import 'package:security_suite/data/services/fakes/fake_cloud_profile_service.dart';
import 'package:security_suite/ui/viewmodels/settings_viewmodel.dart';

void main() {
  late DeviceRepository deviceRepo;
  late FakeCloudProfileService fakeCloudService;
  late SettingsViewModel viewModel;

  setUp(() async {
    fakeCloudService = FakeCloudProfileService();

    await setupServiceLocator(
      useFakes: true,
      customCloudService: fakeCloudService,
    );

    deviceRepo = sl<DeviceRepository>();
    viewModel = SettingsViewModel(deviceRepository: deviceRepo);
  });

  tearDown(() async {
    viewModel.dispose();
    await resetServiceLocator();
  });

  group('SettingsViewModel Unit Tests', () {
    test('loads device profile and offline queue count upon initialization', () async {
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(viewModel.deviceProfile, isNotNull);
      expect(viewModel.capabilityTier, isNotNull);
      expect(viewModel.offlineQueueCount, 0);
      expect(viewModel.isSyncing, isFalse);
    });

    test('triggerManualSync pushes profile to cloud successfully', () async {
      await viewModel.triggerManualSync();

      expect(viewModel.isSyncing, isFalse);
      expect(viewModel.statusMessage, contains('completed'));
      final fetched = await fakeCloudService.fetchDeviceProfile(viewModel.deviceProfile!.deviceId);
      expect(fetched, isNotNull);
    });

    test('flushOfflineQueue calls repository and updates status', () async {
      // Simulate offline mutations
      fakeCloudService.isOnline = false;
      await deviceRepo.updateTrackingStatus({'trackingEnabled': true});
      await viewModel.refreshProfile();
      expect(viewModel.offlineQueueCount, greaterThan(0));

      // Re-enable network and flush
      fakeCloudService.isOnline = true;
      await viewModel.flushOfflineQueue();

      expect(viewModel.isSyncing, isFalse);
      expect(viewModel.statusMessage, contains('flushed'));
      expect(viewModel.offlineQueueCount, 0);
    });
  });
}
