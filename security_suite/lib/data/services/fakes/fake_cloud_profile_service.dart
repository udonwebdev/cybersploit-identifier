import 'dart:async';
import '../../models/device_profile.dart';
import '../contracts/i_cloud_profile_service.dart';

/// In-memory fake implementation of [ICloudProfileService] for headless CI testing.
class FakeCloudProfileService implements ICloudProfileService {
  final Map<String, DeviceProfile> _remoteStore = {};
  final List<DeviceProfile> _offlineQueue = [];
  final StreamController<SyncStatus> _statusController =
      StreamController<SyncStatus>.broadcast();

  bool isOnline = true;
  bool simulateFailure = false;

  FakeCloudProfileService({this.isOnline = true});

  @override
  Stream<SyncStatus> get syncStatusStream => _statusController.stream;

  @override
  Future<void> syncDeviceProfile(DeviceProfile profile) async {
    _statusController.add(SyncStatus.syncing);

    if (!isOnline || simulateFailure) {
      _offlineQueue.add(profile);
      _statusController.add(SyncStatus.offlineQueued);
      return;
    }

    _remoteStore[profile.deviceId] = profile;
    _statusController.add(SyncStatus.synced);
  }

  @override
  Future<DeviceProfile?> fetchDeviceProfile(String deviceId) async {
    return _remoteStore[deviceId];
  }

  @override
  Future<int> getQueuedCount() async {
    return _offlineQueue.length;
  }

  @override
  Future<void> flushOfflineQueue() async {
    if (!isOnline || simulateFailure) {
      return;
    }

    if (_offlineQueue.isEmpty) {
      _statusController.add(SyncStatus.synced);
      return;
    }

    _statusController.add(SyncStatus.syncing);
    while (_offlineQueue.isNotEmpty) {
      final profile = _offlineQueue.removeAt(0);
      _remoteStore[profile.deviceId] = profile;
    }
    _statusController.add(SyncStatus.synced);
  }

  void dispose() {
    _statusController.close();
  }
}
