import '../../models/device_profile.dart';

/// Synchronization status flags for cloud profile provisioning.
enum SyncStatus {
  idle,
  syncing,
  synced,
  offlineQueued,
  failed,
}

/// Contract for securely provisioning and synchronizing device profile data
/// to Cloud Firestore with atomic upsert, offline queueing, and sanitization.
abstract class ICloudProfileService {
  /// Synchronizes the given [profile] to the remote cloud store.
  /// If offline, enqueues the profile for later dispatch.
  Future<void> syncDeviceProfile(DeviceProfile profile);

  /// Fetches a device profile document by [deviceId].
  Future<DeviceProfile?> fetchDeviceProfile(String deviceId);

  /// Stream of synchronization state transitions.
  Stream<SyncStatus> get syncStatusStream;

  /// Returns the number of payloads currently buffered in the offline queue.
  Future<int> getQueuedCount();

  /// Flushes pending offline payloads to the cloud store.
  Future<void> flushOfflineQueue();
}
