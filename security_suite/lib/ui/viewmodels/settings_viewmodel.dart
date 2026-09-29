import 'dart:async';
import 'package:flutter/foundation.dart';

import '../../data/models/device_profile.dart';
import '../../data/repositories/device_repository.dart';
import '../../data/services/contracts/i_cloud_profile_service.dart';

/// ViewModel for application settings and device profile synchronization.
/// Zero direct UI rendering logic.
class SettingsViewModel extends ChangeNotifier {
  final DeviceRepository deviceRepository;

  DeviceProfile? _deviceProfile;
  int _offlineQueueCount = 0;
  bool _isSyncing = false;
  String? _statusMessage;
  StreamSubscription<SyncStatus>? _syncSubscription;

  SettingsViewModel({required this.deviceRepository}) {
    _init();
  }

  void _init() {
    refreshProfile();

    _syncSubscription = deviceRepository.syncStatusStream.listen((status) {
      if (status == SyncStatus.synced) {
        _statusMessage = 'Profile synced with cloud.';
      } else if (status == SyncStatus.offlineQueued) {
        _statusMessage = 'Device offline. Profile queued for sync.';
      } else if (status == SyncStatus.failed) {
        _statusMessage = 'Cloud synchronization failed.';
      }
      _updateOfflineCount();
    });
  }

  /// Current device profile metadata.
  DeviceProfile? get deviceProfile => _deviceProfile;

  /// Hardware capability tier.
  CapabilityTier get capabilityTier =>
      _deviceProfile?.capabilityTier ?? CapabilityTier.modern;

  /// Number of offline mutations awaiting network transmission.
  int get offlineQueueCount => _offlineQueueCount;

  /// Whether a sync operation is underway.
  bool get isSyncing => _isSyncing;

  /// Status feedback message.
  String? get statusMessage => _statusMessage;

  /// Refreshes device profile and offline queue count.
  Future<void> refreshProfile() async {
    try {
      _deviceProfile =
          await deviceRepository.getOrCreateDeviceProfile(syncToCloud: false);
      _offlineQueueCount = await deviceRepository.getOfflineQueuedCount();
      notifyListeners();
    } catch (e) {
      _statusMessage = 'Failed to load profile: $e';
      notifyListeners();
    }
  }

  Future<void> _updateOfflineCount() async {
    try {
      _offlineQueueCount = await deviceRepository.getOfflineQueuedCount();
      notifyListeners();
    } catch (_) {}
  }

  /// Triggers immediate manual cloud synchronization.
  Future<void> triggerManualSync() async {
    _isSyncing = true;
    _statusMessage = 'Synchronizing profile to cloud...';
    notifyListeners();

    try {
      await deviceRepository.syncProfile(force: true);
      _deviceProfile =
          await deviceRepository.getOrCreateDeviceProfile(syncToCloud: false);
      _offlineQueueCount = await deviceRepository.getOfflineQueuedCount();
      _statusMessage = 'Cloud synchronization completed.';
    } catch (e) {
      _statusMessage = 'Sync failed: $e';
    } finally {
      _isSyncing = false;
      notifyListeners();
    }
  }

  /// Flushes pending offline payloads to Firestore.
  Future<void> flushOfflineQueue() async {
    _isSyncing = true;
    _statusMessage = 'Flushing offline queue...';
    notifyListeners();

    try {
      await deviceRepository.flushOfflineQueue();
      _offlineQueueCount = await deviceRepository.getOfflineQueuedCount();
      _statusMessage = 'Offline queue flushed.';
    } catch (e) {
      _statusMessage = 'Failed to flush queue: $e';
    } finally {
      _isSyncing = false;
      notifyListeners();
    }
  }

  @override
  void dispose() {
    _syncSubscription?.cancel();
    super.dispose();
  }
}
