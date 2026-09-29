import '../models/device_profile.dart';
import '../services/contracts/i_cloud_profile_service.dart';
import '../services/contracts/i_device_identity_service.dart';
import '../services/contracts/i_secure_storage_service.dart';

/// Repository for orchestrating device identity, system metadata aggregation,
/// capability tier evaluation, and cloud profile synchronization.
class DeviceRepository {
  final IDeviceIdentityService identityService;
  final ICloudProfileService cloudProfileService;
  final ISecureStorageService storageService;

  DeviceProfile? _cachedProfile;
  Future<DeviceProfile>? _pendingProfileFuture;

  DeviceRepository({
    required this.identityService,
    required this.cloudProfileService,
    required this.storageService,
  });

  /// Exposes reactive stream of cloud synchronization events.
  Stream<SyncStatus> get syncStatusStream =>
      cloudProfileService.syncStatusStream;

  /// Gets the cached or freshly provisioned [DeviceProfile].
  /// If [syncToCloud] is true, triggers cloud sync in background or immediately.
  Future<DeviceProfile> getOrCreateDeviceProfile({
    bool syncToCloud = true,
  }) async {
    if (_cachedProfile != null) {
      if (syncToCloud) {
        await cloudProfileService.syncDeviceProfile(_cachedProfile!);
      }
      return _cachedProfile!;
    }

    if (_pendingProfileFuture != null) {
      final profile = await _pendingProfileFuture!;
      if (syncToCloud) {
        await cloudProfileService.syncDeviceProfile(profile);
      }
      return profile;
    }

    final future = _loadOrCreateProfile();
    _pendingProfileFuture = future;

    try {
      final profile = await future;
      if (syncToCloud) {
        await cloudProfileService.syncDeviceProfile(profile);
      }
      return profile;
    } finally {
      _pendingProfileFuture = null;
    }
  }

  Future<DeviceProfile> _loadOrCreateProfile() async {
    final deviceId = await identityService.getOrCreateAppScopedDeviceId();
    final metadata = await identityService.collectDeviceMetadata();
    final tier = identityService.classifyCapabilityTier(metadata);

    final profile = DeviceProfile(
      deviceId: deviceId,
      metadata: metadata,
      capabilityTier: tier,
      lastSeen: DateTime.now(),
      tamperFlags: {
        'rootDetected': false,
        'jailbreakDetected': false,
        'debuggerAttached': false,
      },
      trackingStatus: {
        'trackingEnabled': false,
        'geofenceActive': false,
        'batteryLevel': 100,
      },
      vaultMetadata: {
        'vaultVersion': 1,
        'itemsCount': 0,
      },
    );

    _cachedProfile = profile;
    return profile;
  }

  /// Classifies capability tier directly from device environment.
  Future<CapabilityTier> getCapabilityTier() async {
    if (_cachedProfile != null) {
      return _cachedProfile!.capabilityTier;
    }
    final metadata = await identityService.collectDeviceMetadata();
    return identityService.classifyCapabilityTier(metadata);
  }

  /// Manually synchronizes the current profile to Cloud Firestore.
  Future<void> syncProfile({bool force = false}) async {
    final profile = await getOrCreateDeviceProfile(syncToCloud: false);
    final updated = profile.copyWith(lastSeen: DateTime.now());
    _cachedProfile = updated;
    await cloudProfileService.syncDeviceProfile(updated);
  }

  /// Updates tamper status flags and pushes to cloud store.
  Future<void> updateTamperFlags(Map<String, dynamic> flags) async {
    final current = await getOrCreateDeviceProfile(syncToCloud: false);
    final merged = Map<String, dynamic>.from(current.tamperFlags)..addAll(flags);
    final updated = current.copyWith(
      tamperFlags: merged,
      lastSeen: DateTime.now(),
    );
    _cachedProfile = updated;
    await cloudProfileService.syncDeviceProfile(updated);
  }

  /// Updates tracking state flags and coordinates.
  Future<void> updateTrackingStatus(Map<String, dynamic> status) async {
    final current = await getOrCreateDeviceProfile(syncToCloud: false);
    final merged = Map<String, dynamic>.from(current.trackingStatus)..addAll(status);
    final updated = current.copyWith(
      trackingStatus: merged,
      lastSeen: DateTime.now(),
    );
    _cachedProfile = updated;
    await cloudProfileService.syncDeviceProfile(updated);
  }

  /// Returns count of pending offline documents waiting for network sync.
  Future<int> getOfflineQueuedCount() =>
      cloudProfileService.getQueuedCount();

  /// Flushes pending offline payloads.
  Future<void> flushOfflineQueue() =>
      cloudProfileService.flushOfflineQueue();

  /// Clears internal cache.
  void clearCache() {
    _cachedProfile = null;
    _pendingProfileFuture = null;
  }
}
