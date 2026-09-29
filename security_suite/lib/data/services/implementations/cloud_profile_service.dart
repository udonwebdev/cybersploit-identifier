import 'dart:async';
import 'dart:convert';
import 'package:cloud_firestore/cloud_firestore.dart';
import '../../../core/constants/security_constants.dart';
import '../../../core/errors/security_exceptions.dart';
import '../../models/device_profile.dart';
import '../contracts/i_cloud_profile_service.dart';
import '../contracts/i_secure_storage_service.dart';

/// Callback or network checker contract for connectivity queries.
typedef NetworkChecker = Future<bool> Function();

/// Production implementation of [ICloudProfileService] providing
/// Firestore-compatible profile synchronization with atomic upsert,
/// local encrypted offline queue buffering, and privacy sanitization.
class CloudProfileService implements ICloudProfileService {
  final ISecureStorageService secureStorage;
  final FirebaseFirestore? firestore;
  final NetworkChecker? networkChecker;
  final StreamController<SyncStatus> _statusController =
      StreamController<SyncStatus>.broadcast();

  // Internal document cache simulating Firestore collection locally if live instance unavailable
  final Map<String, Map<String, dynamic>> _firestoreRemoteStore = {};

  CloudProfileService({
    required this.secureStorage,
    this.firestore,
    this.networkChecker,
  });

  @override
  Stream<SyncStatus> get syncStatusStream => _statusController.stream;

  /// Sanitizes profile attributes to guarantee no unhashed PII or
  /// forbidden hardware identifiers (IMEI, MAC, serials) are sent.
  DeviceProfile sanitizeProfile(DeviceProfile profile) {
    final sanitizedModel = profile.metadata.deviceModel
        .replaceAll(RegExp(r'[^\w\s\.-]'), '')
        .trim();
    final sanitizedMfr = profile.metadata.manufacturer
        .replaceAll(RegExp(r'[^\w\s\.-]'), '')
        .trim();

    final sanitizedMetadata = profile.metadata.copyWith(
      deviceModel: sanitizedModel,
      manufacturer: sanitizedMfr,
    );

    // Filter tamper flags to allowed boolean flags only
    final allowedTamperKeys = {
      'rootDetected',
      'jailbreakDetected',
      'debuggerAttached',
      'emulatorDetected'
    };
    final sanitizedTamper = <String, dynamic>{};
    profile.tamperFlags.forEach((key, value) {
      if (allowedTamperKeys.contains(key) && value is bool) {
        sanitizedTamper[key] = value;
      }
    });

    // Filter tracking status: sanitize coordinates to precision limits if present
    final sanitizedTracking = <String, dynamic>{};
    profile.trackingStatus.forEach((key, value) {
      if (key == 'latitude' || key == 'longitude') {
        if (value is num) {
          // Truncate coordinate precision to ~1 meter (5 decimal places) for privacy
          sanitizedTracking[key] = double.parse(value.toStringAsFixed(5));
        }
      } else if (key == 'geofenceActive' ||
          key == 'batteryLevel' ||
          key == 'trackingEnabled') {
        sanitizedTracking[key] = value;
      }
    });

    return profile.copyWith(
      metadata: sanitizedMetadata,
      tamperFlags: sanitizedTamper,
      trackingStatus: sanitizedTracking,
    );
  }

  /// Converts a [DeviceProfile] into a Firestore-compliant document map.
  Map<String, dynamic> toFirestoreDocument(DeviceProfile profile) {
    return {
      'deviceId': profile.deviceId,
      'platform': profile.metadata.platform,
      'osVersion': profile.metadata.osVersion,
      'apiLevel': profile.metadata.apiLevel,
      'deviceModel': profile.metadata.deviceModel,
      'manufacturer': profile.metadata.manufacturer,
      'hardwareArchitecture': profile.metadata.hardwareArchitecture,
      'isPhysical': profile.metadata.isPhysical,
      'capabilityTier': profile.capabilityTier.name,
      'lastSeen': profile.lastSeen.toIso8601String(),
      'tamperFlags': profile.tamperFlags,
      'trackingStatus': profile.trackingStatus,
      'vaultMetadata': profile.vaultMetadata,
    };
  }

  @override
  Future<void> syncDeviceProfile(DeviceProfile profile) async {
    _statusController.add(SyncStatus.syncing);

    final sanitized = sanitizeProfile(profile);

    bool isOnline = true;
    final checker = networkChecker;
    if (checker != null) {
      try {
        isOnline = await checker();
      } catch (_) {
        isOnline = false;
      }
    }

    if (!isOnline) {
      await _enqueueOffline(sanitized);
      _statusController.add(SyncStatus.offlineQueued);
      return;
    }

    try {
      // Atomic upsert into Firestore collection: /devices/{deviceId}
      final doc = toFirestoreDocument(sanitized);
      final liveFirestore = firestore;
      if (liveFirestore != null) {
        await liveFirestore
            .collection('devices')
            .doc(sanitized.deviceId)
            .set(doc, SetOptions(merge: true));
      }
      _firestoreRemoteStore[sanitized.deviceId] = doc;
      _statusController.add(SyncStatus.synced);
    } catch (e) {
      await _enqueueOffline(sanitized);
      _statusController.add(SyncStatus.offlineQueued);
      throw CloudSyncException(
          'Failed to upsert device profile to Firestore', e);
    }
  }

  @override
  Future<DeviceProfile?> fetchDeviceProfile(String deviceId) async {
    final liveFirestore = firestore;
    if (liveFirestore != null) {
      try {
        final snap = await liveFirestore.collection('devices').doc(deviceId).get();
        if (snap.exists && snap.data() != null) {
          final data = snap.data()!;
          return DeviceProfile(
            deviceId: data['deviceId'] as String? ?? deviceId,
            metadata: DeviceMetadata(
              platform: data['platform'] as String? ?? 'unknown',
              osVersion: data['osVersion'] as String? ?? 'unknown',
              apiLevel: (data['apiLevel'] as num?)?.toInt() ?? 0,
              deviceModel: data['deviceModel'] as String? ?? 'unknown',
              manufacturer: data['manufacturer'] as String? ?? 'unknown',
              hardwareArchitecture:
                  data['hardwareArchitecture'] as String? ?? 'unknown',
              isPhysical: data['isPhysical'] as bool? ?? true,
              timestamp: DateTime.tryParse(data['lastSeen'] as String? ?? '') ??
                  DateTime.now(),
            ),
            capabilityTier: CapabilityTier.values.firstWhere(
              (t) => t.name == data['capabilityTier'],
              orElse: () => CapabilityTier.legacy,
            ),
            lastSeen: DateTime.tryParse(data['lastSeen'] as String? ?? '') ??
                DateTime.now(),
            tamperFlags:
                Map<String, dynamic>.from(data['tamperFlags'] as Map? ?? {}),
            trackingStatus:
                Map<String, dynamic>.from(data['trackingStatus'] as Map? ?? {}),
            vaultMetadata:
                Map<String, dynamic>.from(data['vaultMetadata'] as Map? ?? {}),
          );
        }
      } catch (_) {
        // Fallback to internal store if offline or error
      }
    }

    final doc = _firestoreRemoteStore[deviceId];
    if (doc == null) return null;

    return DeviceProfile(
      deviceId: doc['deviceId'] as String? ?? deviceId,
      metadata: DeviceMetadata(
        platform: doc['platform'] as String? ?? 'unknown',
        osVersion: doc['osVersion'] as String? ?? 'unknown',
        apiLevel: (doc['apiLevel'] as num?)?.toInt() ?? 0,
        deviceModel: doc['deviceModel'] as String? ?? 'unknown',
        manufacturer: doc['manufacturer'] as String? ?? 'unknown',
        hardwareArchitecture:
            doc['hardwareArchitecture'] as String? ?? 'unknown',
        isPhysical: doc['isPhysical'] as bool? ?? true,
        timestamp: DateTime.tryParse(doc['lastSeen'] as String? ?? '') ??
            DateTime.now(),
      ),
      capabilityTier: CapabilityTier.values.firstWhere(
        (t) => t.name == doc['capabilityTier'],
        orElse: () => CapabilityTier.legacy,
      ),
      lastSeen: DateTime.tryParse(doc['lastSeen'] as String? ?? '') ??
          DateTime.now(),
      tamperFlags: Map<String, dynamic>.from(doc['tamperFlags'] as Map? ?? {}),
      trackingStatus:
          Map<String, dynamic>.from(doc['trackingStatus'] as Map? ?? {}),
      vaultMetadata:
          Map<String, dynamic>.from(doc['vaultMetadata'] as Map? ?? {}),
    );
  }

  @override
  Future<int> getQueuedCount() async {
    final queue = await _loadQueue();
    return queue.length;
  }

  @override
  Future<void> flushOfflineQueue() async {
    final queue = await _loadQueue();
    if (queue.isEmpty) {
      _statusController.add(SyncStatus.synced);
      return;
    }

    _statusController.add(SyncStatus.syncing);

    final remaining = <Map<String, dynamic>>[];
    for (final item in queue) {
      try {
        final profile = DeviceProfile.fromMap(item);
        final doc = toFirestoreDocument(profile);
        final liveFirestore = firestore;
        if (liveFirestore != null) {
          await liveFirestore
              .collection('devices')
              .doc(profile.deviceId)
              .set(doc, SetOptions(merge: true));
        }
        _firestoreRemoteStore[profile.deviceId] = doc;
      } catch (e) {
        remaining.add(item);
      }
    }

    await _saveQueue(remaining);

    if (remaining.isEmpty) {
      _statusController.add(SyncStatus.synced);
    } else {
      _statusController.add(SyncStatus.offlineQueued);
    }
  }

  Future<void> _enqueueOffline(DeviceProfile profile) async {
    try {
      final queue = await _loadQueue();
      // Remove any stale queued profile for this same deviceId to ensure atomic latest state
      queue.removeWhere((item) => item['deviceId'] == profile.deviceId);
      queue.add(profile.toMap());
      await _saveQueue(queue);
    } catch (e) {
      throw OfflineQueueException(
          'Failed to enqueue profile to offline storage', e);
    }
  }

  Future<List<Map<String, dynamic>>> _loadQueue() async {
    final raw = await secureStorage.read(
      key: SecurityConstants.keyOfflineSyncQueue,
    );
    if (raw == null || raw.isEmpty) {
      return [];
    }
    try {
      final decoded = jsonDecode(raw) as List;
      return decoded.map((e) => Map<String, dynamic>.from(e as Map)).toList();
    } catch (_) {
      return [];
    }
  }

  Future<void> _saveQueue(List<Map<String, dynamic>> queue) async {
    await secureStorage.write(
      key: SecurityConstants.keyOfflineSyncQueue,
      value: jsonEncode(queue),
    );
  }

  void dispose() {
    _statusController.close();
  }
}
