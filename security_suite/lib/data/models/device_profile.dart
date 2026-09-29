import 'dart:convert';

/// Strict capability tiers partitioned between legacy and modern runtimes.
enum CapabilityTier {
  /// Legacy tier: Android 8.0 - 9.0 (API 26-28), constrained memory (<35MB RSS), lean defense.
  legacy,

  /// Modern tier: Android 10+ (API 29+) & modern iOS (14+), deep heuristic defense.
  modern,
}

/// Hardware and OS metadata collected without privileged or non-resettable identifiers.
class DeviceMetadata {
  final String platform;
  final String osVersion;
  final int apiLevel;
  final String deviceModel;
  final String manufacturer;
  final String hardwareArchitecture;
  final bool isPhysical;
  final DateTime timestamp;

  const DeviceMetadata({
    required this.platform,
    required this.osVersion,
    required this.apiLevel,
    required this.deviceModel,
    required this.manufacturer,
    required this.hardwareArchitecture,
    required this.isPhysical,
    required this.timestamp,
  });

  Map<String, dynamic> toMap() {
    return {
      'platform': platform,
      'osVersion': osVersion,
      'apiLevel': apiLevel,
      'deviceModel': deviceModel,
      'manufacturer': manufacturer,
      'hardwareArchitecture': hardwareArchitecture,
      'isPhysical': isPhysical,
      'timestamp': timestamp.toIso8601String(),
    };
  }

  factory DeviceMetadata.fromMap(Map<String, dynamic> map) {
    return DeviceMetadata(
      platform: map['platform'] as String? ?? 'unknown',
      osVersion: map['osVersion'] as String? ?? 'unknown',
      apiLevel: (map['apiLevel'] as num?)?.toInt() ?? 0,
      deviceModel: map['deviceModel'] as String? ?? 'unknown',
      manufacturer: map['manufacturer'] as String? ?? 'unknown',
      hardwareArchitecture: map['hardwareArchitecture'] as String? ?? 'unknown',
      isPhysical: map['isPhysical'] as bool? ?? true,
      timestamp: map['timestamp'] != null
          ? DateTime.tryParse(map['timestamp'] as String) ?? DateTime.now()
          : DateTime.now(),
    );
  }

  String toJson() => jsonEncode(toMap());

  factory DeviceMetadata.fromJson(String source) =>
      DeviceMetadata.fromMap(jsonDecode(source) as Map<String, dynamic>);

  DeviceMetadata copyWith({
    String? platform,
    String? osVersion,
    int? apiLevel,
    String? deviceModel,
    String? manufacturer,
    String? hardwareArchitecture,
    bool? isPhysical,
    DateTime? timestamp,
  }) {
    return DeviceMetadata(
      platform: platform ?? this.platform,
      osVersion: osVersion ?? this.osVersion,
      apiLevel: apiLevel ?? this.apiLevel,
      deviceModel: deviceModel ?? this.deviceModel,
      manufacturer: manufacturer ?? this.manufacturer,
      hardwareArchitecture: hardwareArchitecture ?? this.hardwareArchitecture,
      isPhysical: isPhysical ?? this.isPhysical,
      timestamp: timestamp ?? this.timestamp,
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is DeviceMetadata &&
          runtimeType == other.runtimeType &&
          platform == other.platform &&
          osVersion == other.osVersion &&
          apiLevel == other.apiLevel &&
          deviceModel == other.deviceModel &&
          manufacturer == other.manufacturer &&
          hardwareArchitecture == other.hardwareArchitecture &&
          isPhysical == other.isPhysical;

  @override
  int get hashCode => Object.hash(
        platform,
        osVersion,
        apiLevel,
        deviceModel,
        manufacturer,
        hardwareArchitecture,
        isPhysical,
      );

  @override
  String toString() {
    return 'DeviceMetadata(platform: $platform, os: $osVersion, api: $apiLevel, model: $deviceModel, mfr: $manufacturer, arch: $hardwareArchitecture, physical: $isPhysical)';
  }
}

/// Complete Device Profile linked to Cloud Firestore.
class DeviceProfile {
  final String deviceId;
  final DeviceMetadata metadata;
  final CapabilityTier capabilityTier;
  final DateTime lastSeen;
  final Map<String, dynamic> tamperFlags;
  final Map<String, dynamic> trackingStatus;
  final Map<String, dynamic> vaultMetadata;

  const DeviceProfile({
    required this.deviceId,
    required this.metadata,
    required this.capabilityTier,
    required this.lastSeen,
    this.tamperFlags = const {},
    this.trackingStatus = const {},
    this.vaultMetadata = const {},
  });

  Map<String, dynamic> toMap() {
    return {
      'deviceId': deviceId,
      'metadata': metadata.toMap(),
      'capabilityTier': capabilityTier.name,
      'lastSeen': lastSeen.toIso8601String(),
      'tamperFlags': tamperFlags,
      'trackingStatus': trackingStatus,
      'vaultMetadata': vaultMetadata,
    };
  }

  factory DeviceProfile.fromMap(Map<String, dynamic> map) {
    return DeviceProfile(
      deviceId: map['deviceId'] as String? ?? '',
      metadata: DeviceMetadata.fromMap(
          map['metadata'] as Map<String, dynamic>? ?? {}),
      capabilityTier: CapabilityTier.values.firstWhere(
        (t) => t.name == map['capabilityTier'],
        orElse: () => CapabilityTier.legacy,
      ),
      lastSeen: map['lastSeen'] != null
          ? DateTime.tryParse(map['lastSeen'] as String) ?? DateTime.now()
          : DateTime.now(),
      tamperFlags: Map<String, dynamic>.from(
          map['tamperFlags'] as Map<String, dynamic>? ?? {}),
      trackingStatus: Map<String, dynamic>.from(
          map['trackingStatus'] as Map<String, dynamic>? ?? {}),
      vaultMetadata: Map<String, dynamic>.from(
          map['vaultMetadata'] as Map<String, dynamic>? ?? {}),
    );
  }

  String toJson() => jsonEncode(toMap());

  factory DeviceProfile.fromJson(String source) =>
      DeviceProfile.fromMap(jsonDecode(source) as Map<String, dynamic>);

  DeviceProfile copyWith({
    String? deviceId,
    DeviceMetadata? metadata,
    CapabilityTier? capabilityTier,
    DateTime? lastSeen,
    Map<String, dynamic>? tamperFlags,
    Map<String, dynamic>? trackingStatus,
    Map<String, dynamic>? vaultMetadata,
  }) {
    return DeviceProfile(
      deviceId: deviceId ?? this.deviceId,
      metadata: metadata ?? this.metadata,
      capabilityTier: capabilityTier ?? this.capabilityTier,
      lastSeen: lastSeen ?? this.lastSeen,
      tamperFlags: tamperFlags ?? this.tamperFlags,
      trackingStatus: trackingStatus ?? this.trackingStatus,
      vaultMetadata: vaultMetadata ?? this.vaultMetadata,
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is DeviceProfile &&
          runtimeType == other.runtimeType &&
          deviceId == other.deviceId &&
          metadata == other.metadata &&
          capabilityTier == other.capabilityTier;

  @override
  int get hashCode => Object.hash(deviceId, metadata, capabilityTier);

  @override
  String toString() {
    return 'DeviceProfile(id: $deviceId, tier: ${capabilityTier.name}, lastSeen: $lastSeen)';
  }
}
