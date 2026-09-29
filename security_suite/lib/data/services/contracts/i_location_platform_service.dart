/// Snapshot of device geolocation coordinates.
class LocationSnapshot {
  final double latitude;
  final double longitude;
  final double accuracy;
  final DateTime timestamp;
  final bool isMockLocation;

  const LocationSnapshot({
    required this.latitude,
    required this.longitude,
    required this.accuracy,
    required this.timestamp,
    this.isMockLocation = false,
  });

  Map<String, dynamic> toMap() {
    return {
      'latitude': latitude,
      'longitude': longitude,
      'accuracy': accuracy,
      'timestamp': timestamp.toIso8601String(),
      'isMockLocation': isMockLocation,
    };
  }

  factory LocationSnapshot.fromMap(Map<String, dynamic> map) {
    return LocationSnapshot(
      latitude: (map['latitude'] as num?)?.toDouble() ?? 0.0,
      longitude: (map['longitude'] as num?)?.toDouble() ?? 0.0,
      accuracy: (map['accuracy'] as num?)?.toDouble() ?? 0.0,
      timestamp: map['timestamp'] != null
          ? DateTime.tryParse(map['timestamp'] as String) ?? DateTime.now()
          : DateTime.now(),
      isMockLocation: map['isMockLocation'] as bool? ?? false,
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is LocationSnapshot &&
          runtimeType == other.runtimeType &&
          latitude == other.latitude &&
          longitude == other.longitude &&
          accuracy == other.accuracy &&
          timestamp == other.timestamp &&
          isMockLocation == other.isMockLocation;

  @override
  int get hashCode => Object.hash(
        latitude,
        longitude,
        accuracy,
        timestamp,
        isMockLocation,
      );

  @override
  String toString() {
    return 'LocationSnapshot(lat: $latitude, lng: $longitude, acc: ${accuracy}m, mock: $isMockLocation)';
  }
}

/// Platform contract for low-power, event-driven location tracking.
///
/// Implementations must favor event-driven cell tower / Wi-Fi handoff
/// updates (Significant Location Change) rather than high-frequency GPS polling.
abstract class ILocationPlatformService {
  /// Prompts the user or system for location permissions.
  Future<bool> requestLocationPermission();

  /// Returns whether location tracking is actively enabled and authorized.
  Future<bool> isLocationTrackingEnabled();

  /// Reactive stream emitting location changes on significant movement.
  Stream<LocationSnapshot> get significantLocationStream;

  /// Fetches the last known or immediate location snapshot.
  Future<LocationSnapshot?> getCurrentLocationSnapshot();
}
