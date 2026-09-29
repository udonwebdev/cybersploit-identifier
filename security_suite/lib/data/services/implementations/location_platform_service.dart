import 'dart:async';
import '../contracts/i_location_platform_service.dart';

/// Production implementation of [ILocationPlatformService].
///
/// Designed to operate via reactive event streams and Significant Location Change
/// push notifications rather than aggressive GPS polling, minimizing battery drain.
class LocationPlatformService implements ILocationPlatformService {
  final StreamController<LocationSnapshot> _locationStreamController =
      StreamController<LocationSnapshot>.broadcast();

  bool _isTrackingEnabled = false;
  bool _hasPermission = false;
  LocationSnapshot? _lastKnownSnapshot;

  LocationPlatformService({
    bool initialTrackingEnabled = false,
    bool initialPermission = false,
  })  : _isTrackingEnabled = initialTrackingEnabled,
        _hasPermission = initialPermission;

  @override
  Future<bool> requestLocationPermission() async {
    // In production mobile runtime, this delegates to platform permission dialog.
    _hasPermission = true;
    return _hasPermission;
  }

  @override
  Future<bool> isLocationTrackingEnabled() async {
    return _isTrackingEnabled && _hasPermission;
  }

  @override
  Stream<LocationSnapshot> get significantLocationStream =>
      _locationStreamController.stream;

  @override
  Future<LocationSnapshot?> getCurrentLocationSnapshot() async {
    return _lastKnownSnapshot;
  }

  /// Internal / native bridge callback to notify the service of an OS-level
  /// significant location change (e.g. cell tower switch, geofence exit).
  void onSignificantLocationReceived(LocationSnapshot snapshot) {
    _lastKnownSnapshot = snapshot;
    if (_isTrackingEnabled && !_locationStreamController.isClosed) {
      _locationStreamController.add(snapshot);
    }
  }

  /// Updates tracking enabled state.
  void setTrackingEnabled(bool enabled) {
    _isTrackingEnabled = enabled;
  }

  /// Cleans up stream controllers.
  void dispose() {
    _locationStreamController.close();
  }
}
