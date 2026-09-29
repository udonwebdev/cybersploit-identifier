import 'dart:async';
import '../contracts/i_location_platform_service.dart';

/// In-memory fake implementation of [ILocationPlatformService] for headless CI testing.
class FakeLocationPlatformService implements ILocationPlatformService {
  final StreamController<LocationSnapshot> _locationController =
      StreamController<LocationSnapshot>.broadcast();

  bool permissionGranted = true;
  bool trackingEnabled = true;
  LocationSnapshot? currentLocation;

  @override
  Future<bool> requestLocationPermission() async {
    return permissionGranted;
  }

  @override
  Future<bool> isLocationTrackingEnabled() async {
    return trackingEnabled && permissionGranted;
  }

  @override
  Stream<LocationSnapshot> get significantLocationStream =>
      _locationController.stream;

  @override
  Future<LocationSnapshot?> getCurrentLocationSnapshot() async {
    return currentLocation;
  }

  /// Test helper: Emits a simulated significant location event.
  void emitLocation(LocationSnapshot snapshot) {
    currentLocation = snapshot;
    if (!_locationController.isClosed) {
      _locationController.add(snapshot);
    }
  }

  /// Test helper: Toggles simulated permission state.
  void setPermission(bool granted) {
    permissionGranted = granted;
  }

  /// Test helper: Toggles simulated tracking active state.
  void setTrackingEnabled(bool enabled) {
    trackingEnabled = enabled;
  }

  /// Closes the stream controller.
  void dispose() {
    _locationController.close();
  }
}
