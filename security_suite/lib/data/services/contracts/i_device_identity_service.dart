import '../../models/device_profile.dart';

/// Contract for generating and retrieving privacy-preserving device identifiers
/// and collecting OS-level capability metadata.
abstract class IDeviceIdentityService {
  /// Retrieves or provisions a persistent, app-scoped hardware-anchored device ID
  /// compliant with Android 8+ and iOS privacy restrictions.
  Future<String> getOrCreateAppScopedDeviceId();

  /// Collects immutable system and hardware metadata without privileged IDs.
  Future<DeviceMetadata> collectDeviceMetadata();

  /// Classifies the runtime environment into Legacy (<35MB) or Modern (<80MB) capability tier.
  CapabilityTier classifyCapabilityTier(DeviceMetadata metadata);
}
