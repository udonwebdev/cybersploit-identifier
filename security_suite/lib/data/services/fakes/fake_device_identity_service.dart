import 'package:uuid/uuid.dart';
import '../../../core/constants/security_constants.dart';
import '../../models/device_profile.dart';
import '../contracts/i_device_identity_service.dart';
import '../contracts/i_secure_storage_service.dart';

/// In-memory fake implementation of [IDeviceIdentityService] for headless CI testing.
class FakeDeviceIdentityService implements IDeviceIdentityService {
  final ISecureStorageService? storageService;
  final Uuid _uuid = const Uuid();

  DeviceMetadata? mockMetadata;
  String? presetDeviceId;

  FakeDeviceIdentityService({
    this.storageService,
    this.mockMetadata,
    this.presetDeviceId,
  });

  @override
  Future<String> getOrCreateAppScopedDeviceId() async {
    final preset = presetDeviceId;
    if (preset != null) {
      return preset;
    }

    final storage = storageService;
    if (storage != null) {
      final existing = await storage.read(
        key: SecurityConstants.keyAppScopedDeviceId,
      );
      if (existing != null && existing.isNotEmpty) {
        return existing;
      }
      final newId = _uuid.v4();
      await storage.write(
        key: SecurityConstants.keyAppScopedDeviceId,
        value: newId,
      );
      return newId;
    }

    final generated = _uuid.v4();
    presetDeviceId = generated;
    return generated;
  }

  @override
  Future<DeviceMetadata> collectDeviceMetadata() async {
    final mock = mockMetadata;
    if (mock != null) {
      return mock;
    }

    return DeviceMetadata(
      platform: 'android',
      osVersion: 'Android 14',
      apiLevel: 34,
      deviceModel: 'Pixel 8 Pro (Simulated)',
      manufacturer: 'Google',
      hardwareArchitecture: 'arm64-v8a',
      isPhysical: false,
      timestamp: DateTime.now(),
    );
  }

  @override
  CapabilityTier classifyCapabilityTier(DeviceMetadata metadata) {
    if (metadata.platform.toLowerCase() == 'android') {
      if (metadata.apiLevel > 0 &&
          metadata.apiLevel < SecurityConstants.android10ApiLevel) {
        return CapabilityTier.legacy;
      }
    }
    return CapabilityTier.modern;
  }
}
