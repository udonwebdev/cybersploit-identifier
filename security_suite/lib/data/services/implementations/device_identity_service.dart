import 'dart:convert';
import 'dart:io' show Platform;
import 'package:crypto/crypto.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:uuid/uuid.dart';

import '../../../core/constants/security_constants.dart';
import '../../../core/errors/security_exceptions.dart';
import '../../models/device_profile.dart';
import '../contracts/i_device_identity_service.dart';
import '../contracts/i_secure_storage_service.dart';

/// Production implementation of [IDeviceIdentityService].
/// Provisions a privacy-preserving app-scoped hardware-anchored token and collects
/// system metadata without accessing restricted non-resettable hardware IDs.
class DeviceIdentityService implements IDeviceIdentityService {
  final ISecureStorageService secureStorage;
  final DeviceInfoPlugin _deviceInfoPlugin;
  final Uuid _uuid;
  final Future<DeviceMetadata> Function()? _customMetadataProvider;

  DeviceIdentityService({
    required this.secureStorage,
    DeviceInfoPlugin? deviceInfoPlugin,
    Uuid? uuid,
    Future<DeviceMetadata> Function()? metadataProvider,
  })  : _deviceInfoPlugin = deviceInfoPlugin ?? DeviceInfoPlugin(),
        _uuid = uuid ?? const Uuid(),
        _customMetadataProvider = metadataProvider;

  Future<String>? _pendingProvisionFuture;

  @override
  Future<String> getOrCreateAppScopedDeviceId() {
    if (_pendingProvisionFuture != null) {
      return _pendingProvisionFuture!;
    }

    final future = _provisionAppScopedDeviceId();
    _pendingProvisionFuture = future;
    return future;
  }

  Future<String> _provisionAppScopedDeviceId() async {
    try {
      final existingId = await secureStorage.read(
        key: SecurityConstants.keyAppScopedDeviceId,
      );
      if (existingId != null && existingId.trim().isNotEmpty) {
        final trimmed = existingId.trim();
        return trimmed;
      }

      // Generate a fresh app instance UUIDv4
      final appInstanceId = _uuid.v4();

      // Collect non-sensitive hardware attributes to anchor the token
      final metadata = await collectDeviceMetadata();
      final fingerprintInput = [
        metadata.platform,
        metadata.manufacturer,
        metadata.deviceModel,
        metadata.hardwareArchitecture,
      ].join('::');

      final fingerprintHash =
          sha256.convert(utf8.encode(fingerprintInput)).toString();

      // Formulate privacy-preserving app-scoped hardware token
      // Combining UUIDv4 with a 16-character hardware anchor slice
      final deviceId = '$appInstanceId-${fingerprintHash.substring(0, 16)}';

      // Persist to secure storage
      await secureStorage.write(
        key: SecurityConstants.keyAppScopedDeviceId,
        value: deviceId,
      );
      await secureStorage.write(
        key: SecurityConstants.keyDeviceFingerprint,
        value: fingerprintHash,
      );

      return deviceId;
    } catch (e) {
      if (e is SecuritySuiteException) rethrow;
      throw DeviceIdentityException(
        'Failed to provision app-scoped device identity: ${e.toString()}',
        e,
      );
    } finally {
      _pendingProvisionFuture = null;
    }
  }

  @override
  Future<DeviceMetadata> collectDeviceMetadata() async {
    final customProvider = _customMetadataProvider;
    if (customProvider != null) {
      return await customProvider();
    }

    try {
      if (kIsWeb) {
        final webInfo = await _deviceInfoPlugin.webBrowserInfo;
        return DeviceMetadata(
          platform: 'web',
          osVersion: webInfo.userAgent ?? 'unknown',
          apiLevel: 0,
          deviceModel: webInfo.browserName.name,
          manufacturer: webInfo.vendor ?? 'unknown',
          hardwareArchitecture: webInfo.platform ?? 'unknown',
          isPhysical: true,
          timestamp: DateTime.now(),
        );
      }

      if (Platform.isAndroid) {
        final androidInfo = await _deviceInfoPlugin.androidInfo;
        return DeviceMetadata(
          platform: 'android',
          osVersion: 'Android ${androidInfo.version.release}',
          apiLevel: androidInfo.version.sdkInt,
          deviceModel: androidInfo.model,
          manufacturer: androidInfo.manufacturer,
          hardwareArchitecture: androidInfo.supportedAbis.isNotEmpty
              ? androidInfo.supportedAbis.first
              : 'unknown',
          isPhysical: androidInfo.isPhysicalDevice,
          timestamp: DateTime.now(),
        );
      }

      if (Platform.isIOS) {
        final iosInfo = await _deviceInfoPlugin.iosInfo;
        final systemMajorVersion =
            int.tryParse(iosInfo.systemVersion.split('.').first) ?? 0;
        return DeviceMetadata(
          platform: 'ios',
          osVersion: '${iosInfo.systemName} ${iosInfo.systemVersion}',
          apiLevel: systemMajorVersion,
          deviceModel: iosInfo.model,
          manufacturer: 'Apple',
          hardwareArchitecture: iosInfo.utsname.machine,
          isPhysical: iosInfo.isPhysicalDevice,
          timestamp: DateTime.now(),
        );
      }

      if (Platform.isWindows) {
        final winInfo = await _deviceInfoPlugin.windowsInfo;
        return DeviceMetadata(
          platform: 'windows',
          osVersion: winInfo.displayVersion,
          apiLevel: winInfo.buildNumber,
          deviceModel: winInfo.computerName,
          manufacturer: 'Microsoft/OEM',
          hardwareArchitecture: 'x86_64',
          isPhysical: true,
          timestamp: DateTime.now(),
        );
      }

      if (Platform.isLinux) {
        final linuxInfo = await _deviceInfoPlugin.linuxInfo;
        return DeviceMetadata(
          platform: 'linux',
          osVersion: linuxInfo.versionId ?? 'unknown',
          apiLevel: 0,
          deviceModel: linuxInfo.name,
          manufacturer: 'Linux',
          hardwareArchitecture: 'unknown',
          isPhysical: true,
          timestamp: DateTime.now(),
        );
      }

      if (Platform.isMacOS) {
        final macInfo = await _deviceInfoPlugin.macOsInfo;
        return DeviceMetadata(
          platform: 'macos',
          osVersion: macInfo.osRelease,
          apiLevel: macInfo.majorVersion,
          deviceModel: macInfo.model,
          manufacturer: 'Apple',
          hardwareArchitecture: macInfo.arch,
          isPhysical: true,
          timestamp: DateTime.now(),
        );
      }

      return DeviceMetadata(
        platform: 'unknown',
        osVersion: 'unknown',
        apiLevel: 0,
        deviceModel: 'generic',
        manufacturer: 'generic',
        hardwareArchitecture: 'unknown',
        isPhysical: true,
        timestamp: DateTime.now(),
      );
    } on MissingPluginException {
      return DeviceMetadata(
        platform: Platform.operatingSystem,
        osVersion: Platform.operatingSystemVersion,
        apiLevel: 0,
        deviceModel: 'Host System',
        manufacturer: 'Host OEM',
        hardwareArchitecture: 'x86_64',
        isPhysical: false,
        timestamp: DateTime.now(),
      );
    } catch (e) {
      throw HardwareTokenGenerationException(
        'Failed to aggregate device metadata: ${e.toString()}',
        e,
      );
    }
  }

  @override
  CapabilityTier classifyCapabilityTier(DeviceMetadata metadata) {
    final platform = metadata.platform.trim().toLowerCase();
    if (platform == 'android') {
      // Android 8.0 (API 26) through Android 9.0 (API 28) is Legacy Tier
      if (metadata.apiLevel > 0 &&
          metadata.apiLevel < SecurityConstants.android10ApiLevel) {
        return CapabilityTier.legacy;
      }
      return CapabilityTier.modern;
    }

    // iOS and other platforms operate under modern or sandboxed tier
    return CapabilityTier.modern;
  }
}
