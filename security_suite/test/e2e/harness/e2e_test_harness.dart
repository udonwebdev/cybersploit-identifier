import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto_pkg;
import 'package:cryptography/cryptography.dart' as crypt;
import 'package:uuid/uuid.dart';

/// Capability tiers conforming to R5 and PROJECT.md § Architecture
enum CapabilityTier {
  legacyLean, // Android 8.0 - 9.0 (<35MB RAM, fast signature only)
  modernFull, // Android 10+ (<80MB RAM, deep heuristic checks)
  iosSandboxed, // iOS 14.0+ (<15MB RAM background budget)
}

/// Platform OS types
enum PlatformOS { android, iOS }

/// Sync status for Cloud Firestore provisioning
enum CloudSyncStatus { idle, syncing, synchronized, offlineQueued, failed }

/// Network connectivity states
enum NetworkState { wifi, cellular, ethernet, none }

/// Power states
enum PowerSource { battery, acCharging, usbCharging, wirelessCharging }

/// Security posture levels
enum SecurityPostureLevel { secure, degraded, critical }

/// Biometric modality types
enum BiometricType { face, fingerprint, iris }

/// Tamper modes for boundary injection
enum TamperMode {
  corruptMagic,
  unsupportedVersion,
  truncatedHeader,
  tamperedCiphertext,
  tamperedAuthTag,
  alteredAssociatedData,
}

/// Device metadata model (F2)
class DeviceMetadata {
  final String brand;
  final String model;
  final PlatformOS os;
  final String osVersion;
  final int apiLevel;
  final String architecture;
  final String securityPatchLevel;
  final int totalRamMb;

  const DeviceMetadata({
    required this.brand,
    required this.model,
    required this.os,
    required this.osVersion,
    required this.apiLevel,
    required this.architecture,
    required this.securityPatchLevel,
    required this.totalRamMb,
  });

  Map<String, dynamic> toMap() => {
        'brand': brand,
        'model': model,
        'os': os.name,
        'osVersion': osVersion,
        'apiLevel': apiLevel,
        'architecture': architecture,
        'securityPatchLevel': securityPatchLevel,
        'totalRamMb': totalRamMb,
      };
}

/// Device cloud profile model (F3)
class DeviceProfile {
  final String deviceId;
  final DeviceMetadata metadata;
  final CapabilityTier capabilityTier;
  final DateTime lastSeen;
  final Map<String, dynamic> tamperFlags;
  final Map<String, dynamic> trackingStatus;
  final Map<String, dynamic> vaultMetadata;

  DeviceProfile({
    required this.deviceId,
    required this.metadata,
    required this.capabilityTier,
    required this.lastSeen,
    required this.tamperFlags,
    required this.trackingStatus,
    required this.vaultMetadata,
  });

  Map<String, dynamic> toFirestoreMap() => {
        'deviceId': deviceId,
        'platform': metadata.os.name,
        'osVersion': metadata.osVersion,
        'apiLevel': metadata.apiLevel,
        'deviceModel': metadata.model,
        'capabilityTier': capabilityTier.name,
        'lastSeen': lastSeen.toIso8601String(),
        'tamperFlags': tamperFlags,
        'trackingStatus': trackingStatus,
        'vaultMetadata': vaultMetadata,
      };
}

/// Security Trigger Event (F4 - F7)
class SecurityTriggerEvent {
  final String triggerId;
  final String eventType; // 'network_handoff', 'power_change', 'location_change', 'scheduled_job'
  final DateTime timestamp;
  final Map<String, dynamic> payload;

  SecurityTriggerEvent({
    required this.triggerId,
    required this.eventType,
    required this.timestamp,
    required this.payload,
  });
}

/// GeoPosition model (F7)
class GeoPosition {
  final double latitude;
  final double longitude;
  final double accuracy;
  final DateTime timestamp;

  const GeoPosition({
    required this.latitude,
    required this.longitude,
    required this.accuracy,
    required this.timestamp,
  });
}

/// Encrypted Vault Payload (F8, F9)
/// Binary layout: [Magic (4B: 'VAUL')] + [Version (1B: 0x01)] + [Nonce (12B)] + [Tag (16B)] + [Ciphertext (NB)]
class EncryptedVaultPayload {
  static const List<int> magicBytes = [0x56, 0x41, 0x55, 0x4C]; // 'VAUL'
  static const int currentVersion = 0x01;
  static const int headerSize = 33; // 4 + 1 + 12 + 16

  final Uint8List rawBytes;

  EncryptedVaultPayload(this.rawBytes);

  Uint8List get magic => rawBytes.sublist(0, 4);
  int get version => rawBytes[4];
  Uint8List get nonce => rawBytes.sublist(5, 17);
  Uint8List get authTag => rawBytes.sublist(17, 33);
  Uint8List get ciphertext => rawBytes.sublist(33);

  bool get isValidHeader {
    if (rawBytes.length < headerSize) return false;
    for (int i = 0; i < 4; i++) {
      if (rawBytes[i] != magicBytes[i]) return false;
    }
    return rawBytes[4] == currentVersion;
  }
}

/// Vault Entry model (F13)
class VaultEntry {
  final String id;
  final String filename;
  final int byteSize;
  final DateTime encryptedAt;
  final String sha256Fingerprint;

  const VaultEntry({
    required this.id,
    required this.filename,
    required this.byteSize,
    required this.encryptedAt,
    required this.sha256Fingerprint,
  });
}

/// Biometric Auth Result (F11)
class BiometricAuthResult {
  final bool isSuccess;
  final String? errorMessage;
  final bool isLockedOut;

  const BiometricAuthResult({
    required this.isSuccess,
    this.errorMessage,
    this.isLockedOut = false,
  });
}

/// Security Posture State (F15)
class SecurityPostureState {
  final bool isTrackingActive;
  final bool hasLocationPermission;
  final bool isBiometricConfigured;
  final bool isRootOrJailbreakDetected;
  final SecurityPostureLevel overallPosture;
  final String statusSummary;
  final DateTime lastEvaluatedAt;

  const SecurityPostureState({
    required this.isTrackingActive,
    required this.hasLocationPermission,
    required this.isBiometricConfigured,
    required this.isRootOrJailbreakDetected,
    required this.overallPosture,
    required this.statusSummary,
    required this.lastEvaluatedAt,
  });

  SecurityPostureState copyWith({
    bool? isTrackingActive,
    bool? hasLocationPermission,
    bool? isBiometricConfigured,
    bool? isRootOrJailbreakDetected,
    SecurityPostureLevel? overallPosture,
    String? statusSummary,
    DateTime? lastEvaluatedAt,
  }) {
    return SecurityPostureState(
      isTrackingActive: isTrackingActive ?? this.isTrackingActive,
      hasLocationPermission: hasLocationPermission ?? this.hasLocationPermission,
      isBiometricConfigured: isBiometricConfigured ?? this.isBiometricConfigured,
      isRootOrJailbreakDetected: isRootOrJailbreakDetected ?? this.isRootOrJailbreakDetected,
      overallPosture: overallPosture ?? this.overallPosture,
      statusSummary: statusSummary ?? this.statusSummary,
      lastEvaluatedAt: lastEvaluatedAt ?? this.lastEvaluatedAt,
    );
  }
}

/// Threat Severity Level (F17, F18)
enum ThreatSeverity { low, medium, high, critical }

/// Detected Threat Item
class ThreatItem {
  final String threatId;
  final String packageName;
  final String detectionType; // 'signature', 'heuristic_accessibility', 'heuristic_sideload', 'entropy'
  final ThreatSeverity severity;
  final String description;

  const ThreatItem({
    required this.threatId,
    required this.packageName,
    required this.detectionType,
    required this.severity,
    required this.description,
  });
}

/// Threat Scan Report (F17, F18)
class ThreatReport {
  final DateTime scanTimestamp;
  final CapabilityTier executedUnderTier;
  final int totalScanned;
  final List<ThreatItem> detectedThreats;
  final int executionTimeMs;

  const ThreatReport({
    required this.scanTimestamp,
    required this.executedUnderTier,
    required this.totalScanned,
    required this.detectedThreats,
    required this.executionTimeMs,
  });

  bool get hasThreats => detectedThreats.isNotEmpty;
}

/// ==============================================================================
/// SIMULATED PLATFORM HARNESS FOR OPAQUE-BOX E2E VERIFICATION
/// ==============================================================================
class E2ETestHarness {
  final _uuid = const Uuid();
  final crypt.AesGcm _aesGcm = crypt.AesGcm.with256bits();

  // --- Platform Environment Configuration ---
  PlatformOS platformOS = PlatformOS.android;
  int apiLevel = 34; // Modern Tier default
  String osVersion = 'Android 14';
  String deviceBrand = 'Google';
  String deviceModel = 'Pixel 8';
  int totalRamMb = 8192;
  String securityPatch = '2026-03-01';

  // --- Simulated Hardware KeyStore / Secure Storage (F10) ---
  final Map<String, String> _secureStorage = {};

  // --- Simulated Cloud Firestore (F3) ---
  final Map<String, Map<String, dynamic>> _cloudFirestore = {};
  final List<Map<String, dynamic>> _offlineSyncQueue = [];
  final StreamController<CloudSyncStatus> _syncStatusController =
      StreamController<CloudSyncStatus>.broadcast();

  // --- Reactive Streams (F4, F5, F6, F7) ---
  final StreamController<SecurityTriggerEvent> _triggerEventController =
      StreamController<SecurityTriggerEvent>.broadcast();
  final StreamController<NetworkState> _networkStreamController =
      StreamController<NetworkState>.broadcast();
  final StreamController<PowerSource> _powerStreamController =
      StreamController<PowerSource>.broadcast();
  final StreamController<GeoPosition> _locationStreamController =
      StreamController<GeoPosition>.broadcast();

  // --- State Observables ---
  NetworkState currentNetwork = NetworkState.wifi;
  PowerSource currentPower = PowerSource.battery;
  int batteryLevelPercent = 85;
  GeoPosition? lastKnownLocation;
  bool isLocationPermissionGranted = true;
  bool isBackgroundLocationEnabled = true;

  // --- Biometric Hardware Simulation (F11) ---
  bool isBiometricHardwareAvailable = true;
  bool hasEnrolledBiometrics = true;
  bool shouldBiometricsSucceed = true;
  bool isBiometricsLockedOut = false;
  int failedBiometricAttempts = 0;
  List<BiometricType> availableBiometrics = [
    BiometricType.fingerprint,
    BiometricType.face,
  ];

  // --- App Fallback PIN & Key Derivation (F12) ---
  String? enrolledPin;
  Uint8List? enrolledPinSalt;

  // --- Cryptographic Vault File Store (F8, F9, F13) ---
  final Map<String, EncryptedVaultPayload> _vaultDiskStorage = {};
  final Map<String, VaultEntry> _vaultMetadataIndex = {};
  Uint8List? _activeMasterKey;

  // --- Threat Scanner Catalog (F17, F18) ---
  final List<Map<String, dynamic>> _simulatedInstalledPackages = [];

  // --- Security Posture State (F14, F15) ---
  late SecurityPostureState _securityPosture;

  E2ETestHarness() {
    _securityPosture = SecurityPostureState(
      isTrackingActive: true,
      hasLocationPermission: true,
      isBiometricConfigured: true,
      isRootOrJailbreakDetected: false,
      overallPosture: SecurityPostureLevel.secure,
      statusSummary: 'Shield active: System protected',
      lastEvaluatedAt: DateTime.now(),
    );
  }

  // --- Getters for Streams ---
  Stream<SecurityTriggerEvent> get triggerEvents => _triggerEventController.stream;
  Stream<NetworkState> get networkStream => _networkStreamController.stream;
  Stream<PowerSource> get powerStream => _powerStreamController.stream;
  Stream<GeoPosition> get locationStream => _locationStreamController.stream;
  Stream<CloudSyncStatus> get syncStatusStream => _syncStatusController.stream;
  SecurityPostureState get currentPosture => _securityPosture;
  Map<String, Map<String, dynamic>> get cloudDatabase => Map.unmodifiable(_cloudFirestore);
  List<Map<String, dynamic>> get offlineQueue => List.unmodifiable(_offlineSyncQueue);
  Map<String, EncryptedVaultPayload> get vaultStorage => Map.unmodifiable(_vaultDiskStorage);

  // ===========================================================================
  // F1 & F2: Privacy-Preserving Device Identity & Hardware Metadata Aggregator
  // ===========================================================================
  Future<DeviceMetadata> collectDeviceMetadata() async {
    return DeviceMetadata(
      brand: deviceBrand,
      model: deviceModel,
      os: platformOS,
      osVersion: osVersion,
      apiLevel: apiLevel,
      architecture: 'arm64-v8a',
      securityPatchLevel: securityPatch,
      totalRamMb: totalRamMb,
    );
  }

  Future<String> getOrCreateAppScopedDeviceId() async {
    const key = 'sec_app_scoped_device_id';
    if (_secureStorage.containsKey(key)) {
      return _secureStorage[key]!;
    }

    // Spec compliance: Android 10+ and iOS cannot access raw IMEI/serial.
    // Derive privacy-preserving hardware token = SHA-256(brand + model + architecture + uuid)
    final instanceUuid = _uuid.v4();
    final combined = '$deviceBrand:$deviceModel:arm64-v8a:$instanceUuid';
    final token = crypto_pkg.sha256.convert(utf8.encode(combined)).toString();

    _secureStorage[key] = token;
    return token;
  }

  // ===========================================================================
  // F16: Adaptive OS Capability Classifier
  // ===========================================================================
  CapabilityTier classifyCapabilityTier(DeviceMetadata metadata) {
    if (metadata.os == PlatformOS.iOS) {
      return CapabilityTier.iosSandboxed;
    }
    if (metadata.apiLevel < 29 || metadata.totalRamMb < 3072) {
      return CapabilityTier.legacyLean;
    }
    return CapabilityTier.modernFull;
  }

  // ===========================================================================
  // F3: Secure Cloud Firestore Profile Provisioning & Offline Queue
  // ===========================================================================
  Future<void> syncDeviceProfile(DeviceProfile profile) async {
    _syncStatusController.add(CloudSyncStatus.syncing);
    await Future.delayed(Duration.zero);

    if (currentNetwork == NetworkState.none) {
      // Offline queueing
      _offlineSyncQueue.add(profile.toFirestoreMap());
      _syncStatusController.add(CloudSyncStatus.offlineQueued);
      return;
    }

    // Atomic upsert
    _cloudFirestore[profile.deviceId] = profile.toFirestoreMap();
    _syncStatusController.add(CloudSyncStatus.synchronized);
    await Future.delayed(Duration.zero);
  }

  Future<void> flushOfflineQueue() async {
    if (currentNetwork == NetworkState.none || _offlineSyncQueue.isEmpty) return;

    _syncStatusController.add(CloudSyncStatus.syncing);
    final itemsToFlush = List<Map<String, dynamic>>.from(_offlineSyncQueue);
    for (final doc in itemsToFlush) {
      final id = doc['deviceId'] as String;
      _cloudFirestore[id] = doc;
    }
    _offlineSyncQueue.clear();
    _syncStatusController.add(CloudSyncStatus.synchronized);
  }

  // ===========================================================================
  // F4 - F7: Event-Driven Background Trigger Engine & Streams
  // ===========================================================================
  void emitNetworkChange(NetworkState state) {
    currentNetwork = state;
    _networkStreamController.add(state);

    final event = SecurityTriggerEvent(
      triggerId: _uuid.v4(),
      eventType: 'network_handoff',
      timestamp: DateTime.now(),
      payload: {'network': state.name},
    );
    _triggerEventController.add(event);

    if (state != NetworkState.none && _offlineSyncQueue.isNotEmpty) {
      flushOfflineQueue();
    }
  }

  void emitPowerChange({required PowerSource source, required int batteryPercent}) {
    currentPower = source;
    batteryLevelPercent = batteryPercent;
    _powerStreamController.add(source);

    final event = SecurityTriggerEvent(
      triggerId: _uuid.v4(),
      eventType: 'power_change',
      timestamp: DateTime.now(),
      payload: {'source': source.name, 'batteryPercent': batteryPercent},
    );
    _triggerEventController.add(event);

    // Adaptive power defense: battery < 15% downgrades active sweeps
    if (batteryPercent < 15 && source == PowerSource.battery) {
      _securityPosture = _securityPosture.copyWith(
        overallPosture: SecurityPostureLevel.degraded,
        statusSummary: 'Battery low (<15%): Heavy security sweeps suspended to preserve anti-theft beacon',
      );
    }
  }

  void emitSignificantLocationChange(double lat, double lng) {
    final pos = GeoPosition(
      latitude: lat,
      longitude: lng,
      accuracy: 10.0,
      timestamp: DateTime.now(),
    );
    lastKnownLocation = pos;
    _locationStreamController.add(pos);

    final event = SecurityTriggerEvent(
      triggerId: _uuid.v4(),
      eventType: 'location_change',
      timestamp: DateTime.now(),
      payload: {'lat': lat, 'lng': lng},
    );
    _triggerEventController.add(event);
  }

  // ===========================================================================
  // F10, F11, F12: Biometrics, KeyStore, Passcode Key Derivation
  // ===========================================================================
  Future<BiometricAuthResult> requestBiometricAuthentication({
    required String reason,
  }) async {
    if (!isBiometricHardwareAvailable) {
      return const BiometricAuthResult(
        isSuccess: false,
        errorMessage: 'Biometric hardware unavailable on this device.',
      );
    }
    if (!hasEnrolledBiometrics) {
      return const BiometricAuthResult(
        isSuccess: false,
        errorMessage: 'No biometric credentials enrolled.',
      );
    }
    if (isBiometricsLockedOut) {
      return const BiometricAuthResult(
        isSuccess: false,
        errorMessage: 'Biometrics temporarily locked due to too many failed attempts.',
        isLockedOut: true,
      );
    }

    if (!shouldBiometricsSucceed) {
      failedBiometricAttempts++;
      if (failedBiometricAttempts >= 5) {
        isBiometricsLockedOut = true;
      }
      return const BiometricAuthResult(
        isSuccess: false,
        errorMessage: 'Biometric verification rejected.',
      );
    }

    failedBiometricAttempts = 0;
    return const BiometricAuthResult(isSuccess: true);
  }

  Future<void> enrollFallbackPin(String pin) async {
    if (pin.length < 4) {
      throw ArgumentError('PIN must be at least 4 digits');
    }
    final salt = Uint8List(16);
    final rng = Random.secure();
    for (int i = 0; i < 16; i++) {
      salt[i] = rng.nextInt(256);
    }
    enrolledPin = pin;
    enrolledPinSalt = salt;
    _secureStorage['pin_salt'] = base64Encode(salt);
  }

  /// PBKDF2 Key Derivation (F12) using SHA-256 HMAC, min 100,000 iterations
  Future<Uint8List> deriveKeyFromPasscode({
    required String passcode,
    required Uint8List salt,
    int iterations = 100000,
  }) async {
    final pbkdf2 = crypt.Pbkdf2(
      macAlgorithm: crypt.Hmac.sha256(),
      iterations: iterations,
      bits: 256,
    );
    final secretKey = await pbkdf2.deriveKey(
      secretKey: crypt.SecretKey(utf8.encode(passcode)),
      nonce: salt,
    );
    final keyBytes = await secretKey.extractBytes();
    return Uint8List.fromList(keyBytes);
  }

  // ===========================================================================
  // F8 & F9: AES-256-GCM Vault Core & Tamper-Evident Binary Container
  // ===========================================================================
  Future<Uint8List> generateMasterVaultKey() async {
    final secretKey = await _aesGcm.newSecretKey();
    final bytes = await secretKey.extractBytes();
    _activeMasterKey = Uint8List.fromList(bytes);
    _secureStorage['master_vault_key'] = base64Encode(_activeMasterKey!);
    return _activeMasterKey!;
  }

  Future<EncryptedVaultPayload> encryptBytes({
    required Uint8List plaintext,
    required Uint8List key256,
    Uint8List? additionalAuthenticatedData,
  }) async {
    if (key256.length != 32) {
      throw ArgumentError('AES-256 key must be exactly 32 bytes.');
    }

    final secretKey = crypt.SecretKey(key256);
    final nonce = _aesGcm.newNonce(); // 12-byte secure random nonce

    final secretBox = await _aesGcm.encrypt(
      plaintext,
      secretKey: secretKey,
      nonce: nonce,
      aad: additionalAuthenticatedData ?? const <int>[],
    );

    // Layout: [Magic: 4B] + [Version: 1B] + [Nonce: 12B] + [Tag: 16B] + [Ciphertext: NB]
    final bb = BytesBuilder();
    bb.add(EncryptedVaultPayload.magicBytes);
    bb.addByte(EncryptedVaultPayload.currentVersion);
    bb.add(secretBox.nonce);
    bb.add(secretBox.mac.bytes);
    bb.add(secretBox.cipherText);

    return EncryptedVaultPayload(bb.toBytes());
  }

  Future<Uint8List> decryptBytes({
    required EncryptedVaultPayload payload,
    required Uint8List key256,
    Uint8List? additionalAuthenticatedData,
  }) async {
    if (key256.length != 32) {
      throw ArgumentError('AES-256 key must be exactly 32 bytes.');
    }
    if (!payload.isValidHeader) {
      throw const FormatException('Invalid or unsupported vault container header.');
    }

    final secretBox = crypt.SecretBox(
      payload.ciphertext,
      nonce: payload.nonce,
      mac: crypt.Mac(payload.authTag),
    );

    final secretKey = crypt.SecretKey(key256);

    // Real mathematical GHASH tag verification
    final decrypted = await _aesGcm.decrypt(
      secretBox,
      secretKey: secretKey,
      aad: additionalAuthenticatedData ?? const <int>[],
    );

    return Uint8List.fromList(decrypted);
  }

  // ===========================================================================
  // F13: Vault File Operations & Shredding
  // ===========================================================================
  Future<VaultEntry> storeVaultFile({
    required String filename,
    required Uint8List plaintext,
    required Uint8List masterKey,
  }) async {
    final aad = Uint8List.fromList(utf8.encode(filename));
    final payload = await encryptBytes(
      plaintext: plaintext,
      key256: masterKey,
      additionalAuthenticatedData: aad,
    );

    final fileId = _uuid.v4();
    _vaultDiskStorage[fileId] = payload;

    final entry = VaultEntry(
      id: fileId,
      filename: filename,
      byteSize: plaintext.length,
      encryptedAt: DateTime.now(),
      sha256Fingerprint: crypto_pkg.sha256.convert(plaintext).toString(),
    );
    _vaultMetadataIndex[fileId] = entry;

    // Secure shredding of temporary buffer
    plaintext.fillRange(0, plaintext.length, 0);

    return entry;
  }

  Future<Uint8List> readVaultFile({
    required String fileId,
    required Uint8List masterKey,
  }) async {
    final payload = _vaultDiskStorage[fileId];
    if (payload == null) {
      throw StateError('Vault file $fileId not found.');
    }
    final entry = _vaultMetadataIndex[fileId]!;
    final aad = Uint8List.fromList(utf8.encode(entry.filename));

    return await decryptBytes(
      payload: payload,
      key256: masterKey,
      additionalAuthenticatedData: aad,
    );
  }

  void injectTamperedPayload(String fileId, TamperMode mode) {
    final original = _vaultDiskStorage[fileId];
    if (original == null) return;

    final bytes = Uint8List.fromList(original.rawBytes);
    switch (mode) {
      case TamperMode.corruptMagic:
        bytes[0] = 0x00;
        break;
      case TamperMode.unsupportedVersion:
        bytes[4] = 0xFF;
        break;
      case TamperMode.truncatedHeader:
        final truncated = bytes.sublist(0, 20);
        _vaultDiskStorage[fileId] = EncryptedVaultPayload(truncated);
        return;
      case TamperMode.tamperedCiphertext:
        bytes[bytes.length - 1] ^= 0x55;
        break;
      case TamperMode.tamperedAuthTag:
        bytes[20] ^= 0xAA;
        break;
      case TamperMode.alteredAssociatedData:
        // Decryption will fail if AAD doesn't match
        break;
    }
    _vaultDiskStorage[fileId] = EncryptedVaultPayload(bytes);
  }

  // ===========================================================================
  // F14 & F15: Authenticated Gatekeeping & Real-Time Posture Tracking
  // ===========================================================================
  Future<bool> setLocationTrackingWithAuth({
    required bool enabled,
    required bool bypassAuthForTesting,
  }) async {
    if (!bypassAuthForTesting) {
      final auth = await requestBiometricAuthentication(
        reason: 'Authorize altering anti-theft location tracking state',
      );
      if (!auth.isSuccess) {
        return false;
      }
    }

    isBackgroundLocationEnabled = enabled;
    _securityPosture = _securityPosture.copyWith(
      isTrackingActive: enabled,
      overallPosture: enabled ? SecurityPostureLevel.secure : SecurityPostureLevel.degraded,
      statusSummary: enabled
          ? 'Anti-Theft Active (Event-driven location monitoring)'
          : 'Warning: Anti-theft tracking disabled by user authorization',
      lastEvaluatedAt: DateTime.now(),
    );
    return true;
  }

  // ===========================================================================
  // F17 & F18: Adaptive Threat Scanners (Lean Signature & Deep Heuristic)
  // ===========================================================================
  void registerSimulatedPackage({
    required String packageName,
    required String sha256Hash,
    required List<String> permissions,
    required bool isSideloaded,
    required double calculatedEntropy,
  }) {
    _simulatedInstalledPackages.add({
      'packageName': packageName,
      'sha256': sha256Hash,
      'permissions': permissions,
      'isSideloaded': isSideloaded,
      'entropy': calculatedEntropy,
    });
  }

  Future<ThreatReport> runThreatScan({required CapabilityTier tier}) async {
    final start = DateTime.now();
    final threats = <ThreatItem>[];

    // Known malicious signatures
    const knownSignatures = {
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855': 'Trojan.Dropper.Generic',
      '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4': 'Spyware.KeyLogger.Mobile',
    };

    for (final pkg in _simulatedInstalledPackages) {
      final pkgName = pkg['packageName'] as String;
      final sha = pkg['sha256'] as String;

      // 1. Signature check (Runs in BOTH Legacy and Modern Tiers)
      if (knownSignatures.containsKey(sha)) {
        threats.add(ThreatItem(
          threatId: _uuid.v4(),
          packageName: pkgName,
          detectionType: 'signature',
          severity: ThreatSeverity.critical,
          description: 'Known malware signature detected: ${knownSignatures[sha]}',
        ));
        continue;
      }

      // 2. Deep Heuristic Checks (Barred from Legacy Lean Tier <35MB to prevent OOM)
      if (tier == CapabilityTier.modernFull) {
        final perms = (pkg['permissions'] as List<String>);
        final isSideloaded = pkg['isSideloaded'] as bool;
        final entropy = pkg['entropy'] as double;

        // Accessibility + Overlay + Sideload = Banking trojan pattern
        final hasAccessibility = perms.contains('android.permission.BIND_ACCESSIBILITY_SERVICE');
        final hasOverlay = perms.contains('android.permission.SYSTEM_ALERT_WINDOW');

        if (isSideloaded && hasAccessibility && hasOverlay) {
          threats.add(ThreatItem(
            threatId: _uuid.v4(),
            packageName: pkgName,
            detectionType: 'heuristic_accessibility',
            severity: ThreatSeverity.high,
            description: 'Heuristic anomaly: Sideloaded app with Accessibility and Overlay permissions',
          ));
        } else if (entropy > 7.8) {
          threats.add(ThreatItem(
            threatId: _uuid.v4(),
            packageName: pkgName,
            detectionType: 'entropy',
            severity: ThreatSeverity.medium,
            description: 'Heuristic anomaly: High binary entropy indicating encrypted/packed malware payload',
          ));
        }
      }
    }

    final duration = DateTime.now().difference(start).inMilliseconds;
    return ThreatReport(
      scanTimestamp: DateTime.now(),
      executedUnderTier: tier,
      totalScanned: _simulatedInstalledPackages.length,
      detectedThreats: threats,
      executionTimeMs: duration,
    );
  }

  void dispose() {
    _syncStatusController.close();
    _triggerEventController.close();
    _networkStreamController.close();
    _powerStreamController.close();
    _locationStreamController.close();
  }
}
