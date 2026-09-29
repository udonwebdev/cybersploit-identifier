import 'dart:async';
import 'package:flutter/foundation.dart';

import '../models/device_profile.dart';
import '../models/security_posture.dart';
import '../models/security_trigger_event.dart';
import '../models/threat_report.dart';
import '../services/contracts/i_biometric_auth_service.dart';
import '../services/contracts/i_location_platform_service.dart';
import 'background_security_repository.dart';
import 'device_repository.dart';

/// Contract for reactive security posture tracking and authenticated permission gatekeeping.
abstract class ISecurityPostureRepository {
  /// Reactive ValueListenable of current security posture state.
  ValueListenable<SecurityPostureState> get posture;

  /// Reactive stream of security posture changes.
  Stream<SecurityPostureState> get postureStream;

  /// Authenticated gate for toggling location tracking.
  /// If [isBiometricallyAuthenticated] is false, refuses to change state and returns false.
  /// If true, updates location tracking in repositories, recalculates posture, and returns true.
  Future<bool> setLocationTrackingEnabled({
    required bool enabled,
    required bool isBiometricallyAuthenticated,
  });

  /// Evaluates device posture and emits updated state.
  Future<void> refreshPosture();

  /// Releases resources and stream subscriptions.
  void dispose();
}

/// Concrete repository that aggregates state from [DeviceRepository],
/// [BackgroundSecurityRepository], [IBiometricAuthService], and [ILocationPlatformService].
class SecurityPostureRepository implements ISecurityPostureRepository {
  final DeviceRepository deviceRepository;
  final BackgroundSecurityRepository backgroundSecurityRepository;
  final IBiometricAuthService biometricService;
  final ILocationPlatformService locationService;

  final ValueNotifier<SecurityPostureState> _postureNotifier =
      ValueNotifier<SecurityPostureState>(SecurityPostureState.initial());
  final StreamController<SecurityPostureState> _postureStreamController =
      StreamController<SecurityPostureState>.broadcast();

  StreamSubscription<SecurityTriggerEvent>? _triggerSubscription;
  StreamSubscription<ThreatReport>? _threatReportSubscription;
  StreamSubscription<LocationSnapshot>? _locationSubscription;

  bool _isDisposed = false;

  SecurityPostureRepository({
    required this.deviceRepository,
    required this.backgroundSecurityRepository,
    required this.biometricService,
    required this.locationService,
  }) {
    _initListeners();
    refreshPosture();
  }

  void _initListeners() {
    // Listen to background security triggers
    _triggerSubscription =
        backgroundSecurityRepository.triggerStream.listen((event) {
      if (event.isSuspicious) {
        refreshPosture();
      }
    });

    // Listen to threat scan reports
    _threatReportSubscription =
        backgroundSecurityRepository.threatReportStream.listen((_) {
      refreshPosture();
    });

    // Listen to significant location updates for mock location detection
    _locationSubscription =
        locationService.significantLocationStream.listen((snapshot) async {
      if (snapshot.isMockLocation) {
        // Flag mock location in device repository
        await deviceRepository.updateTamperFlags({'mockLocationDetected': true});
        await refreshPosture();
      }
    });
  }

  @override
  ValueListenable<SecurityPostureState> get posture => _postureNotifier;

  @override
  Stream<SecurityPostureState> get postureStream =>
      _postureStreamController.stream;

  @override
  Future<bool> setLocationTrackingEnabled({
    required bool enabled,
    required bool isBiometricallyAuthenticated,
  }) async {
    if (!isBiometricallyAuthenticated) {
      return false;
    }

    // Update tracking status in device profile
    await deviceRepository.updateTrackingStatus({'trackingEnabled': enabled});

    // Update background monitoring
    if (enabled) {
      await backgroundSecurityRepository.startBackgroundMonitoring();
    } else {
      await backgroundSecurityRepository.stopBackgroundMonitoring();
    }

    await refreshPosture();
    return true;
  }

  @override
  Future<void> refreshPosture() async {
    if (_isDisposed) return;

    // 1. Check device profile tamper & tracking status
    DeviceProfile? profile;
    try {
      profile = await deviceRepository.getOrCreateDeviceProfile(syncToCloud: false);
    } catch (_) {
      // Graceful fallback if device profile fails to load
    }

    final bool rootOrJailbreak = profile?.tamperFlags['rootDetected'] == true ||
        profile?.tamperFlags['jailbreakDetected'] == true ||
        profile?.tamperFlags['debuggerAttached'] == true ||
        profile?.tamperFlags['mockLocationDetected'] == true;

    // 2. Check location tracking and permission
    bool isTracking = false;
    bool hasPermission = false;
    try {
      hasPermission = await locationService.isLocationTrackingEnabled();
      isTracking = profile?.trackingStatus['trackingEnabled'] == true && hasPermission;
    } catch (_) {
      hasPermission = false;
      isTracking = false;
    }

    // 3. Check biometric enrollment & capability
    bool isBiometricConfigured = false;
    try {
      final canCheck = await biometricService.canCheckBiometrics();
      final available = await biometricService.getAvailableBiometrics();
      isBiometricConfigured = canCheck && available.isNotEmpty;
    } catch (_) {
      isBiometricConfigured = false;
    }

    // 4. Check active threats from threat scanner
    final latestReport = backgroundSecurityRepository.latestThreatReport;
    final bool hasHighThreats = latestReport != null &&
        latestReport.threatDetails.any((t) =>
            t.severity == ThreatSeverity.critical ||
            t.severity == ThreatSeverity.high);

    final bool isTamper = rootOrJailbreak || hasHighThreats;

    // 5. Compute overall posture level & status summary
    final SecurityLevel level;
    final String summary;

    if (isTamper) {
      level = SecurityLevel.critical;
      if (hasHighThreats) {
        summary = 'Critical threat detected by malware scanner.';
      } else if (profile?.tamperFlags['mockLocationDetected'] == true) {
        summary = 'Critical alert: Mock location spoofing detected.';
      } else {
        summary = 'Critical alert: Device integrity compromised (root/jailbreak).';
      }
    } else if (isTracking && hasPermission && isBiometricConfigured) {
      level = SecurityLevel.high;
      summary = 'All shields active. Anti-theft tracking & biometric gates secured.';
    } else {
      level = SecurityLevel.degraded;
      final List<String> pending = [];
      if (!isTracking) pending.add('Tracking disabled');
      if (!hasPermission) pending.add('Location permission missing');
      if (!isBiometricConfigured) pending.add('Biometrics not enrolled');
      summary = 'Protection degraded: ${pending.join(', ')}.';
    }

    final newState = SecurityPostureState(
      isTrackingActive: isTracking,
      hasLocationPermission: hasPermission,
      isBiometricConfigured: isBiometricConfigured,
      isTamperDetected: isTamper,
      overallPosture: level,
      statusSummary: summary,
      lastEvaluatedAt: DateTime.now(),
    );

    if (_isDisposed) return;

    _postureNotifier.value = newState;
    if (!_postureStreamController.isClosed) {
      _postureStreamController.add(newState);
    }
  }

  @override
  void dispose() {
    _isDisposed = true;
    _triggerSubscription?.cancel();
    _threatReportSubscription?.cancel();
    _locationSubscription?.cancel();
    _postureNotifier.dispose();
    _postureStreamController.close();
  }
}
