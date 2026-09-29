import 'dart:async';
import 'package:flutter/foundation.dart';

import '../../data/models/device_profile.dart';
import '../../data/models/threat_report.dart';
import '../../data/repositories/background_security_repository.dart';
import '../../data/repositories/device_repository.dart';

/// ViewModel managing on-demand and reactive background threat scans.
/// Enforces capability tier scaling (<35MB Legacy signatures vs <80MB Modern deep heuristics).
/// Zero direct UI rendering logic.
class ThreatScannerViewModel extends ChangeNotifier {
  final BackgroundSecurityRepository backgroundSecurityRepository;
  final DeviceRepository deviceRepository;

  bool _isScanning = false;
  ThreatReport? _latestReport;
  CapabilityTier _currentTier = CapabilityTier.modern;
  String? _errorMessage;
  StreamSubscription<ThreatReport>? _threatSubscription;

  ThreatScannerViewModel({
    required this.backgroundSecurityRepository,
    required this.deviceRepository,
  }) {
    _init();
  }

  void _init() {
    _latestReport = backgroundSecurityRepository.latestThreatReport;

    // Determine device capability tier
    deviceRepository.getCapabilityTier().then((tier) {
      _currentTier = tier;
      notifyListeners();
    }).catchError((_) {
      _currentTier = CapabilityTier.modern;
      notifyListeners();
    });

    // Reactively update when background engine dispatches a threat scan
    _threatSubscription =
        backgroundSecurityRepository.threatReportStream.listen((report) {
      _latestReport = report;
      notifyListeners();
    });
  }

  /// Whether a threat scan is actively running.
  bool get isScanning => _isScanning;

  /// Most recent completed threat report.
  ThreatReport? get latestReport =>
      _latestReport ?? backgroundSecurityRepository.latestThreatReport;

  /// Active capability tier governing scan depth.
  CapabilityTier get currentTier => _currentTier;

  /// Any error message encountered during scanning.
  String? get errorMessage => _errorMessage;

  /// Triggers an immediate adaptive threat scan scaled to the active tier.
  Future<ThreatReport> triggerScan() async {
    _isScanning = true;
    _errorMessage = null;
    notifyListeners();

    try {
      final report = await backgroundSecurityRepository.dispatchThreatScan(
        overrideTier: _currentTier,
      );
      _latestReport = report;
      _isScanning = false;
      notifyListeners();
      return report;
    } catch (e) {
      _errorMessage = 'Threat scan failed: $e';
      _isScanning = false;
      notifyListeners();
      rethrow;
    }
  }

  @override
  void dispose() {
    _threatSubscription?.cancel();
    super.dispose();
  }
}
