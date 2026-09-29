import 'dart:async';
import '../models/device_profile.dart';
import '../models/security_trigger_event.dart';
import '../models/threat_report.dart';
import '../services/contracts/i_background_trigger_service.dart';
import '../services/contracts/i_location_platform_service.dart';
import '../services/contracts/i_threat_scanner_service.dart';
import 'device_repository.dart';

/// Repository that coordinates the event-driven background security engine,
/// reactive trigger streams, automated threat scan dispatches, and security posture updates.
class BackgroundSecurityRepository {
  final IBackgroundTriggerService triggerService;
  final IThreatScannerService threatScannerService;
  final ILocationPlatformService? locationService;
  final DeviceRepository? deviceRepository;

  final StreamController<ThreatReport> _threatReportController =
      StreamController<ThreatReport>.broadcast();
  final List<SecurityTriggerEvent> _eventHistory = [];

  StreamSubscription<SecurityTriggerEvent>? _triggerSubscription;
  ThreatReport? _latestThreatReport;
  bool _isMonitoringActive = false;

  BackgroundSecurityRepository({
    required this.triggerService,
    required this.threatScannerService,
    this.locationService,
    this.deviceRepository,
  });

  /// Reactive stream of threat scan reports produced automatically or on-demand.
  Stream<ThreatReport> get threatReportStream => _threatReportController.stream;

  /// Reactive stream of security trigger events.
  Stream<SecurityTriggerEvent> get triggerStream => triggerService.triggerStream;

  /// Latest completed threat scan report.
  ThreatReport? get latestThreatReport => _latestThreatReport;

  /// History of received trigger events (bounded to last 100 entries to prevent memory leaks).
  List<SecurityTriggerEvent> get eventHistory =>
      List.unmodifiable(_eventHistory);

  /// Whether the background monitoring engine is active.
  bool get isMonitoringActive => _isMonitoringActive;

  /// Activates event-driven background monitoring and reactive event handling.
  Future<void> startBackgroundMonitoring() async {
    if (_isMonitoringActive) return;
    _isMonitoringActive = true;

    await triggerService.registerEventTriggers();

    _triggerSubscription = triggerService.triggerStream.listen(_handleTriggerEvent);
  }

  /// Deactivates background monitoring.
  Future<void> stopBackgroundMonitoring() async {
    _isMonitoringActive = false;
    await _triggerSubscription?.cancel();
    _triggerSubscription = null;
    await triggerService.unregisterEventTriggers();
  }

  /// Handles incoming reactive trigger events without any blocking while-sleep loops.
  Future<void> _handleTriggerEvent(SecurityTriggerEvent event) async {
    // Record in bounded event history
    if (_eventHistory.length >= 100) {
      _eventHistory.removeAt(0);
    }
    _eventHistory.add(event);

    // If event is flagged as suspicious, immediately execute security check and dispatch adaptive scan
    if (event.isSuspicious) {
      await triggerService.executeSecurityCheck(event);
      await dispatchThreatScan();
    }

    // If event contains location update, sync with device repository if available
    if (event.type == TriggerEventType.significantLocation &&
        deviceRepository != null) {
      final lat = event.payload['latitude'];
      final lng = event.payload['longitude'];
      if (lat != null && lng != null) {
        try {
          await deviceRepository!.updateTrackingStatus({
            'lastKnownCoordinates': {'lat': lat, 'lng': lng},
            'lastLocationTimestamp': event.timestamp.toIso8601String(),
          });
        } catch (_) {
          // Graceful handling of offline or non-blocking sync
        }
      }
    }
  }

  /// Dispatches an adaptive threat scan scaled to the device capability tier.
  Future<ThreatReport> dispatchThreatScan({CapabilityTier? overrideTier}) async {
    CapabilityTier tier = overrideTier ?? CapabilityTier.modern;

    if (overrideTier == null && deviceRepository != null) {
      try {
        final profile = await deviceRepository!.getOrCreateDeviceProfile(syncToCloud: false);
        tier = profile.capabilityTier;
      } catch (_) {
        tier = CapabilityTier.modern;
      }
    }

    final report = await threatScannerService.performScan(tier: tier);
    _latestThreatReport = report;

    if (!_threatReportController.isClosed) {
      _threatReportController.add(report);
    }

    return report;
  }

  /// Disposes repository subscriptions and streams.
  void dispose() {
    stopBackgroundMonitoring();
    _threatReportController.close();
  }
}
