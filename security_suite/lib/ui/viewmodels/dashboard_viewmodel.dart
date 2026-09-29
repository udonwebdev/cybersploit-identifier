import 'dart:async';
import 'package:flutter/foundation.dart';

import '../../data/models/security_posture.dart';
import '../../data/models/security_trigger_event.dart';
import '../../data/repositories/background_security_repository.dart';
import '../../data/repositories/security_posture_repository.dart';
import '../../data/services/contracts/i_biometric_auth_service.dart';

/// ViewModel for the Dashboard screen.
/// Manages security posture visualization, authenticated tracking toggle, and trigger event feed.
/// Zero direct UI rendering logic.
class DashboardViewModel extends ChangeNotifier {
  final ISecurityPostureRepository postureRepository;
  final IBiometricAuthService biometricService;
  final BackgroundSecurityRepository backgroundSecurityRepository;

  bool _isProcessing = false;
  String? _errorMessage;
  StreamSubscription<SecurityTriggerEvent>? _triggerSubscription;

  DashboardViewModel({
    required this.postureRepository,
    required this.biometricService,
    required this.backgroundSecurityRepository,
  }) {
    postureRepository.posture.addListener(_onPostureChanged);
    _triggerSubscription =
        backgroundSecurityRepository.triggerStream.listen((_) {
      notifyListeners();
    });
  }

  void _onPostureChanged() {
    notifyListeners();
  }

  /// Current real-time security posture state.
  SecurityPostureState get postureState => postureRepository.posture.value;

  /// Whether an authentication or repository operation is underway.
  bool get isProcessing => _isProcessing;

  /// Human-readable error message from failed authentication or operations.
  String? get errorMessage => _errorMessage;

  /// Bounded history of recent background trigger events.
  List<SecurityTriggerEvent> get recentEvents =>
      backgroundSecurityRepository.eventHistory;

  /// Toggles location tracking gated behind biometric authentication.
  /// If authentication fails, cancelled, or locked out, records error and leaves state intact.
  Future<bool> toggleTrackingWithAuth({required bool desiredState}) async {
    _isProcessing = true;
    _errorMessage = null;
    notifyListeners();

    try {
      final reason = desiredState
          ? 'Authenticate to enable background anti-theft location tracking'
          : 'Authenticate to disable background anti-theft location tracking';

      final authResult = await biometricService.authenticate(
        localizedReason: reason,
        biometricOnly: false,
      );

      if (!authResult.isSuccess) {
        if (authResult.isLockedOut) {
          _errorMessage = 'Biometric authentication locked out. Please use device passcode.';
        } else {
          _errorMessage = authResult.errorMessage ?? 'Authentication cancelled or failed.';
        }
        _isProcessing = false;
        notifyListeners();
        return false;
      }

      // Biometrically authenticated -> update repository
      final success = await postureRepository.setLocationTrackingEnabled(
        enabled: desiredState,
        isBiometricallyAuthenticated: true,
      );

      _isProcessing = false;
      notifyListeners();
      return success;
    } catch (e) {
      _errorMessage = 'Failed to toggle location tracking: $e';
      _isProcessing = false;
      notifyListeners();
      return false;
    }
  }

  /// Manually triggers posture re-evaluation.
  Future<void> refresh() async {
    _isProcessing = true;
    _errorMessage = null;
    notifyListeners();

    try {
      await postureRepository.refreshPosture();
    } catch (e) {
      _errorMessage = 'Failed to refresh posture: $e';
    } finally {
      _isProcessing = false;
      notifyListeners();
    }
  }

  @override
  void dispose() {
    postureRepository.posture.removeListener(_onPostureChanged);
    _triggerSubscription?.cancel();
    super.dispose();
  }
}
