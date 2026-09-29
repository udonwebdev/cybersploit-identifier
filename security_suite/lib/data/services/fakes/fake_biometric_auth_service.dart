import '../contracts/i_biometric_auth_service.dart';

/// Configurable in-memory fake for biometric authentication.
/// Allows simulating biometric enrollment, prompt success/failure,
/// and lockout scenarios in headless CI environments.
class FakeBiometricAuthService implements IBiometricAuthService {
  bool isHardwareAvailable;
  bool isEnrolled;
  bool shouldSucceed;
  bool isLockedOut;
  bool isPasscodeSet;
  int failedAttempts = 0;
  int maxFailedAttemptsBeforeLockout;
  List<BiometricType> availableTypes;
  String? lastPromptReason;
  bool lastPromptBiometricOnly = false;
  bool wasStopCalled = false;

  FakeBiometricAuthService({
    this.isHardwareAvailable = true,
    this.isEnrolled = true,
    this.shouldSucceed = true,
    this.isLockedOut = false,
    this.isPasscodeSet = true,
    this.maxFailedAttemptsBeforeLockout = 5,
    List<BiometricType>? availableTypes,
  }) : availableTypes = availableTypes ??
            [
              BiometricType.fingerprint,
              BiometricType.face,
            ];

  @override
  Future<bool> canCheckBiometrics() async {
    return isHardwareAvailable && isEnrolled;
  }

  @override
  Future<bool> isDeviceSupported() async {
    return isHardwareAvailable;
  }

  @override
  Future<List<BiometricType>> getAvailableBiometrics() async {
    if (!isHardwareAvailable || !isEnrolled) {
      return [];
    }
    return List.unmodifiable(availableTypes);
  }

  @override
  Future<BiometricAuthResult> authenticate({
    required String localizedReason,
    bool biometricOnly = false,
  }) async {
    lastPromptReason = localizedReason;
    lastPromptBiometricOnly = biometricOnly;

    if (!isHardwareAvailable) {
      return const BiometricAuthResult.failure(
        message: 'Biometric hardware unavailable on this device.',
      );
    }

    if (!isEnrolled) {
      return const BiometricAuthResult.failure(
        message: 'No biometric credentials enrolled in system settings.',
        notEnrolled: true,
      );
    }

    if (isLockedOut) {
      return const BiometricAuthResult.failure(
        message: 'Biometrics locked out due to too many failed attempts.',
        lockedOut: true,
      );
    }

    if (!shouldSucceed) {
      failedAttempts++;
      if (failedAttempts >= maxFailedAttemptsBeforeLockout) {
        isLockedOut = true;
      }
      return const BiometricAuthResult.failure(
        message: 'Biometric authentication was rejected by sensor or user cancelled.',
      );
    }

    // Successful authentication resets failure counter
    failedAttempts = 0;
    return const BiometricAuthResult.success();
  }

  @override
  Future<bool> stopAuthentication() async {
    wasStopCalled = true;
    return true;
  }

  /// Resets simulated state back to default healthy enrolled conditions.
  void reset() {
    isHardwareAvailable = true;
    isEnrolled = true;
    shouldSucceed = true;
    isLockedOut = false;
    isPasscodeSet = true;
    failedAttempts = 0;
    lastPromptReason = null;
    lastPromptBiometricOnly = false;
    wasStopCalled = false;
  }
}
