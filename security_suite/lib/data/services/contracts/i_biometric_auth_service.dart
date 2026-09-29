/// Biometric credential type wrapper.
enum BiometricType {
  fingerprint,
  face,
  iris,
  weak,
  strong,
}

/// Result of a biometric authentication attempt.
class BiometricAuthResult {
  final bool isSuccess;
  final String? errorMessage;
  final bool isLockedOut;
  final bool isNotEnrolled;
  final bool isPasscodeNotSet;

  const BiometricAuthResult({
    required this.isSuccess,
    this.errorMessage,
    this.isLockedOut = false,
    this.isNotEnrolled = false,
    this.isPasscodeNotSet = false,
  });

  const BiometricAuthResult.success()
      : isSuccess = true,
        errorMessage = null,
        isLockedOut = false,
        isNotEnrolled = false,
        isPasscodeNotSet = false;

  const BiometricAuthResult.failure({
    required String message,
    bool lockedOut = false,
    bool notEnrolled = false,
    bool passcodeNotSet = false,
  })  : isSuccess = false,
        errorMessage = message,
        isLockedOut = lockedOut,
        isNotEnrolled = notEnrolled,
        isPasscodeNotSet = passcodeNotSet;
}

/// Abstract contract for biometric and device-level authentication.
abstract class IBiometricAuthService {
  /// Checks whether the device hardware is capable of checking biometrics.
  Future<bool> canCheckBiometrics();

  /// Checks whether biometric hardware is present and device security is supported.
  Future<bool> isDeviceSupported();

  /// Retrieves list of enrolled biometric types available on the device.
  Future<List<BiometricType>> getAvailableBiometrics();

  /// Prompts user for biometric authentication with a reason.
  /// If [biometricOnly] is true, disables OS PIN/password fallback in the platform prompt.
  Future<BiometricAuthResult> authenticate({
    required String localizedReason,
    bool biometricOnly = false,
  });

  /// Cancels any active authentication prompt.
  Future<bool> stopAuthentication();
}
