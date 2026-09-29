import 'package:flutter/services.dart';
import 'package:local_auth/error_codes.dart' as auth_error;
import 'package:local_auth/local_auth.dart' as la;

import '../contracts/i_biometric_auth_service.dart';

/// Production implementation of IBiometricAuthService wrapping package:local_auth.
/// Maps platform exceptions (NotEnrolled, LockedOut, PasscodeNotSet) into typed results.
class LocalAuthBiometricService implements IBiometricAuthService {
  final la.LocalAuthentication _localAuth;

  LocalAuthBiometricService({la.LocalAuthentication? localAuth})
      : _localAuth = localAuth ?? la.LocalAuthentication();

  @override
  Future<bool> canCheckBiometrics() async {
    try {
      return await _localAuth.canCheckBiometrics;
    } on PlatformException {
      return false;
    }
  }

  @override
  Future<bool> isDeviceSupported() async {
    try {
      return await _localAuth.isDeviceSupported();
    } on PlatformException {
      return false;
    }
  }

  @override
  Future<List<BiometricType>> getAvailableBiometrics() async {
    try {
      final available = await _localAuth.getAvailableBiometrics();
      return available.map(_mapPlatformBiometric).toList();
    } on PlatformException {
      return [];
    }
  }

  @override
  Future<BiometricAuthResult> authenticate({
    required String localizedReason,
    bool biometricOnly = false,
  }) async {
    try {
      final authenticated = await _localAuth.authenticate(
        localizedReason: localizedReason,
        options: la.AuthenticationOptions(
          biometricOnly: biometricOnly,
          stickyAuth: true,
          useErrorDialogs: false,
          sensitiveTransaction: true,
        ),
      );

      if (authenticated) {
        return const BiometricAuthResult.success();
      } else {
        return const BiometricAuthResult.failure(
          message: 'Biometric verification rejected or cancelled by user.',
        );
      }
    } on PlatformException catch (e) {
      return _mapPlatformException(e);
    } catch (e) {
      return BiometricAuthResult.failure(message: 'Authentication error: $e');
    }
  }

  @override
  Future<bool> stopAuthentication() async {
    try {
      return await _localAuth.stopAuthentication();
    } on PlatformException {
      return false;
    }
  }

  BiometricType _mapPlatformBiometric(la.BiometricType type) {
    switch (type) {
      case la.BiometricType.face:
        return BiometricType.face;
      case la.BiometricType.fingerprint:
        return BiometricType.fingerprint;
      case la.BiometricType.iris:
        return BiometricType.iris;
      case la.BiometricType.weak:
        return BiometricType.weak;
      case la.BiometricType.strong:
        return BiometricType.strong;
    }
  }

  BiometricAuthResult _mapPlatformException(PlatformException e) {
    if (e.code == auth_error.notEnrolled) {
      return BiometricAuthResult.failure(
        message: 'No biometric credentials enrolled: ${e.message}',
        notEnrolled: true,
      );
    } else if (e.code == auth_error.lockedOut || e.code == auth_error.permanentlyLockedOut) {
      return BiometricAuthResult.failure(
        message: 'Biometrics locked out: ${e.message}',
        lockedOut: true,
      );
    } else if (e.code == auth_error.passcodeNotSet) {
      return BiometricAuthResult.failure(
        message: 'Device passcode/screen lock not configured: ${e.message}',
        passcodeNotSet: true,
      );
    } else if (e.code == auth_error.notAvailable) {
      return BiometricAuthResult.failure(
        message: 'Biometric authentication hardware not available: ${e.message}',
      );
    }
    return BiometricAuthResult.failure(
      message: 'Platform authentication error [${e.code}]: ${e.message}',
    );
  }
}
