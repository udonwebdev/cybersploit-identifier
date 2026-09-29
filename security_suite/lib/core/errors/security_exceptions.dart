/// Base class for all security suite exceptions.
abstract class SecuritySuiteException implements Exception {
  final String message;
  final dynamic cause;

  const SecuritySuiteException(this.message, [this.cause]);

  @override
  String toString() {
    if (cause != null) {
      return '$runtimeType: $message (Caused by: $cause)';
    }
    return '$runtimeType: $message';
  }
}

/// Generic security exception for file and vault errors.
class SecurityException extends SecuritySuiteException {
  const SecurityException(super.message, [super.cause]);
}

/// Thrown when device identity generation, provisioning, or retrieval fails.
class DeviceIdentityException extends SecuritySuiteException {
  const DeviceIdentityException(super.message, [super.cause]);
}

/// Thrown when hardware token derivation encounters invalid or corrupted attributes.
class HardwareTokenGenerationException extends SecuritySuiteException {
  const HardwareTokenGenerationException(super.message, [super.cause]);
}

/// Thrown when operations on KeyStore, Keychain, or encrypted storage fail.
class SecureStorageException extends SecuritySuiteException {
  const SecureStorageException(super.message, [super.cause]);
}

/// Thrown when Firestore or remote cloud profile sync encounters a network or schema failure.
class CloudSyncException extends SecuritySuiteException {
  const CloudSyncException(super.message, [super.cause]);
}

/// Thrown when local offline buffer enqueue or dequeue operations fail.
class OfflineQueueException extends SecuritySuiteException {
  const OfflineQueueException(super.message, [super.cause]);
}

/// Thrown when the target platform or OS version is unsupported.
class UnsupportedPlatformException extends SecuritySuiteException {
  const UnsupportedPlatformException(super.message, [super.cause]);
}

/// Thrown when an authenticated biometric or passcode challenge fails or is cancelled.
class AuthenticationRequiredException extends SecuritySuiteException {
  const AuthenticationRequiredException(super.message, [super.cause]);
}

/// Thrown when cryptographic tag verification fails or vault payload is corrupted.
class CryptographicIntegrityException extends SecuritySuiteException {
  const CryptographicIntegrityException(super.message, [super.cause]);
}
