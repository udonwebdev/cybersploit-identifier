/// Constants for security suite configuration, storage keys, and thresholds.
class SecurityConstants {
  SecurityConstants._();

  // Storage Keys
  static const String keyAppScopedDeviceId = 'sec_app_scoped_device_id';
  static const String keyDeviceFingerprint = 'sec_device_fingerprint_token';
  static const String keyCapabilityTier = 'sec_capability_tier';
  static const String keyOfflineSyncQueue = 'sec_offline_sync_queue';
  static const String keyMasterVaultKey = 'sec_master_vault_key_raw';
  static const String keyPasscodeWrappedMasterKey = 'sec_passcode_wrapped_master_key';
  static const String keyPasscodeSalt = 'sec_passcode_salt';
  static const String keyBiometricEnrolled = 'sec_biometric_enrolled';

  // API Level Thresholds
  static const int androidOreoApiLevel = 26; // Android 8.0
  static const int androidPieApiLevel = 28; // Android 9.0
  static const int android10ApiLevel = 29; // Android 10.0 (Strict privacy boundary)
  static const int android14ApiLevel = 34; // Android 14.0

  // Memory Budget Caps (in Megabytes)
  static const int legacyRssMemoryCapMb = 35;
  static const int modernRssMemoryCapMb = 80;
  static const int iosBackgroundMemoryCapMb = 15;

  // Cryptographic Constants
  static const List<int> vaultMagicHeader = [0x56, 0x41, 0x55, 0x4C]; // 'VAUL'
  static const int vaultFormatVersion = 0x01;
  static const int aesKeyLengthBytes = 32; // 256 bits
  static const int gcmNonceLengthBytes = 12; // 96 bits
  static const int gcmTagLengthBytes = 16; // 128 bits
  static const int vaultHeaderLengthBytes = 33; // 4 + 1 + 12 + 16

  // Firestore Collections & Document Paths
  static const String firestoreDevicesCollection = 'devices';
  static const String firestoreAuditLogsCollection = 'audit_logs';

  // Rate Limiting & Timeouts
  static const int maxPinFailedAttemptsBeforeLockout = 3;
  static const Duration initialLockoutDuration = Duration(seconds: 30);
  static const Duration networkDebounceDuration = Duration(milliseconds: 2500);
}
