# Project: Lightweight Event-Driven Cross-Platform Security Suite (Flutter & Firebase)

## Architecture
- Clean MVVM architecture (Views, ViewModels, Repositories, Domain Services, Platform Adaptors).
- Dependency Injection via `get_it` service locator at composition root (`setupServiceLocator()`).
- Reactive UI binding using `ChangeNotifier` and `ListenableBuilder` (zero code-generation overhead, ultra-low memory footprint).
- Pure Dart service abstraction contracts with complete in-memory test fakes for 100% CI headless testability without physical mobile hardware.
- Event-driven background engine leveraging OS background channels (`WorkManager` / `BGTaskScheduler`) and reactive streams (`connectivity_plus`), with strict prohibition of unbounded while-sleep polling loops.
- Authenticated AES-256-GCM cryptographic vault with tamper-evident binary container format `[Magic (4B) + Version (1B) + Nonce (12B) + Tag (16B) + Ciphertext (NB)]`.
- Dual-tier authentication gate (Platform Biometrics `local_auth` + Salted PBKDF2/Argon2id Passcode fallback).
- Adaptive capability scaling across Legacy Tier (Android 8.0-9.0, <35MB RSS) and Modern Tier (Android 10+, modern iOS, <80MB RSS).

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| F1 | Privacy-Preserving Device Identity | Generate & securely persist app-scoped hardware-anchored device ID compliant with Android 8+ & iOS restrictions | M1 | R1 |
| F2 | Hardware & OS Metadata Aggregator | Collect system model, OS version, SDK level, architecture, security patch level without privileged IDs | M1 | R1, R5 |
| F3 | Secure Cloud Firestore Profile Provisioning | Link device metadata to Firestore document with atomic upsert, offline queue, and privacy sanitization | M1 | R1 |
| F4 | Event-Driven Background Trigger Engine | Native background task scheduling (WorkManager/BGTasks) triggered on OS events with zero while-sleep polling | M3 | R2 |
| F5 | Reactive Connectivity & Network Handoff Trigger | Stream-based trigger responding to Wi-Fi/Cellular/Ethernet/None transitions via connectivity_plus | M3 | R2 |
| F6 | Power & Battery State Trigger | Event listener for power connect/disconnect and critical battery threshold transitions | M3 | R2 |
| F7 | Significant Location Change Trigger | Event-driven location updates on significant motion/cell tower handoff without continuous GPS polling | M3 | R2 |
| F8 | AES-256-GCM Cryptographic Vault Core | Pure Dart + native AEAD cipher generating 128-bit authentication tags and unique 12-byte random nonces | M2 | R3 |
| F9 | Tamper-Evident Binary Container | 5-part binary format `[Magic:4B][Version:1B][Nonce:12B][Tag:16B][Ciphertext:NB]` with strict tag validation | M2 | R3 |
| F10 | Hardware-Backed Key Derivation & Storage | Secure master key generation and storage via KeyStore/Keychain (`flutter_secure_storage`) | M2 | R3 |
| F11 | Multi-Factor Biometric Adaptor | Adaptive biometric authentication (`local_auth`: Face ID, Touch ID, BiometricPrompt) | M2 | R3 |
| F12 | Fallback Passcode Key Derivation | PBKDF2/Argon2id key derivation with cryptographic salt for biometric failure resilience | M2 | R3 |
| F13 | Vault File Management & Secure Shredding | Encrypted file persistence, atomic read/write, and secure wiping of temp buffers | M2 | R3 |
| F14 | Authenticated Permission Gatekeeping | Biometric/PIN challenge mandatory before toggling tracking or modifying security permissions | M4 | R4 |
| F15 | Real-Time Transparent Security Posture Tracking | Continuous `SecurityPostureState` stream, reactive UI health badges, and transparent status notifications | M4 | R4 |
| F16 | Adaptive OS Capability Classifier | Dynamically partition device capabilities into Legacy (<35MB RSS) and Modern (<80MB RSS) tiers | M1, M3 | R5 |
| F17 | Lean Signature Anti-Malware Scanner | Fast signature/hash-based inspection designed for legacy Android 8-9 memory constraints | M3 | R5 |
| F18 | Deep Heuristic Behavioral Threat Scanner | Advanced permission combination, side-loading, and accessibility exploitation scanner for Modern Tier | M3 | R5 |
| F19 | Clean MVVM Presentation Layer | DashboardView, VaultView, ThreatScannerView, SettingsView with ViewModels and responsive widgets | M4 | R1-R5 |
| F20 | Opaque-Box E2E Test Suite | 4-Tier requirement-driven test suite (Features, Boundaries, Combinations, Real-World Workloads) | M-E2E, M5 | AC |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M-E2E | E2E Testing Track | Requirement-driven test suite infrastructure, Tier 1-4 test cases, mock platform environment, test runner | none | DONE |
| M1 | Core Scaffolding, DI & Device Identity | Project setup, DI registration, Device ID, Metadata, Firestore provisioning (F1, F2, F3, F16) | none | DONE |
| M2 | Biometric & Passcode AES-256-GCM Vault | AES-GCM container, KeyStore storage, local_auth, PIN fallback, secure file operations (F8-F13) | M1 | DONE |
| M3 | Event-Driven Background Engine & Threat Scanners | WorkManager/connectivity streams, triggers (network, power, location), adaptive threat scanners (F4-F7, F16-F18) | M1 | DONE |
| M4 | Authenticated Gatekeeping & MVVM UI | Biometric permission guard, SecurityPostureState, ViewModels, Dashboard, Vault, Scanner, Settings Views (F14, F15, F19) | M2, M3 | PLANNED |
| M5 | E2E Integration & Adversarial Hardening | Pass 100% of E2E test suite (Tiers 1-4) and execute Tier 5 adversarial coverage hardening | M-E2E, M4 | PLANNED |

## Code Layout
Target directory: `c:/Users/ANON KFP/Documents/antigravity/epic-einstein/security_suite/`
```
lib/
├── core/
│   ├── di/
│   │   └── service_locator.dart
│   ├── errors/
│   │   └── security_exceptions.dart
│   ├── network/
│   │   └── connectivity_service.dart
│   └── constants/
│       └── security_constants.dart
├── data/
│   ├── models/
│   │   ├── device_profile.dart
│   │   ├── vault_entry.dart
│   │   ├── threat_report.dart
│   │   └── security_posture.dart
│   ├── services/
│   │   ├── contracts/
│   │   │   ├── i_device_identity_service.dart
│   │   │   ├── i_cloud_profile_service.dart
│   │   │   ├── i_vault_crypto_service.dart
│   │   │   ├── i_biometric_auth_service.dart
│   │   │   ├── i_secure_storage_service.dart
│   │   │   ├── i_background_trigger_service.dart
│   │   │   ├── i_location_platform_service.dart
│   │   │   └── i_threat_scanner_service.dart
│   │   ├── fakes/
│   │   │   ├── fake_device_identity_service.dart
│   │   │   ├── fake_cloud_profile_service.dart
│   │   │   ├── fake_biometric_auth_service.dart
│   │   │   ├── fake_secure_storage_service.dart
│   │   │   ├── fake_background_trigger_service.dart
│   │   │   ├── fake_location_platform_service.dart
│   │   │   └── fake_threat_scanner_service.dart
│   │   └── implementations/
│   │       ├── device_identity_service.dart
│   │       ├── cloud_profile_service.dart
│   │       ├── aes_gcm_vault_crypto_service.dart
│   │       ├── local_auth_biometric_service.dart
│   │       ├── secure_storage_service.dart
│   │       ├── event_driven_background_service.dart
│   │       ├── adaptive_threat_scanner_service.dart
│   │       └── location_platform_service.dart
│   └── repositories/
│       ├── device_repository.dart
│       ├── vault_repository.dart
│       ├── background_security_repository.dart
│       └── security_posture_repository.dart
├── ui/
│   ├── viewmodels/
│   │   ├── dashboard_viewmodel.dart
│   │   ├── vault_viewmodel.dart
│   │   ├── threat_scanner_viewmodel.dart
│   │   └── settings_viewmodel.dart
│   └── views/
│       ├── dashboard_view.dart
│       ├── vault_view.dart
│       ├── threat_scanner_view.dart
│       ├── settings_view.dart
│       └── widgets/
│           ├── posture_badge.dart
│           ├── biometric_prompt_dialog.dart
│           ├── trigger_activity_tile.dart
│           └── vault_item_tile.dart
└── main.dart

test/
├── unit/
│   ├── crypto/
│   │   └── aes_gcm_vault_test.dart
│   ├── identity/
│   │   └── device_identity_test.dart
│   ├── background/
│   │   └── event_driven_triggers_test.dart
│   ├── scanners/
│   │   └── adaptive_threat_scanner_test.dart
│   └── viewmodels/
│       ├── dashboard_viewmodel_test.dart
│       ├── vault_viewmodel_test.dart
│       └── threat_scanner_viewmodel_test.dart
├── widget/
│   ├── dashboard_view_test.dart
│   ├── vault_view_test.dart
│   └── threat_scanner_view_test.dart
└── e2e/
    ├── harness/
    │   └── e2e_test_harness.dart
    ├── tier1_features/
    │   └── tier1_features_test.dart
    ├── tier2_boundaries/
    │   └── tier2_boundaries_test.dart
    ├── tier3_combinations/
    │   └── tier3_combinations_test.dart
    └── tier4_scenarios/
        └── tier4_real_world_test.dart
```

## Interface Contracts

### 1. `IDeviceIdentityService` ↔ `DeviceRepository`
```dart
abstract class IDeviceIdentityService {
  Future<String> getOrCreateAppScopedDeviceId();
  Future<DeviceMetadata> collectDeviceMetadata();
  CapabilityTier classifyCapabilityTier(DeviceMetadata metadata);
}
```

### 2. `ICloudProfileService` ↔ `DeviceRepository`
```dart
abstract class ICloudProfileService {
  Future<void> syncDeviceProfile(DeviceProfile profile);
  Future<DeviceProfile?> fetchDeviceProfile(String deviceId);
  Stream<SyncStatus> get syncStatusStream;
}
```

### 3. `IVaultCryptoService` ↔ `VaultRepository`
```dart
abstract class IVaultCryptoService {
  Future<Uint8List> encryptBytes({required Uint8List plaintext, required SecretKey masterKey, Uint8List? additionalData});
  Future<Uint8List> decryptBytes({required Uint8List encryptedContainer, required SecretKey masterKey, Uint8List? additionalData});
  Future<EncryptedVaultPayload> encryptFile({required String sourcePath, required String destinationPath, required SecretKey masterKey});
  Future<String> decryptFile({required String encryptedFilePath, required String decryptedDestinationPath, required SecretKey masterKey});
  Future<SecretKey> deriveKeyFromPasscode({required String passcode, required Uint8List salt});
  Future<SecretKey> generateMasterKey();
}
```

### 4. `IBiometricAuthService` ↔ `VaultRepository` & `DashboardViewModel`
```dart
abstract class IBiometricAuthService {
  Future<bool> canCheckBiometrics();
  Future<List<BiometricType>> getAvailableBiometrics();
  Future<BiometricAuthResult> authenticate({required String localizedReason, bool biometricOnly = false});
}
```

### 5. `IBackgroundTriggerService` ↔ `BackgroundSecurityRepository`
```dart
abstract class IBackgroundTriggerService {
  Future<void> registerEventTriggers();
  Future<void> unregisterEventTriggers();
  Stream<SecurityTriggerEvent> get triggerStream;
  Future<void> executeSecurityCheck(SecurityTriggerEvent trigger);
}
```

### 6. `ISecurityPostureRepository` ↔ `DashboardViewModel`
```dart
abstract class ISecurityPostureRepository {
  ValueListenable<SecurityPostureState> get posture;
  Future<bool> setLocationTrackingEnabled({required bool enabled, required bool isBiometricallyAuthenticated});
  Future<void> refreshPosture();
}
```
