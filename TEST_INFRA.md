# Test Infrastructure Specification: Lightweight Security Suite

**Document Reference**: TEST-INFRA-SEC-2026  
**Target Environment**: Headless CI / Local Developer Environment (Windows, macOS, Linux)  
**Supported Platforms Simulated**: Android 8.0 - 9.0 (Legacy Tier), Android 10+ (Modern Tier), iOS 14.0+ (Sandboxed Tier)  
**Framework**: Flutter 3.47+ / Dart 3.13+  

---

## 1. Test Philosophy & Design Principles

The Lightweight Event-Driven Cross-Platform Security Suite operates under high-assurance security, performance, and privacy requirements. The testing infrastructure is governed by five foundational axioms:

1. **Deterministic Opaque-Box Validation**:
   Tests interact with services, repositories, and ViewModels exclusively through documented public API boundaries and interface contracts. Tests never manipulate private internal state, guaranteeing zero facade implementations.
2. **100% Headless Isolation**:
   Mobile platform services (`local_auth`, `flutter_secure_storage`, `connectivity_plus`, `geolocator`, `workmanager`) depend on OS-level platform channels that are unavailable in CI or non-mobile host environments. The test infrastructure provides high-fidelity, in-memory simulated platform drivers that emulate real-world hardware, biometrics, power state transitions, network interfaces, and encrypted filesystems with zero native binary or emulator overhead.
3. **Cryptographic Rigor**:
   AES-256-GCM verification is backed by real mathematical authentication tag checks, random IV generation, and tamper-resistance assertions. Every test validating encryption exercises real cryptography (`package:cryptography` / standard cryptographic primitives).
4. **Zero-Tolerance for Flaky Background Polling**:
   Background triggers, network handoffs, battery shifts, and location events are tested through reactive Dart streams and event schedulers. No test relies on non-deterministic `sleep()` delays or arbitrary timing windows.
5. **Multi-Tier Quality Gate**:
   Validation is organized into four hierarchical tiers:
   - **Tier 1 (Feature Coverage)**: Direct behavioral verification of features F1 through F19 (minimum 5 tests per feature).
   - **Tier 2 (Boundary & Corner Cases)**: Malformed packets, empty inputs, truncated payloads, corrupt ciphertexts, expired tokens, revoked permissions, and rapid flapping.
   - **Tier 3 (Cross-Feature Combinations)**: Multi-system interactions (e.g., biometric auth gate combined with network handoff during active vault write; capability scaling under low battery).
   - **Tier 4 (Real-World Application Scenarios)**: Complex lifecycle workflows simulating anti-theft tracking, device theft handoff, offline encrypted vault management, and heuristic malware sweeps under OS memory pressure.

---

## 2. Feature Inventory (F1 – F20)

| ID | Feature Name | Description | Target Milestone | Primary Interface / Component |
|---|---|---|---|---|
| **F1** | Privacy-Preserving Device Identity | Generation and persistent storage of non-resettable-resistant, app-scoped hardware-anchored device ID compliant with Android 8+ and iOS policies | M1 | `IDeviceIdentityService`, `DeviceRepository` |
| **F2** | Hardware & OS Metadata Aggregator | Non-privileged collection of device brand, model, OS version, API level, architecture, and security patch levels | M1 | `IDeviceIdentityService`, `DeviceMetadata` |
| **F3** | Secure Cloud Firestore Profile Provisioning | Atomic profile upsert and offline queueing to Cloud Firestore with PII sanitization and sync status streaming | M1 | `ICloudProfileService`, `SyncStatus` |
| **F4** | Event-Driven Background Trigger Engine | Platform background job coordination without continuous while-sleep polling | M3 | `IBackgroundTriggerService`, `BackgroundSecurityRepository` |
| **F5** | Reactive Connectivity & Network Handoff Trigger | Instantaneous reaction to Wi-Fi/Cellular/Ethernet/None transitions with debounce & perimeter check | M3 | `IConnectivityService`, `SecurityTriggerEvent` |
| **F6** | Power & Battery State Trigger | Event listener for AC/battery toggles, low power thresholds, and thermal mitigation | M3 | `IPowerTriggerService`, `BatteryState` |
| **F7** | Significant Location Change Trigger | Low-power cell tower/motion handoff location tracking without continuous high-frequency GPS | M3 | `ILocationPlatformService`, `GeoPosition` |
| **F8** | AES-256-GCM Cryptographic Vault Core | Pure Dart + native AEAD authenticated cipher producing 12-byte random nonces and 128-bit authentication tags | M2 | `IVaultCryptoService` |
| **F9** | Tamper-Evident Binary Container | 5-part binary format `[Magic:4B][Version:1B][Nonce:12B][Tag:16B][Ciphertext:NB]` with strict tag validation | M2 | `EncryptedVaultPayload`, `IVaultCryptoService` |
| **F10** | Hardware-Backed Key Derivation & Storage | KeyStore/Keychain master key generation, wrapping, and secure persistence via secure storage | M2 | `ISecureStorageService`, `VaultRepository` |
| **F11** | Multi-Factor Biometric Adaptor | Biometric challenge gate supporting Face ID, Touch ID, and BiometricPrompt with sticky auth | M2 | `IBiometricAuthService`, `BiometricAuthResult` |
| **F12** | Fallback Passcode Key Derivation | PBKDF2/Argon2id key derivation with cryptographic salt for biometric lockout resilience | M2 | `IVaultCryptoService`, `VaultRepository` |
| **F13** | Vault File Management & Secure Shredding | Encrypted file read/write, directory indexing, and zero-fill memory buffer shredding | M2 | `IVaultRepository`, `VaultEntry` |
| **F14** | Authenticated Permission Gatekeeping | Biometric/PIN challenge mandatory before toggling tracking or modifying security permissions | M4 | `ISecurityPostureRepository`, `DashboardViewModel` |
| **F15** | Real-Time Transparent Security Posture Tracking | Continuous `SecurityPostureState` stream, reactive UI health badges, and transparent notifications | M4 | `ISecurityPostureRepository`, `SecurityPostureState` |
| **F16** | Adaptive OS Capability Classifier | Dynamic classification of device into Legacy (<35MB RSS), Modern (<80MB RSS), or Sandboxed iOS tiers | M1, M3 | `ICapabilityClassifier`, `CapabilityTier` |
| **F17** | Lean Signature Anti-Malware Scanner | Fast SHA-256 signature/hash inspection for Legacy Tier memory budgets (<35MB) | M3 | `IThreatScannerService`, `ThreatReport` |
| **F18** | Deep Heuristic Behavioral Threat Scanner | Advanced permission combination, side-loading, and accessibility exploitation scanner for Modern Tier | M3 | `IThreatScannerService`, `ThreatReport` |
| **F19** | Clean MVVM Presentation Layer | ViewModels and reactive widgets for Dashboard, Vault, Threat Scanner, and Settings views | M4 | `DashboardViewModel`, `VaultViewModel`, `ThreatScannerViewModel` |
| **F20** | Opaque-Box E2E Test Suite | 4-Tier test suite executing in headless CI validating requirements R1-R5 and acceptance criteria | M-E2E, M5 | `E2ETestHarness`, Tiers 1-4 Test Suites |

---

## 3. Test Architecture & Harness Design

The E2E Test Harness (`test/e2e/harness/e2e_test_harness.dart`) serves as the central control plane for all headless integration tests.

```
┌────────────────────────────────────────────────────────────────────────┐
│                          E2E TEST HARNESS                              │
├────────────────────────────────────────────────────────────────────────┤
│  • Simulated Hardware & OS Environment (Android 8/10+, iOS)           │
│  • Simulated Hardware KeyStore / Keychain (Secure Storage Fake)        │
│  • Simulated Biometric Hardware Driver (Face, Fingerprint, Lockout)    │
│  • Simulated Reactive Connectivity Stream (Wi-Fi, Cellular, Offline)   │
│  • Simulated Power & Battery State Controller                          │
│  • Simulated Significant Location Provider (GPS/Cell Tower)            │
│  • Simulated Cloud Firestore Database & Offline Sync Queue             │
│  • Simulated Package Manager / App Installation Registry (Scanners)   │
│  • Real AES-256-GCM Cryptographic Engine & Tamper Injector             │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ wires into
┌───────────────────────────────────▼────────────────────────────────────┐
│                    END-TO-END TEST SUITES (TIERS 1-4)                  │
├────────────────────────────────────────────────────────────────────────┤
│  • Tier 1: Feature Coverage (F1 - F19, >= 5 tests per feature)        │
│  • Tier 2: Boundary & Corner Cases (Tampering, Limits, Timeouts)       │
│  • Tier 3: Cross-Feature Combinations (Pairwise Interlocking)          │
│  • Tier 4: Real-World Scenarios (Theft Handoff, Offline Vault, Scans)  │
└────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Harness Capabilities
- **`harness.setPlatform(PlatformType.android, sdkLevel: 28)`**: Instantly configures the simulated environment to Android 8.1 Oreo (Legacy Tier) to verify strict capability gating.
- **`harness.setPlatform(PlatformType.android, sdkLevel: 34)`**: Instantly promotes the environment to Android 14 (Modern Tier) to verify deep heuristic scans.
- **`harness.simulateBiometricAuth(bool succeeds, {bool lockOut = false})`**: Controls biometric verification outcomes, including sensor hardware failure or enrollment absence.
- **`harness.emitConnectivity(ConnectivityType.wifi)`**: Emits reactive network state transitions through real broadcast streams.
- **`harness.emitBatteryLevel(int percent, {bool isCharging = false})`**: Triggers power events and thermal throttling logic.
- **`harness.emitLocationChange(double lat, double lng)`**: Fires geofence and significant location triggers.
- **`harness.injectCorruptVaultFile(String path, TamperMode mode)`**: Injects truncated headers, bit-flipped ciphertexts, or mismatched auth tags into the encrypted file store.

---

## 4. Real-World Scenario Definitions (Tier 4)

1. **Scenario 1: Anti-Theft Device Tracking Handoff**
   - Device transitions from Trusted Home Wi-Fi to Cellular to Offline.
   - Significant location change is detected.
   - Attacker attempts to disable background tracking via UI toggle.
   - Biometric prompt rejects the unauthorized attempt; tracking remains forced ON.
   - Telemetry queue accumulates encrypted beacons offline.
   - Connectivity returns via public Wi-Fi; offline telemetry queue is immediately and atomically synced to Firestore.

2. **Scenario 2: Offline Encrypted Vault Lifecycle & Attack Resilience**
   - User securely provisions master vault key via biometric enrollment.
   - Encrypts sensitive documents (photos/credentials) with AAD binding.
   - System goes completely offline; device restarts.
   - User unlocks vault with fallback PBKDF2 PIN.
   - Attacker modifies single byte in disk payload; decryption fails cleanly with `MacMismatchException` and zeroes plaintext memory buffers.

3. **Scenario 3: Adaptive Threat Detection Under Hostile Environment**
   - Low-tier legacy device (Android 8.0, 2GB RAM) installs suspicious APK with accessibility permissions.
   - Memory budget constraint is enforced (<35MB cap); deep graph traversal is suppressed.
   - Fast signature scanner flags SHA-256 match.
   - Security posture updates immediately to `Critical / Degraded`.
   - Notification bar updates posture badge.

---

## 5. Coverage & Verification Thresholds

| Metric | Target Threshold | Validation Method |
|---|---|---|
| Feature Coverage (F1–F19) | 100% (>=5 tests per feature) | `flutter test test/e2e/tier1_features/` |
| Boundary & Corner Case Coverage | >=15 distinct boundary conditions | `flutter test test/e2e/tier2_boundaries/` |
| Cross-Feature Combination Coverage | >=10 cross-feature pairs | `flutter test test/e2e/tier3_combinations/` |
| Real-World Scenario Coverage | >=3 full lifecycle scenarios | `flutter test test/e2e/tier4_scenarios/` |
| Cryptographic Integrity Verification | 100% mathematical tag validation | AES-GCM cipher checks |
| Headless Execution Success Rate | 100% Pass (0 skips, 0 failures) | `flutter test test/e2e/` |
