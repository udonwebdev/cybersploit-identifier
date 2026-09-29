import 'package:get_it/get_it.dart';

import '../../data/models/device_profile.dart';
import '../../data/repositories/background_security_repository.dart';
import '../../data/repositories/device_repository.dart';
import '../../data/repositories/vault_repository.dart';
import '../../data/services/contracts/i_background_trigger_service.dart';
import '../../data/services/contracts/i_biometric_auth_service.dart';
import '../../data/services/contracts/i_cloud_profile_service.dart';
import '../../data/services/contracts/i_device_identity_service.dart';
import '../../data/services/contracts/i_location_platform_service.dart';
import '../../data/services/contracts/i_secure_storage_service.dart';
import '../../data/services/contracts/i_threat_scanner_service.dart';
import '../../data/services/contracts/i_vault_crypto_service.dart';
import '../../data/services/fakes/fake_background_trigger_service.dart';
import '../../data/services/fakes/fake_biometric_auth_service.dart';
import '../../data/services/fakes/fake_cloud_profile_service.dart';
import '../../data/services/fakes/fake_device_identity_service.dart';
import '../../data/services/fakes/fake_location_platform_service.dart';
import '../../data/services/fakes/fake_secure_storage_service.dart';
import '../../data/services/fakes/fake_threat_scanner_service.dart';
import '../../data/services/fakes/fake_vault_crypto_service.dart';
import '../../data/services/implementations/adaptive_threat_scanner_service.dart';
import '../../data/services/implementations/aes_gcm_vault_crypto_service.dart';
import '../../data/services/implementations/cloud_profile_service.dart';
import '../../data/services/implementations/device_identity_service.dart';
import '../../data/services/implementations/event_driven_background_service.dart';
import '../../data/services/implementations/local_auth_biometric_service.dart';
import '../../data/services/implementations/location_platform_service.dart';
import '../../data/services/implementations/secure_storage_service.dart';

import '../../data/repositories/security_posture_repository.dart';
import '../../ui/viewmodels/dashboard_viewmodel.dart';
import '../../ui/viewmodels/settings_viewmodel.dart';
import '../../ui/viewmodels/threat_scanner_viewmodel.dart';
import '../../ui/viewmodels/vault_viewmodel.dart';

final GetIt sl = GetIt.instance;

/// Configures dependency injection using GetIt.
/// Supports running with in-memory fakes for headless testing or production implementations.
Future<void> setupServiceLocator({
  bool useFakes = false,
  ISecureStorageService? customStorageService,
  IDeviceIdentityService? customIdentityService,
  ICloudProfileService? customCloudService,
  IVaultCryptoService? customCryptoService,
  IBiometricAuthService? customBiometricService,
  ILocationPlatformService? customLocationService,
  IBackgroundTriggerService? customBackgroundService,
  IThreatScannerService? customThreatScannerService,
  BackgroundSecurityRepository? customBackgroundSecurityRepository,
  ISecurityPostureRepository? customSecurityPostureRepository,
  DeviceMetadata? mockMetadata,
}) async {
  await resetServiceLocator();

  // 1. Secure Storage Service
  if (customStorageService != null) {
    sl.registerLazySingleton<ISecureStorageService>(() => customStorageService);
  } else if (useFakes) {
    sl.registerLazySingleton<ISecureStorageService>(
      () => FakeSecureStorageService(),
    );
  } else {
    sl.registerLazySingleton<ISecureStorageService>(
      () => SecureStorageService(),
    );
  }

  // 2. Device Identity Service
  if (customIdentityService != null) {
    sl.registerLazySingleton<IDeviceIdentityService>(() => customIdentityService);
  } else if (useFakes) {
    sl.registerLazySingleton<IDeviceIdentityService>(
      () => FakeDeviceIdentityService(
        storageService: sl<ISecureStorageService>(),
        mockMetadata: mockMetadata,
      ),
    );
  } else {
    sl.registerLazySingleton<IDeviceIdentityService>(
      () => DeviceIdentityService(
        secureStorage: sl<ISecureStorageService>(),
      ),
    );
  }

  // 3. Cloud Profile Service
  if (customCloudService != null) {
    sl.registerLazySingleton<ICloudProfileService>(() => customCloudService);
  } else if (useFakes) {
    sl.registerLazySingleton<ICloudProfileService>(
      () => FakeCloudProfileService(),
    );
  } else {
    sl.registerLazySingleton<ICloudProfileService>(
      () => CloudProfileService(
        secureStorage: sl<ISecureStorageService>(),
      ),
    );
  }

  // 4. Vault Crypto Service (AES-256-GCM)
  if (customCryptoService != null) {
    sl.registerLazySingleton<IVaultCryptoService>(() => customCryptoService);
  } else if (useFakes) {
    sl.registerLazySingleton<IVaultCryptoService>(
      () => FakeVaultCryptoService(),
    );
  } else {
    sl.registerLazySingleton<IVaultCryptoService>(
      () => AesGcmVaultCryptoService(),
    );
  }

  // 5. Biometric Auth Service
  if (customBiometricService != null) {
    sl.registerLazySingleton<IBiometricAuthService>(() => customBiometricService);
  } else if (useFakes) {
    sl.registerLazySingleton<IBiometricAuthService>(
      () => FakeBiometricAuthService(),
    );
  } else {
    sl.registerLazySingleton<IBiometricAuthService>(
      () => LocalAuthBiometricService(),
    );
  }

  // 6. Location Platform Service (Event-driven significant location)
  if (customLocationService != null) {
    sl.registerLazySingleton<ILocationPlatformService>(() => customLocationService);
  } else if (useFakes) {
    sl.registerLazySingleton<ILocationPlatformService>(
      () => FakeLocationPlatformService(),
    );
  } else {
    sl.registerLazySingleton<ILocationPlatformService>(
      () => LocationPlatformService(),
    );
  }

  // 7. Background Trigger Service (Zero while-sleep polling)
  if (customBackgroundService != null) {
    sl.registerLazySingleton<IBackgroundTriggerService>(
        () => customBackgroundService);
  } else if (useFakes) {
    sl.registerLazySingleton<IBackgroundTriggerService>(
      () => FakeBackgroundTriggerService(),
    );
  } else {
    sl.registerLazySingleton<IBackgroundTriggerService>(
      () => EventDrivenBackgroundService(
        locationService: sl<ILocationPlatformService>(),
      ),
    );
  }

  // 8. Adaptive Threat Scanner Service (Legacy <35MB vs Modern <80MB)
  if (customThreatScannerService != null) {
    sl.registerLazySingleton<IThreatScannerService>(
        () => customThreatScannerService);
  } else if (useFakes) {
    sl.registerLazySingleton<IThreatScannerService>(
      () => FakeThreatScannerService(),
    );
  } else {
    sl.registerLazySingleton<IThreatScannerService>(
      () => AdaptiveThreatScannerService(),
    );
  }

  // 9. Repositories
  sl.registerLazySingleton<DeviceRepository>(
    () => DeviceRepository(
      identityService: sl<IDeviceIdentityService>(),
      cloudProfileService: sl<ICloudProfileService>(),
      storageService: sl<ISecureStorageService>(),
    ),
  );

  sl.registerLazySingleton<VaultRepository>(
    () => VaultRepository(
      cryptoService: sl<IVaultCryptoService>(),
      biometricService: sl<IBiometricAuthService>(),
      storageService: sl<ISecureStorageService>(),
    ),
  );

  sl.registerLazySingleton<BackgroundSecurityRepository>(
    () =>
        customBackgroundSecurityRepository ??
        BackgroundSecurityRepository(
          triggerService: sl<IBackgroundTriggerService>(),
          threatScannerService: sl<IThreatScannerService>(),
          locationService: sl<ILocationPlatformService>(),
          deviceRepository: sl<DeviceRepository>(),
        ),
  );

  // 10. Security Posture Repository
  sl.registerLazySingleton<ISecurityPostureRepository>(
    () =>
        customSecurityPostureRepository ??
        SecurityPostureRepository(
          deviceRepository: sl<DeviceRepository>(),
          backgroundSecurityRepository: sl<BackgroundSecurityRepository>(),
          biometricService: sl<IBiometricAuthService>(),
          locationService: sl<ILocationPlatformService>(),
        ),
  );

  sl.registerLazySingleton<SecurityPostureRepository>(
    () => sl<ISecurityPostureRepository>() as SecurityPostureRepository,
  );

  // 11. ViewModels (Factory registration for clean lifecycle)
  sl.registerFactory<DashboardViewModel>(
    () => DashboardViewModel(
      postureRepository: sl<ISecurityPostureRepository>(),
      biometricService: sl<IBiometricAuthService>(),
      backgroundSecurityRepository: sl<BackgroundSecurityRepository>(),
    ),
  );

  sl.registerFactory<VaultViewModel>(
    () => VaultViewModel(
      vaultRepository: sl<VaultRepository>(),
    ),
  );

  sl.registerFactory<ThreatScannerViewModel>(
    () => ThreatScannerViewModel(
      backgroundSecurityRepository: sl<BackgroundSecurityRepository>(),
      deviceRepository: sl<DeviceRepository>(),
    ),
  );

  sl.registerFactory<SettingsViewModel>(
    () => SettingsViewModel(
      deviceRepository: sl<DeviceRepository>(),
    ),
  );
}

/// Clears all registrations in GetIt service locator.
Future<void> resetServiceLocator() async {
  await sl.reset();
}
