# CYBERSPLOI IDENTIFIER — FEATURE STATUS CLASSIFICATION

This inventory evaluates every capability against evidence discovered in the codebase.

| Category | Feature | Status | Files | Evidence | Missing Work | Priority |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Auth** | User Registration / Login | **NOT IMPLEMENTED** | pubspec.yaml | irebase_auth dependency declared in pubspec, but no Auth UI, controllers, or user session logic exist in lib/. | Registration/Login views, AuthViewModel, Token/Session management. | **P0** |
| **Auth** | Borrowed Device Recovery Login | **NOT IMPLEMENTED** | None | No web portal or alternate device login workflow exists. | Cross-device authentication and recovery flows. | **P0** |
| **Device Mgmt** | Device Enrollment / ID | **VERIFIED WORKING** | device_identity_service.dart | 100% test coverage (device_identity_test.dart); persists hardware-anchored UUIDs. | None on client; requires user-account association in Firestore. | **P1** |
| **Theft Tracking** | On-Device Location Gate | **VERIFIED WORKING** | dashboard_view.dart, local_auth_biometric_service.dart | Verified via widget test (dashboard_view_test.dart); biometric prompt blocks toggle. | Live OS GPS background service (geolocator/native channels). | **P0** |
| **Theft Tracking** | Remote Location Requests | **NOT IMPLEMENTED** | None | No remote command listening mechanism (FCM push / Firestore listener) exists on client. | Push notification handler, Firestore command listener, background executor. | **P0** |
| **Theft Tracking** | Map Rendering | **NOT IMPLEMENTED** | None | No Google Maps or Mapbox package is present in pubspec.yaml or UI views. | Map widget integration, coordinate pinning, accuracy circle. | **P0** |
| **Theft Tracking** | Cloud Telemetry Sync | **VERIFIED WORKING** | cloud_profile_service.dart | Verified via unit tests; atomic upsert to /devices/{deviceId} and local encrypted offline queue. | End-to-end multi-device read authorization. | **P0** |
| **Recovery** | Web Recovery Portal | **NOT IMPLEMENTED** | web/ | Only default Flutter web boilerplate (web/index.html) exists. | Next.js/React or Flutter Web portal with authenticated map dashboard. | **P0** |
| **Vault** | AES-256-GCM Encrypted Vault | **VERIFIED WORKING** | es_gcm_vault_crypto_service.dart, ault_view.dart | Verified via es_gcm_vault_test.dart; AEAD encryption with random 96-bit IV. | None. Secondary feature fully operational. | **P2** |
| **Scanner** | Adaptive Threat Scanner | **VERIFIED WORKING** | daptive_threat_scanner_service.dart, 	hreat_scanner_view.dart | Verified via unit/widget tests; capability tier scaling between legacy and modern OS. | Real malware signature engine or threat feed integration. | **P2** |
