# CYBERSPLOI IDENTIFIER — DEVELOPER HANDOFF REPORT

## 1. Quick Context for Incoming Senior Engineer / AI Assistant
* **Repository**: https://github.com/udonwebdev/cybersploit-identifier.git (branch main).
* **Active Working Directory**: c:\Users\ANON KFP\Documents\antigravity\epic-einstein\security_suite
* **Current Application State**: The codebase is a working Flutter application featuring a 4-tab dashboard (Security Posture, Vault, Scanner, Settings). It compiles clean and has 291 passing automated tests.
* **The Core Gap**: The app currently operates strictly as an **on-device security utility** (local AES-256-GCM vault, biometric switch gate, adaptive threat scanner). **It cannot locate a missing device from another phone or browser today.** User accounts, multi-device listing, maps, remote push triggers, and the web recovery portal have not been built yet.

---

## 2. Verified Working Functionality
- **AES-256-GCM Vault**: Encrypts and decrypts files with 256-bit keys and random 96-bit IVs (lib/data/services/implementations/aes_gcm_vault_crypto_service.dart).
- **Biometric Gate**: Android BiometricPrompt and iOS LocalAuthentication gate on tracking switch (lib/data/services/implementations/local_auth_biometric_service.dart).
- **Cloud Firestore Client Upsert**: Serializes device metadata and pushes to /devices/{deviceId} with local encrypted queue fallback (lib/data/services/implementations/cloud_profile_service.dart).
- **Firestore Security Rules**: Deployed to Firebase project identifier-c91aa, enforcing device-owner isolation and append-only subcollections (irestore.rules).
- **Cybersploit Branding**: Branded neon-blue shield launcher icons (es/mipmap-*) and in-app AppBar header emblem.

---

## 3. Immediate Next Implementation Task
**TASK-AUTH-01: User Authentication & Device Ownership Linking**
1. Add an AuthService using irebase_auth.
2. Implement a simple login/register gate before entering MainNavigationShell.
3. In CloudProfileService.syncDeviceProfile(), attach ownerUid: FirebaseAuth.instance.currentUser?.uid to /devices/{deviceId}.
4. Modify irestore.rules to allow users to query /devices where esource.data.ownerUid == request.auth.uid.

---

## 4. Key Developer Commands

`powershell
# Navigate to project
cd  c:\Users\ANON KFP\Documents\antigravity\epic-einstein\security_suite

# Get dependencies
flutter pub get

# Run test suite
flutter test

# Run static analysis
dart analyze lib test

# Build Android Debug APK
flutter build apk --debug
`
