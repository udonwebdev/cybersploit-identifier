# CYBERSPLOI IDENTIFIER — SECURITY FINDINGS & VULNERABILITY AUDIT

## Finding Matrix

| ID | Title | Severity | Location | Status |
| :--- | :--- | :---: | :--- | :---: |
| **SEC-01** | Anonymous / Unauthenticated Client Firestore Access Risk | **HIGH** | irestore.rules, service_locator.dart | Open |
| **SEC-02** | Stubbed Native GPS & Permission Delegation | **MEDIUM** | location_platform_service.dart | Open |
| **SEC-03** | Lack of Account-to-Device Multi-Tenancy Mapping | **HIGH** | cloud_profile_service.dart | Open |
| **SEC-04** | Missing Remote Revocation / Session Kill Switch | **MEDIUM** | Architectural | Open |

---

### SEC-01: Anonymous / Unauthenticated Client Firestore Access Risk
* **Severity**: **HIGH**
* **Location**: [irestore.rules](file:///c:/Users/ANON%20KFP/Documents/antigravity/epic-einstein/firestore.rules#L4-L12)
* **Description**: irestore.rules specifies isOwner(deviceId) { return request.auth != null && ... }. However, the client application currently initializes Firebase without performing a FirebaseAuth.instance.signInAnonymously() or user login. As a result, in a live environment without authenticated sessions, calls to Firestore from the app will fail with permission-denied.
* **Remediation**: Implement a foundational Auth service (FirebaseAuthService) that automatically establishes an anonymous session or signs the user in before initiating profile synchronization.

---

### SEC-02: Stubbed Native GPS & Permission Delegation
* **Severity**: **MEDIUM**
* **Location**: [location_platform_service.dart](file:///c:/Users/ANON%20KFP/Documents/antigravity/epic-einstein/security_suite/lib/data/services/implementations/location_platform_service.dart#L23-L27)
* **Description**: The method equestLocationPermission() hardcodes _hasPermission = true; without invoking the Android runtime permission dialog (ACCESS_FINE_LOCATION, ACCESS_BACKGROUND_LOCATION).
* **Remediation**: Integrate the official geolocator or permission_handler plugin to request true OS-level runtime permissions.

---

### SEC-03: Lack of Account-to-Device Multi-Tenancy Mapping
* **Severity**: **HIGH**
* **Location**: [cloud_profile_service.dart](file:///c:/Users/ANON%20KFP/Documents/antigravity/epic-einstein/security_suite/lib/data/services/implementations/cloud_profile_service.dart#L90-L105)
* **Description**: Documents are written strictly to top-level /devices/{deviceId}. If user Alice logs into a secondary device, she has no queryable link to discover that {deviceId} belongs to her account.
* **Remediation**: Add a user-device junction: /users/{userId}/devices/{deviceId} or index ownerUid on /devices/{deviceId} with appropriate query rules.
