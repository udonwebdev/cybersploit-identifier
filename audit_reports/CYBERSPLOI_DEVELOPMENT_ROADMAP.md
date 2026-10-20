# CYBERSPLOI IDENTIFIER — DEVELOPMENT ROADMAP & BACKLOG

## P0: Critical Theft-Recovery Functionality (Must-Have for MVP)
1. **TASK-AUTH-01: Firebase Authentication & User Session Management**
   - Implement IAuthService and FirebaseAuthService (Email/Password & Google Sign-In).
   - Create Login & Registration screens before entering MainNavigationShell.
   - Ensure authenticated UID is linked to device enrollment.

2. **TASK-LOC-01: Live Native GPS & Background Location Tracking**
   - Add geolocator and integrate real hardware GPS coordinates into LocationPlatformService.
   - Configure Android background location permission (ACCESS_BACKGROUND_LOCATION) and Foreground Service notification.

3. **TASK-CLOUD-01: Multi-Device Ownership & Query Pipeline**
   - Update Firestore schema to associate devices with user accounts: /users/{uid}/devices/{deviceId}.
   - Update irestore.rules to permit users to query all devices where ownerId == request.auth.uid.

4. **TASK-REC-01: Secondary Device Recovery View & Map Display**
   - Add an " Enrolled Devices\ management view in the mobile app.
 - Add a map screen (using google_maps_flutter or Flutter Map/OSM) displaying the last known coordinates, timestamp, and accuracy circle of a selected missing device.

5. **TASK-WEB-01: Lightweight Web Recovery Portal**
 - Build a lightweight web recovery interface (using Flutter Web or Next.js) deployed to Firebase Hosting.
 - Allows users to log in from any browser, view their enrolled devices, and see the latest GPS waypoint on a map.

---

## P1: Security & Reliability Hardening
1. **TASK-FCM-01: Remote Command & Force-Update Push Pipeline**
 - Integrate irebase_messaging (FCM) to send silent high-priority data messages to the lost phone requesting an immediate GPS snapshot.
2. **TASK-SEC-01: Forensic Audit Trail Verification**
 - Enforce cryptographic HMAC signatures on location breadcrumbs before appending to Firestore /locations.

---

## P2: Advanced Threat Defense (Secondary)
1. Real-world threat heuristics feed for the Threat Scanner.
2. Encrypted Vault export/import capabilities.
