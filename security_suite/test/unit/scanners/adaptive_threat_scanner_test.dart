import 'dart:math';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:security_suite/core/constants/security_constants.dart';
import 'package:security_suite/data/models/device_profile.dart';
import 'package:security_suite/data/models/threat_report.dart';
import 'package:security_suite/data/services/fakes/fake_threat_scanner_service.dart';
import 'package:security_suite/data/services/implementations/adaptive_threat_scanner_service.dart';

void main() {
  group('ThreatReport & ThreatDetail Models & Serialization', () {
    test('constructs and serializes ThreatDetail properly', () {
      final now = DateTime.parse('2026-09-27T01:30:00.000Z');
      final detail = ThreatDetail(
        threatId: 'threat-1',
        target: 'com.malicious.keylogger',
        detectionType: 'signature',
        severity: ThreatSeverity.critical,
        description: 'Known keylogger detected',
        timestamp: now,
      );

      final map = detail.toMap();
      final fromMap = ThreatDetail.fromMap(map);

      expect(fromMap.threatId, equals('threat-1'));
      expect(fromMap.target, equals('com.malicious.keylogger'));
      expect(fromMap.detectionType, equals('signature'));
      expect(fromMap.severity, equals(ThreatSeverity.critical));
      expect(fromMap.description, equals('Known keylogger detected'));
      expect(fromMap.timestamp, equals(now));
      expect(fromMap, equals(detail));
    });

    test('constructs and serializes ThreatReport properly', () {
      final now = DateTime.parse('2026-09-27T01:30:00.000Z');
      final detail = ThreatDetail(
        threatId: 'threat-1',
        target: '/system/bin/exploit',
        detectionType: 'entropy',
        severity: ThreatSeverity.medium,
        description: 'High entropy payload',
        timestamp: now,
      );

      final report = ThreatReport(
        scanTimestamp: now,
        totalScanned: 15,
        threatsFound: 1,
        tier: CapabilityTier.modern,
        memoryConsumptionMb: 32.5,
        threatDetails: [detail],
      );

      expect(report.hasThreats, isTrue);

      final jsonStr = report.toJson();
      final reconstituted = ThreatReport.fromJson(jsonStr);

      expect(reconstituted.totalScanned, equals(15));
      expect(reconstituted.threatsFound, equals(1));
      expect(reconstituted.tier, equals(CapabilityTier.modern));
      expect(reconstituted.memoryConsumptionMb, equals(32.5));
      expect(reconstituted.threatDetails.length, equals(1));
      expect(reconstituted.threatDetails.first, equals(detail));
      expect(reconstituted, equals(report));
    });
  });

  group('Shannon Entropy Algorithm Verification', () {
    test('returns 0.0 for empty or completely uniform bytes', () {
      expect(AdaptiveThreatScannerService.calculateShannonEntropy(Uint8List(0)), equals(0.0));

      // All identical zeroes
      final allZeroes = Uint8List(100);
      expect(AdaptiveThreatScannerService.calculateShannonEntropy(allZeroes), equals(0.0));
    });

    test('returns moderate entropy (~3.0 to ~5.0) for standard ASCII text', () {
      final textBytes = Uint8List.fromList('The quick brown fox jumps over the lazy dog'.codeUnits);
      final entropy = AdaptiveThreatScannerService.calculateShannonEntropy(textBytes);

      expect(entropy, greaterThan(3.0));
      expect(entropy, lessThan(5.0));
    });

    test('returns high entropy (>7.8) for cryptographically pseudorandom bytes', () {
      final rng = Random(42);
      final randomBytes = Uint8List(4096);
      for (int i = 0; i < randomBytes.length; i++) {
        randomBytes[i] = rng.nextInt(256);
      }

      final entropy = AdaptiveThreatScannerService.calculateShannonEntropy(randomBytes);
      expect(entropy, greaterThan(7.8));
    });
  });

  group('FakeThreatScannerService Tests', () {
    late FakeThreatScannerService fakeScanner;

    setUp(() {
      fakeScanner = FakeThreatScannerService();
    });

    test('detects known malware signatures in simulated targets', () async {
      fakeScanner.registerSimulatedTarget(const SimulatedScanTarget(
        identifier: 'com.android.badware',
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      ));

      final report = await fakeScanner.performScan(tier: CapabilityTier.legacy);
      expect(report.totalScanned, equals(1));
      expect(report.threatsFound, equals(1));
      expect(report.threatDetails.first.detectionType, equals('signature'));
      expect(report.threatDetails.first.severity, equals(ThreatSeverity.critical));
      expect(report.memoryConsumptionMb, lessThanOrEqualTo(35.0));
    });

    test('skips deep heuristics on legacy tier even if target has banking trojan flags', () async {
      fakeScanner.registerSimulatedTarget(const SimulatedScanTarget(
        identifier: 'com.stealth.banking',
        sha256: 'clean_sha_123',
        permissions: [
          'android.permission.BIND_ACCESSIBILITY_SERVICE',
          'android.permission.SYSTEM_ALERT_WINDOW',
        ],
        isSideloaded: true,
      ));

      // Legacy Tier
      final legacyReport = await fakeScanner.performScan(tier: CapabilityTier.legacy);
      expect(legacyReport.threatsFound, equals(0));
      expect(legacyReport.memoryConsumptionMb, lessThan(35.0));

      // Modern Tier executes deep heuristics
      final modernReport = await fakeScanner.performScan(tier: CapabilityTier.modern);
      expect(modernReport.threatsFound, equals(1));
      expect(modernReport.threatDetails.first.detectionType, equals('heuristic_accessibility'));
      expect(modernReport.memoryConsumptionMb, lessThan(80.0));
    });
  });

  group('AdaptiveThreatScannerService Production Engine Tests', () {
    late AdaptiveThreatScannerService scanner;

    setUp(() {
      scanner = AdaptiveThreatScannerService();
    });

    test('detects known malware signatures via scanFileSignature', () async {
      // Empty input SHA-256 hash matches Trojan.Dropper.Generic
      final emptyBytes = Uint8List(0);
      final threat = await scanner.scanFileSignature(
        filePath: '/data/app/dropper.apk',
        fileBytes: emptyBytes,
      );

      expect(threat, isNotNull);
      expect(threat!.detectionType, equals('signature'));
      expect(threat.severity, equals(ThreatSeverity.critical));
      expect(threat.description, contains('Trojan.Dropper.Generic'));
    });

    test('returns null for benign file signature', () async {
      final benignBytes = Uint8List.fromList('Safe benign application payload'.codeUnits);
      final threat = await scanner.scanFileSignature(
        filePath: '/data/app/benign.apk',
        fileBytes: benignBytes,
      );

      expect(threat, isNull);
    });

    test('heuristics: detects banking trojan pattern (sideloaded + accessibility + overlay)', () async {
      final threats = await scanner.evaluateHeuristics(
        identifier: 'com.fake.bank.trojan',
        permissions: [
          'android.permission.BIND_ACCESSIBILITY_SERVICE',
          'android.permission.SYSTEM_ALERT_WINDOW',
        ],
        isSideloaded: true,
      );

      expect(threats.length, equals(1));
      expect(threats.first.detectionType, equals('heuristic_accessibility'));
      expect(threats.first.severity, equals(ThreatSeverity.high));
      expect(threats.first.description, contains('Banking Trojan'));
    });

    test('heuristics: detects suspicious sideloaded SMS interceptor', () async {
      final threats = await scanner.evaluateHeuristics(
        identifier: 'com.spy.smsinterceptor',
        permissions: [
          'android.permission.RECEIVE_SMS',
          'android.permission.READ_SMS',
        ],
        isSideloaded: true,
      );

      expect(threats.length, equals(1));
      expect(threats.first.detectionType, equals('heuristic_sideload'));
      expect(threats.first.severity, equals(ThreatSeverity.high));
    });

    test('heuristics: does not flag store-installed app with accessibility alone', () async {
      final threats = await scanner.evaluateHeuristics(
        identifier: 'com.google.android.marvin.talkback',
        permissions: ['android.permission.BIND_ACCESSIBILITY_SERVICE'],
        isSideloaded: false, // Legitimate store install
      );

      expect(threats, isEmpty);
    });

    test('heuristics: flags high binary entropy packed payload', () async {
      final rng = Random(99);
      final encryptedPayload = Uint8List(4096);
      for (int i = 0; i < encryptedPayload.length; i++) {
        encryptedPayload[i] = rng.nextInt(256);
      }

      final threats = await scanner.evaluateHeuristics(
        identifier: 'libpacked_payload.so',
        permissions: [],
        isSideloaded: false,
        rawBytes: encryptedPayload,
      );

      expect(threats.length, equals(1));
      expect(threats.first.detectionType, equals('entropy'));
      expect(threats.first.severity, equals(ThreatSeverity.medium));
      expect(threats.first.description, contains('High binary entropy'));
    });

    test('enforces Legacy capability tier: lean signature scan under <35MB budget, skipping deep heuristics', () async {
      // Register multiple targets: some signature hits, some heuristic candidates
      scanner.registerTarget(const PackageScanTarget(
        identifier: 'com.trojan.drop',
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      ));
      scanner.registerTarget(const PackageScanTarget(
        identifier: 'com.sideload.overlay',
        sha256: 'clean_sha_aaa',
        permissions: [
          'android.permission.BIND_ACCESSIBILITY_SERVICE',
          'android.permission.SYSTEM_ALERT_WINDOW',
        ],
        isSideloaded: true,
      ));
      scanner.registerTarget(const PackageScanTarget(
        identifier: 'com.clean.app',
        sha256: 'clean_sha_bbb',
      ));

      final report = await scanner.performScan(tier: CapabilityTier.legacy);

      expect(report.totalScanned, equals(3));
      // Only the signature hit is detected; heuristics are skipped
      expect(report.threatsFound, equals(1));
      expect(report.threatDetails.first.target, equals('com.trojan.drop'));
      expect(report.tier, equals(CapabilityTier.legacy));

      // Memory strictly capped under < 35MB
      expect(report.memoryConsumptionMb, lessThanOrEqualTo(SecurityConstants.legacyRssMemoryCapMb.toDouble()));
    });

    test('enforces Modern capability tier: runs both signature and deep heuristics under <80MB budget', () async {
      scanner.registerTarget(const PackageScanTarget(
        identifier: 'com.trojan.drop',
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      ));
      scanner.registerTarget(const PackageScanTarget(
        identifier: 'com.sideload.overlay',
        sha256: 'clean_sha_aaa',
        permissions: [
          'android.permission.BIND_ACCESSIBILITY_SERVICE',
          'android.permission.SYSTEM_ALERT_WINDOW',
        ],
        isSideloaded: true,
      ));
      scanner.registerTarget(const PackageScanTarget(
        identifier: 'com.clean.app',
        sha256: 'clean_sha_bbb',
      ));

      final report = await scanner.performScan(tier: CapabilityTier.modern);

      expect(report.totalScanned, equals(3));
      // Both signature hit and banking trojan heuristic are detected!
      expect(report.threatsFound, equals(2));
      expect(report.tier, equals(CapabilityTier.modern));

      final targets = report.threatDetails.map((t) => t.target).toList();
      expect(targets, contains('com.trojan.drop'));
      expect(targets, contains('com.sideload.overlay'));

      // Memory strictly capped under < 80MB
      expect(report.memoryConsumptionMb, lessThanOrEqualTo(SecurityConstants.modernRssMemoryCapMb.toDouble()));
    });
  });
}
