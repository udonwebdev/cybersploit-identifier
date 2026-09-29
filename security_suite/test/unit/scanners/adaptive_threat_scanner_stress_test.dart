import 'dart:math';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:security_suite/core/constants/security_constants.dart';
import 'package:security_suite/data/models/device_profile.dart';
import 'package:security_suite/data/models/threat_report.dart';
import 'package:security_suite/data/services/implementations/adaptive_threat_scanner_service.dart';

void main() {
  group('Empirical Challenge: Adaptive Capability Tier Scaling Stress Harness', () {
    late AdaptiveThreatScannerService scanner;

    setUp(() {
      scanner = AdaptiveThreatScannerService();
    });

    test('Legacy Tier Stress (<35MB): 200 adversarial targets - strictly avoids heuristics & entropy', () async {
      // Generate 200 adversarial targets:
      // - 10 known signatures
      // - 90 banking trojans (sideloaded + accessibility + overlay)
      // - 50 SMS interceptors (sideloaded + receive_sms)
      // - 50 packed/high-entropy binaries
      final targets = <PackageScanTarget>[];

      // 10 Known signatures (using known hash from scanner)
      for (int i = 0; i < 10; i++) {
        targets.add(PackageScanTarget(
          identifier: 'com.malware.known$i',
          sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', // Trojan.Dropper.Generic
        ));
      }

      // 90 Banking trojan patterns
      for (int i = 0; i < 90; i++) {
        targets.add(PackageScanTarget(
          identifier: 'com.banktrojan.sample$i',
          sha256: 'unknownhash$i',
          isSideloaded: true,
          permissions: [
            'android.permission.BIND_ACCESSIBILITY_SERVICE',
            'android.permission.SYSTEM_ALERT_WINDOW',
          ],
        ));
      }

      // 50 SMS interceptors
      for (int i = 0; i < 50; i++) {
        targets.add(PackageScanTarget(
          identifier: 'com.smsinterceptor.sample$i',
          sha256: 'smshash$i',
          isSideloaded: true,
          permissions: ['android.permission.RECEIVE_SMS'],
        ));
      }

      // 50 High entropy targets
      for (int i = 0; i < 50; i++) {
        targets.add(PackageScanTarget(
          identifier: 'com.packedmalware.sample$i',
          sha256: 'entropyhash$i',
          entropy: 7.95,
        ));
      }

      for (final t in targets) {
        scanner.registerTarget(t);
      }

      // Run scan under Legacy Tier
      final report = await scanner.performScan(tier: CapabilityTier.legacy);

      expect(report.totalScanned, equals(200));
      expect(report.tier, equals(CapabilityTier.legacy));

      // In Legacy Tier, ONLY signature scans run. ZERO heuristics and ZERO entropy checks!
      expect(report.threatsFound, equals(10),
          reason: 'Legacy tier MUST skip deep heuristics and entropy to protect 2GB RAM budget');

      for (final threat in report.threatDetails) {
        expect(threat.detectionType, equals('signature'));
        expect(threat.severity, equals(ThreatSeverity.critical));
      }

      // Verify RSS memory cap constraint (< 35 MB)
      expect(report.memoryConsumptionMb, lessThanOrEqualTo(SecurityConstants.legacyRssMemoryCapMb.toDouble()),
          reason: 'Legacy tier memory footprint must not exceed 35MB cap');
    });

    test('Modern Tier Stress (<80MB): 200 adversarial targets - deep heuristics & entropy flag threats', () async {
      // Same 200 adversarial targets under Modern Tier
      final targets = <PackageScanTarget>[];

      // 10 Known signatures
      for (int i = 0; i < 10; i++) {
        targets.add(PackageScanTarget(
          identifier: 'com.malware.known$i',
          sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        ));
      }

      // 90 Banking trojans
      for (int i = 0; i < 90; i++) {
        targets.add(PackageScanTarget(
          identifier: 'com.banktrojan.sample$i',
          sha256: 'unknownhash$i',
          isSideloaded: true,
          permissions: [
            'android.permission.BIND_ACCESSIBILITY_SERVICE',
            'android.permission.SYSTEM_ALERT_WINDOW',
          ],
        ));
      }

      // 50 SMS interceptors
      for (int i = 0; i < 50; i++) {
        targets.add(PackageScanTarget(
          identifier: 'com.smsinterceptor.sample$i',
          sha256: 'smshash$i',
          isSideloaded: true,
          permissions: ['android.permission.RECEIVE_SMS'],
        ));
      }

      // 50 High entropy targets
      for (int i = 0; i < 50; i++) {
        targets.add(PackageScanTarget(
          identifier: 'com.packedmalware.sample$i',
          sha256: 'entropyhash$i',
          entropy: 7.95,
        ));
      }

      for (final t in targets) {
        scanner.registerTarget(t);
      }

      // Run scan under Modern Tier
      final report = await scanner.performScan(tier: CapabilityTier.modern);

      expect(report.totalScanned, equals(200));
      expect(report.tier, equals(CapabilityTier.modern));

      // In Modern Tier, ALL 200 malicious targets should be flagged:
      // 10 signatures + 90 banking trojans + 50 sms interceptors + 50 high entropy
      expect(report.threatsFound, equals(200),
          reason: 'Modern tier MUST execute deep heuristics, flagging all 200 threats');

      final sigCount = report.threatDetails.where((d) => d.detectionType == 'signature').length;
      final heuAccessCount = report.threatDetails.where((d) => d.detectionType == 'heuristic_accessibility').length;
      final heuSideloadCount = report.threatDetails.where((d) => d.detectionType == 'heuristic_sideload').length;
      final entropyCount = report.threatDetails.where((d) => d.detectionType == 'entropy').length;

      expect(sigCount, equals(10));
      expect(heuAccessCount, equals(90));
      expect(heuSideloadCount, equals(50));
      expect(entropyCount, equals(50));

      // Verify RSS memory cap constraint (< 80 MB)
      expect(report.memoryConsumptionMb, lessThanOrEqualTo(SecurityConstants.modernRssMemoryCapMb.toDouble()),
          reason: 'Modern tier memory footprint must not exceed 80MB cap');
    });

    test('Mathematical Shannon Entropy Precision Oracle', () {
      // Oracle 1: Single byte repeated -> zero entropy
      final zeroEntropyBytes = Uint8List(1024); // all 0x00
      expect(AdaptiveThreatScannerService.calculateShannonEntropy(zeroEntropyBytes), equals(0.0));

      // Oracle 2: Uniform distribution of all 256 bytes -> exact log2(256) = 8.0 bits
      final uniformBytes = Uint8List(256 * 10);
      for (int i = 0; i < uniformBytes.length; i++) {
        uniformBytes[i] = i % 256;
      }
      expect(AdaptiveThreatScannerService.calculateShannonEntropy(uniformBytes), equals(8.0));

      // Oracle 3: Binary with 2 equally probable values (0 and 1) -> exact log2(2) = 1.0 bit
      final twoValues = Uint8List(1000);
      for (int i = 0; i < twoValues.length; i++) {
        twoValues[i] = (i % 2);
      }
      expect(AdaptiveThreatScannerService.calculateShannonEntropy(twoValues), equals(1.0));

      // Oracle 4: Pseudo-random bytes generator
      final rng = Random(42);
      final randomBytes = Uint8List.fromList(List.generate(8192, (_) => rng.nextInt(256)));
      final entropy = AdaptiveThreatScannerService.calculateShannonEntropy(randomBytes);
      expect(entropy, greaterThan(7.9));
    });
  });
}
