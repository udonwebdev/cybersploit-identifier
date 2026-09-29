import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto_pkg;
import '../../models/device_profile.dart';
import '../../models/threat_report.dart';
import '../contracts/i_threat_scanner_service.dart';

/// Simulated installed app or target file for fake threat scanning.
class SimulatedScanTarget {
  final String identifier;
  final String sha256;
  final List<String> permissions;
  final bool isSideloaded;
  final double entropy;
  final Uint8List? rawBytes;

  const SimulatedScanTarget({
    required this.identifier,
    required this.sha256,
    this.permissions = const [],
    this.isSideloaded = false,
    this.entropy = 4.5,
    this.rawBytes,
  });
}

/// In-memory fake implementation of [IThreatScannerService] for headless CI testing.
class FakeThreatScannerService implements IThreatScannerService {
  final Map<String, String> _knownSignatures = {
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855':
        'Trojan.Dropper.Generic',
    '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4':
        'Spyware.KeyLogger.Mobile',
    '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824':
        'Ransomware.Cryptor.FakeLocker',
  };

  final List<SimulatedScanTarget> _targets = [];
  double lastRecordedMemoryMb = 0.0;
  CapabilityTier? lastScanTier;

  void addKnownSignature(String sha256Hex, String malwareName) {
    _knownSignatures[sha256Hex.toLowerCase()] = malwareName;
  }

  void registerSimulatedTarget(SimulatedScanTarget target) {
    _targets.add(target);
  }

  void clearSimulatedTargets() {
    _targets.clear();
  }

  @override
  Future<ThreatDetail?> scanFileSignature({
    required String filePath,
    required Uint8List fileBytes,
  }) async {
    final hash = crypto_pkg.sha256.convert(fileBytes).toString().toLowerCase();
    if (_knownSignatures.containsKey(hash)) {
      final name = _knownSignatures[hash]!;
      return ThreatDetail(
        target: filePath,
        detectionType: 'signature',
        severity: ThreatSeverity.critical,
        description: 'Known malware signature detected: $name',
      );
    }
    return null;
  }

  @override
  Future<List<ThreatDetail>> evaluateHeuristics({
    required String identifier,
    required List<String> permissions,
    required bool isSideloaded,
    Uint8List? rawBytes,
  }) async {
    final threats = <ThreatDetail>[];

    final hasAccessibility =
        permissions.contains('android.permission.BIND_ACCESSIBILITY_SERVICE');
    final hasOverlay =
        permissions.contains('android.permission.SYSTEM_ALERT_WINDOW');

    // Accessibility + Overlay + Sideload: Banking Trojan / Overlay Hijacking pattern
    if (isSideloaded && hasAccessibility && hasOverlay) {
      threats.add(ThreatDetail(
        target: identifier,
        detectionType: 'heuristic_accessibility',
        severity: ThreatSeverity.high,
        description:
            'Heuristic anomaly: Sideloaded app with Accessibility and Overlay permissions',
      ));
    } else if (isSideloaded &&
        (permissions.contains('android.permission.RECEIVE_SMS') ||
            permissions.contains('android.permission.READ_CALL_LOG'))) {
      threats.add(ThreatDetail(
        target: identifier,
        detectionType: 'heuristic_sideload',
        severity: ThreatSeverity.medium,
        description:
            'Suspicious sideloaded app with credential harvesting SMS/Call permissions',
      ));
    }

    // High binary entropy check
    double entropy = 0.0;
    if (rawBytes != null && rawBytes.isNotEmpty) {
      entropy = _calculateShannonEntropy(rawBytes);
    }

    if (entropy > 7.8) {
      threats.add(ThreatDetail(
        target: identifier,
        detectionType: 'entropy',
        severity: ThreatSeverity.medium,
        description:
            'Heuristic anomaly: High binary entropy ($entropy) indicating packed/encrypted payload',
      ));
    }

    return threats;
  }

  @override
  Future<ThreatReport> performScan({required CapabilityTier tier}) async {
    lastScanTier = tier;
    final threats = <ThreatDetail>[];

    for (final target in _targets) {
      // 1. Signature scan (executed in both Legacy and Modern)
      if (_knownSignatures.containsKey(target.sha256.toLowerCase())) {
        threats.add(ThreatDetail(
          target: target.identifier,
          detectionType: 'signature',
          severity: ThreatSeverity.critical,
          description:
              'Known malware signature detected: ${_knownSignatures[target.sha256.toLowerCase()]}',
        ));
        continue;
      }

      // 2. Deep Heuristics (Strictly barred in Legacy tier to protect <35MB RSS memory cap)
      if (tier == CapabilityTier.modern) {
        final heuristicThreats = await evaluateHeuristics(
          identifier: target.identifier,
          permissions: target.permissions,
          isSideloaded: target.isSideloaded,
          rawBytes: target.rawBytes,
        );

        if (heuristicThreats.isNotEmpty) {
          threats.addAll(heuristicThreats);
        } else if (target.entropy > 7.8) {
          threats.add(ThreatDetail(
            target: target.identifier,
            detectionType: 'entropy',
            severity: ThreatSeverity.medium,
            description:
                'Heuristic anomaly: High binary entropy indicating encrypted/packed malware payload',
          ));
        }
      }
    }

    // Allocate simulated memory consumption conforming to tier boundaries
    // Legacy: strictly < 35MB (e.g. 18.5 MB)
    // Modern: strictly < 80MB (e.g. 52.0 MB)
    lastRecordedMemoryMb = (tier == CapabilityTier.legacy) ? 18.5 : 52.0;

    return ThreatReport(
      scanTimestamp: DateTime.now(),
      totalScanned: _targets.length,
      threatsFound: threats.length,
      tier: tier,
      memoryConsumptionMb: lastRecordedMemoryMb,
      threatDetails: threats,
    );
  }

  double _calculateShannonEntropy(Uint8List bytes) {
    if (bytes.isEmpty) return 0.0;
    final byteCounts = List<int>.filled(256, 0);
    for (final b in bytes) {
      byteCounts[b]++;
    }
    double entropy = 0.0;
    final total = bytes.length;
    for (final count in byteCounts) {
      if (count > 0) {
        final p = count / total;
        entropy -= p * (log(p) / ln2);
      }
    }
    return entropy;
  }
}
