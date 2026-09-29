import 'dart:typed_data';
import '../../models/device_profile.dart';
import '../../models/threat_report.dart';

/// Contract for the adaptive anti-malware and threat scanning engine.
///
/// Implementations must adhere strictly to OS capability tiers:
/// - Legacy Tier (Android 8.0 - 9.0): Lean signature inspection under strict <35MB memory budget.
/// - Modern Tier (Android 10+, modern iOS): Full deep heuristics, permission combination analysis,
///   sideload detection, and entropy inspection within <80MB memory budget.
abstract class IThreatScannerService {
  /// Executes a system-wide or installed targets scan adapting to the given [tier].
  Future<ThreatReport> performScan({required CapabilityTier tier});

  /// Evaluates an individual file by comparing its cryptographic hash against
  /// known malicious signatures. Returns a [ThreatDetail] if a match is detected.
  Future<ThreatDetail?> scanFileSignature({
    required String filePath,
    required Uint8List fileBytes,
  });

  /// Performs deep behavioral and heuristic analysis for an app or package [identifier].
  ///
  /// Analyzes dangerous permission combinations (e.g. Accessibility + Overlay),
  /// installation origin (sideloaded), and binary entropy.
  Future<List<ThreatDetail>> evaluateHeuristics({
    required String identifier,
    required List<String> permissions,
    required bool isSideloaded,
    Uint8List? rawBytes,
  });
}
