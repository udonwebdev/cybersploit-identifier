import 'dart:convert';
import 'package:uuid/uuid.dart';
import 'device_profile.dart';

/// Threat severity classifications.
enum ThreatSeverity {
  low,
  medium,
  high,
  critical,
}

/// Detailed metadata of a detected security threat or anomaly.
class ThreatDetail {
  final String threatId;
  final String target;
  final String detectionType;
  final ThreatSeverity severity;
  final String description;
  final DateTime timestamp;

  ThreatDetail({
    String? threatId,
    required this.target,
    required this.detectionType,
    required this.severity,
    required this.description,
    DateTime? timestamp,
  })  : threatId = threatId ?? const Uuid().v4(),
        timestamp = timestamp ?? DateTime.now();

  ThreatDetail copyWith({
    String? threatId,
    String? target,
    String? detectionType,
    ThreatSeverity? severity,
    String? description,
    DateTime? timestamp,
  }) {
    return ThreatDetail(
      threatId: threatId ?? this.threatId,
      target: target ?? this.target,
      detectionType: detectionType ?? this.detectionType,
      severity: severity ?? this.severity,
      description: description ?? this.description,
      timestamp: timestamp ?? this.timestamp,
    );
  }

  Map<String, dynamic> toMap() {
    return {
      'threatId': threatId,
      'target': target,
      'detectionType': detectionType,
      'severity': severity.name,
      'description': description,
      'timestamp': timestamp.toIso8601String(),
    };
  }

  factory ThreatDetail.fromMap(Map<String, dynamic> map) {
    return ThreatDetail(
      threatId: map['threatId'] as String? ?? const Uuid().v4(),
      target: map['target'] as String? ?? '',
      detectionType: map['detectionType'] as String? ?? 'unknown',
      severity: ThreatSeverity.values.firstWhere(
        (s) => s.name == map['severity'],
        orElse: () => ThreatSeverity.medium,
      ),
      description: map['description'] as String? ?? '',
      timestamp: map['timestamp'] != null
          ? DateTime.tryParse(map['timestamp'] as String) ?? DateTime.now()
          : DateTime.now(),
    );
  }

  String toJson() => jsonEncode(toMap());

  factory ThreatDetail.fromJson(String source) =>
      ThreatDetail.fromMap(jsonDecode(source) as Map<String, dynamic>);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is ThreatDetail &&
          runtimeType == other.runtimeType &&
          threatId == other.threatId &&
          target == other.target &&
          detectionType == other.detectionType &&
          severity == other.severity &&
          description == other.description;

  @override
  int get hashCode => Object.hash(
        threatId,
        target,
        detectionType,
        severity,
        description,
      );

  @override
  String toString() {
    return 'ThreatDetail(id: $threatId, target: $target, type: $detectionType, sev: ${severity.name})';
  }
}

/// Comprehensive report produced by threat scanning operations.
class ThreatReport {
  final DateTime scanTimestamp;
  final int totalScanned;
  final int threatsFound;
  final CapabilityTier tier;
  final double memoryConsumptionMb;
  final List<ThreatDetail> threatDetails;

  const ThreatReport({
    required this.scanTimestamp,
    required this.totalScanned,
    required this.threatsFound,
    required this.tier,
    required this.memoryConsumptionMb,
    required this.threatDetails,
  });

  bool get hasThreats => threatsFound > 0;

  ThreatReport copyWith({
    DateTime? scanTimestamp,
    int? totalScanned,
    int? threatsFound,
    CapabilityTier? tier,
    double? memoryConsumptionMb,
    List<ThreatDetail>? threatDetails,
  }) {
    return ThreatReport(
      scanTimestamp: scanTimestamp ?? this.scanTimestamp,
      totalScanned: totalScanned ?? this.totalScanned,
      threatsFound: threatsFound ?? this.threatsFound,
      tier: tier ?? this.tier,
      memoryConsumptionMb: memoryConsumptionMb ?? this.memoryConsumptionMb,
      threatDetails: threatDetails ?? this.threatDetails,
    );
  }

  Map<String, dynamic> toMap() {
    return {
      'scanTimestamp': scanTimestamp.toIso8601String(),
      'totalScanned': totalScanned,
      'threatsFound': threatsFound,
      'tier': tier.name,
      'memoryConsumptionMb': memoryConsumptionMb,
      'threatDetails': threatDetails.map((t) => t.toMap()).toList(),
    };
  }

  factory ThreatReport.fromMap(Map<String, dynamic> map) {
    final detailsList = (map['threatDetails'] as List<dynamic>?)
            ?.map((e) => ThreatDetail.fromMap(Map<String, dynamic>.from(e as Map)))
            .toList() ??
        <ThreatDetail>[];

    return ThreatReport(
      scanTimestamp: map['scanTimestamp'] != null
          ? DateTime.tryParse(map['scanTimestamp'] as String) ?? DateTime.now()
          : DateTime.now(),
      totalScanned: (map['totalScanned'] as num?)?.toInt() ?? 0,
      threatsFound: (map['threatsFound'] as num?)?.toInt() ?? detailsList.length,
      tier: CapabilityTier.values.firstWhere(
        (t) => t.name == map['tier'],
        orElse: () => CapabilityTier.legacy,
      ),
      memoryConsumptionMb:
          (map['memoryConsumptionMb'] as num?)?.toDouble() ?? 0.0,
      threatDetails: detailsList,
    );
  }

  String toJson() => jsonEncode(toMap());

  factory ThreatReport.fromJson(String source) =>
      ThreatReport.fromMap(jsonDecode(source) as Map<String, dynamic>);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is ThreatReport &&
          runtimeType == other.runtimeType &&
          scanTimestamp == other.scanTimestamp &&
          totalScanned == other.totalScanned &&
          threatsFound == other.threatsFound &&
          tier == other.tier &&
          memoryConsumptionMb == other.memoryConsumptionMb;

  @override
  int get hashCode => Object.hash(
        scanTimestamp,
        totalScanned,
        threatsFound,
        tier,
        memoryConsumptionMb,
      );

  @override
  String toString() {
    return 'ThreatReport(time: $scanTimestamp, scanned: $totalScanned, threats: $threatsFound, tier: ${tier.name}, mem: ${memoryConsumptionMb}MB)';
  }
}
