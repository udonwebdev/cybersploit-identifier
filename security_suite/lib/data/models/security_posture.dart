import 'dart:convert';

/// High-level security posture health status.
enum SecurityLevel {
  /// All shields active, biometrics enrolled, location tracking secured.
  high,

  /// One or more non-critical protections disabled or permissions pending.
  degraded,

  /// Critical threat detected (tamper, revoked location tracking without auth, etc.).
  critical,
}

/// Reactive security posture state model reflecting real-time transparent security status.
class SecurityPostureState {
  final bool isTrackingActive;
  final bool hasLocationPermission;
  final bool isBiometricConfigured;
  final bool isTamperDetected;
  final SecurityLevel overallPosture;
  final String statusSummary;
  final DateTime lastEvaluatedAt;

  const SecurityPostureState({
    required this.isTrackingActive,
    required this.hasLocationPermission,
    required this.isBiometricConfigured,
    required this.isTamperDetected,
    required this.overallPosture,
    required this.statusSummary,
    required this.lastEvaluatedAt,
  });

  factory SecurityPostureState.initial() => SecurityPostureState(
        isTrackingActive: false,
        hasLocationPermission: false,
        isBiometricConfigured: false,
        isTamperDetected: false,
        overallPosture: SecurityLevel.degraded,
        statusSummary: 'Initializing security posture...',
        lastEvaluatedAt: DateTime.now(),
      );

  SecurityPostureState copyWith({
    bool? isTrackingActive,
    bool? hasLocationPermission,
    bool? isBiometricConfigured,
    bool? isTamperDetected,
    SecurityLevel? overallPosture,
    String? statusSummary,
    DateTime? lastEvaluatedAt,
  }) {
    return SecurityPostureState(
      isTrackingActive: isTrackingActive ?? this.isTrackingActive,
      hasLocationPermission:
          hasLocationPermission ?? this.hasLocationPermission,
      isBiometricConfigured:
          isBiometricConfigured ?? this.isBiometricConfigured,
      isTamperDetected: isTamperDetected ?? this.isTamperDetected,
      overallPosture: overallPosture ?? this.overallPosture,
      statusSummary: statusSummary ?? this.statusSummary,
      lastEvaluatedAt: lastEvaluatedAt ?? this.lastEvaluatedAt,
    );
  }

  Map<String, dynamic> toMap() {
    return {
      'isTrackingActive': isTrackingActive,
      'hasLocationPermission': hasLocationPermission,
      'isBiometricConfigured': isBiometricConfigured,
      'isTamperDetected': isTamperDetected,
      'overallPosture': overallPosture.name,
      'statusSummary': statusSummary,
      'lastEvaluatedAt': lastEvaluatedAt.toIso8601String(),
    };
  }

  factory SecurityPostureState.fromMap(Map<String, dynamic> map) {
    return SecurityPostureState(
      isTrackingActive: map['isTrackingActive'] as bool? ?? false,
      hasLocationPermission: map['hasLocationPermission'] as bool? ?? false,
      isBiometricConfigured: map['isBiometricConfigured'] as bool? ?? false,
      isTamperDetected: map['isTamperDetected'] as bool? ?? false,
      overallPosture: SecurityLevel.values.firstWhere(
        (e) => e.name == map['overallPosture'],
        orElse: () => SecurityLevel.degraded,
      ),
      statusSummary:
          map['statusSummary'] as String? ?? 'Status unknown',
      lastEvaluatedAt: map['lastEvaluatedAt'] != null
          ? DateTime.tryParse(map['lastEvaluatedAt'] as String) ??
              DateTime.now()
          : DateTime.now(),
    );
  }

  String toJson() => jsonEncode(toMap());

  factory SecurityPostureState.fromJson(String source) =>
      SecurityPostureState.fromMap(jsonDecode(source) as Map<String, dynamic>);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is SecurityPostureState &&
          runtimeType == other.runtimeType &&
          isTrackingActive == other.isTrackingActive &&
          hasLocationPermission == other.hasLocationPermission &&
          isBiometricConfigured == other.isBiometricConfigured &&
          isTamperDetected == other.isTamperDetected &&
          overallPosture == other.overallPosture &&
          statusSummary == other.statusSummary;

  @override
  int get hashCode => Object.hash(
        isTrackingActive,
        hasLocationPermission,
        isBiometricConfigured,
        isTamperDetected,
        overallPosture,
        statusSummary,
      );

  @override
  String toString() {
    return 'SecurityPostureState(posture: ${overallPosture.name}, tracking: $isTrackingActive, biometric: $isBiometricConfigured, tamper: $isTamperDetected)';
  }
}
