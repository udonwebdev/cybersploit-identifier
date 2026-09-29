import 'dart:convert';
import 'package:uuid/uuid.dart';

/// Supported background trigger event types conforming to R2.
enum TriggerEventType {
  networkHandoff,
  powerState,
  significantLocation,
  scheduledJob,
}

/// Represents an event that triggers security engine evaluation.
class SecurityTriggerEvent {
  final String triggerId;
  final TriggerEventType type;
  final DateTime timestamp;
  final Map<String, dynamic> payload;
  final bool isSuspicious;

  SecurityTriggerEvent({
    String? triggerId,
    required this.type,
    required this.timestamp,
    this.payload = const {},
    this.isSuspicious = false,
  }) : triggerId = triggerId ?? const Uuid().v4();

  SecurityTriggerEvent copyWith({
    String? triggerId,
    TriggerEventType? type,
    DateTime? timestamp,
    Map<String, dynamic>? payload,
    bool? isSuspicious,
  }) {
    return SecurityTriggerEvent(
      triggerId: triggerId ?? this.triggerId,
      type: type ?? this.type,
      timestamp: timestamp ?? this.timestamp,
      payload: payload ?? this.payload,
      isSuspicious: isSuspicious ?? this.isSuspicious,
    );
  }

  Map<String, dynamic> toMap() {
    return {
      'triggerId': triggerId,
      'type': type.name,
      'timestamp': timestamp.toIso8601String(),
      'payload': payload,
      'isSuspicious': isSuspicious,
    };
  }

  factory SecurityTriggerEvent.fromMap(Map<String, dynamic> map) {
    return SecurityTriggerEvent(
      triggerId: map['triggerId'] as String? ?? const Uuid().v4(),
      type: TriggerEventType.values.firstWhere(
        (t) => t.name == map['type'],
        orElse: () => TriggerEventType.scheduledJob,
      ),
      timestamp: map['timestamp'] != null
          ? DateTime.tryParse(map['timestamp'] as String) ?? DateTime.now()
          : DateTime.now(),
      payload: Map<String, dynamic>.from(
          map['payload'] as Map<String, dynamic>? ?? {}),
      isSuspicious: map['isSuspicious'] as bool? ?? false,
    );
  }

  String toJson() => jsonEncode(toMap());

  factory SecurityTriggerEvent.fromJson(String source) =>
      SecurityTriggerEvent.fromMap(jsonDecode(source) as Map<String, dynamic>);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is SecurityTriggerEvent &&
          runtimeType == other.runtimeType &&
          triggerId == other.triggerId &&
          type == other.type &&
          timestamp == other.timestamp &&
          isSuspicious == other.isSuspicious;

  @override
  int get hashCode => Object.hash(triggerId, type, timestamp, isSuspicious);

  @override
  String toString() {
    return 'SecurityTriggerEvent(id: $triggerId, type: ${type.name}, time: $timestamp, suspicious: $isSuspicious)';
  }
}
