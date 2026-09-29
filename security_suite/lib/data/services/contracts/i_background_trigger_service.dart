import '../../models/security_trigger_event.dart';

/// Contract for event-driven background security engine.
///
/// Implementations MUST rely strictly on OS-native event streams and broadcast channels
/// (e.g. WorkManager/JobScheduler, connectivity_plus, battery state).
///
/// CRITICAL ARCHITECTURAL RULE:
/// Implementations MUST have ZERO unbounded while-sleep polling loops.
abstract class IBackgroundTriggerService {
  /// Registers event listeners for system triggers (network handoffs, power changes,
  /// significant location handoffs, and scheduled tasks).
  Future<void> registerEventTriggers();

  /// Unregisters all background triggers and releases platform resources.
  Future<void> unregisterEventTriggers();

  /// Reactive stream of security trigger events emitted when system state changes.
  Stream<SecurityTriggerEvent> get triggerStream;

  /// Executes an immediate security evaluation responding to a specific trigger event.
  Future<void> executeSecurityCheck(SecurityTriggerEvent trigger);
}
