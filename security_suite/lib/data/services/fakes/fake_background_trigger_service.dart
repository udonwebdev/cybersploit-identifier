import 'dart:async';
import '../../models/security_trigger_event.dart';
import '../contracts/i_background_trigger_service.dart';

/// In-memory fake implementation of [IBackgroundTriggerService] for headless CI testing.
class FakeBackgroundTriggerService implements IBackgroundTriggerService {
  final StreamController<SecurityTriggerEvent> _triggerController =
      StreamController<SecurityTriggerEvent>.broadcast();

  bool isRegistered = false;
  final List<SecurityTriggerEvent> executedChecks = [];

  @override
  Future<void> registerEventTriggers() async {
    isRegistered = true;
  }

  @override
  Future<void> unregisterEventTriggers() async {
    isRegistered = false;
  }

  @override
  Stream<SecurityTriggerEvent> get triggerStream => _triggerController.stream;

  @override
  Future<void> executeSecurityCheck(SecurityTriggerEvent trigger) async {
    executedChecks.add(trigger);
  }

  /// Test helper: Emits a trigger event to all stream subscribers.
  void emitTrigger(SecurityTriggerEvent event) {
    if (!_triggerController.isClosed) {
      _triggerController.add(event);
    }
  }

  /// Closes the stream controller.
  void dispose() {
    _triggerController.close();
  }
}
