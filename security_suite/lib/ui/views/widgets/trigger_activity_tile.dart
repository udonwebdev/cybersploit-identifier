import 'package:flutter/material.dart';

import '../../../data/models/security_trigger_event.dart';

/// List tile representing an individual background security trigger event.
class TriggerActivityTile extends StatelessWidget {
  final SecurityTriggerEvent event;

  const TriggerActivityTile({
    super.key,
    required this.event,
  });

  @override
  Widget build(BuildContext context) {
    final IconData icon;
    final Color iconColor;

    switch (event.type) {
      case TriggerEventType.significantLocation:
        icon = Icons.location_on_outlined;
        iconColor = Colors.blue;
        break;
      case TriggerEventType.networkHandoff:
        icon = Icons.wifi_find;
        iconColor = Colors.teal;
        break;
      case TriggerEventType.powerState:
        icon = Icons.battery_charging_full;
        iconColor = Colors.orange;
        break;
      case TriggerEventType.scheduledJob:
        icon = Icons.schedule;
        iconColor = Colors.purple;
        break;
    }

    final formattedTime =
        '${event.timestamp.hour.toString().padLeft(2, '0')}:${event.timestamp.minute.toString().padLeft(2, '0')}:${event.timestamp.second.toString().padLeft(2, '0')}';

    return ListTile(
      leading: CircleAvatar(
        backgroundColor: event.isSuspicious
            ? Colors.red.shade900.withValues(alpha: 0.3)
            : iconColor.withValues(alpha: 0.15),
        child: Icon(
          event.isSuspicious ? Icons.warning_rounded : icon,
          color: event.isSuspicious ? Colors.redAccent : iconColor,
        ),
      ),
      title: Row(
        children: [
          Text(
            _formatEventType(event.type),
            style: const TextStyle(fontWeight: FontWeight.w600),
          ),
          if (event.isSuspicious) ...[
            const SizedBox(width: 8),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                color: Colors.redAccent,
                borderRadius: BorderRadius.circular(4),
              ),
              child: const Text(
                'SUSPICIOUS',
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 10,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
          ],
        ],
      ),
      subtitle: Text(
        'Recorded at $formattedTime • ${event.payload.keys.join(', ')}',
        style: Theme.of(context).textTheme.bodySmall,
      ),
      dense: true,
    );
  }

  String _formatEventType(TriggerEventType type) {
    switch (type) {
      case TriggerEventType.significantLocation:
        return 'Location Shift';
      case TriggerEventType.networkHandoff:
        return 'Network Handoff';
      case TriggerEventType.powerState:
        return 'Power Transition';
      case TriggerEventType.scheduledJob:
        return 'Scheduled Audit';
    }
  }
}
