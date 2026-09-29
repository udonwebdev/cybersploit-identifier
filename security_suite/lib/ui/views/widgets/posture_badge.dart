import 'package:flutter/material.dart';

import '../../../data/models/security_posture.dart';

/// Visual badge reflecting overall security posture with accessibility semantics.
class PostureBadge extends StatelessWidget {
  final SecurityLevel level;
  final VoidCallback? onTap;

  const PostureBadge({
    super.key,
    required this.level,
    this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final Color backgroundColor;
    final Color foregroundColor;
    final IconData icon;
    final String label;
    final String semanticDescription;

    switch (level) {
      case SecurityLevel.high:
        backgroundColor = Colors.green.shade900.withValues(alpha: 0.3);
        foregroundColor = Colors.greenAccent.shade400;
        icon = Icons.verified_user_rounded;
        label = 'HIGH SECURITY';
        semanticDescription = 'Security posture high: all protections active';
        break;
      case SecurityLevel.degraded:
        backgroundColor = Colors.amber.shade900.withValues(alpha: 0.3);
        foregroundColor = Colors.amberAccent.shade400;
        icon = Icons.warning_amber_rounded;
        label = 'DEGRADED';
        semanticDescription = 'Security posture degraded: some protections missing or disabled';
        break;
      case SecurityLevel.critical:
        backgroundColor = Colors.red.shade900.withValues(alpha: 0.3);
        foregroundColor = Colors.redAccent.shade400;
        icon = Icons.gpp_bad_rounded;
        label = 'CRITICAL ALERT';
        semanticDescription = 'Security posture critical: tamper or malware detected';
        break;
    }

    return Semantics(
      label: semanticDescription,
      button: onTap != null,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(12),
        child: Container(
          key: const Key('posture_badge'),
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
          decoration: BoxDecoration(
            color: backgroundColor,
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: foregroundColor.withValues(alpha: 0.6), width: 1.5),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(icon, color: foregroundColor, size: 20),
              const SizedBox(width: 8),
              Text(
                label,
                style: TextStyle(
                  color: foregroundColor,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 1.1,
                  fontSize: 13,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
