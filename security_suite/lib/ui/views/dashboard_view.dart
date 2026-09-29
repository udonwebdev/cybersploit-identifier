import 'package:flutter/material.dart';

import '../viewmodels/dashboard_viewmodel.dart';
import 'widgets/posture_badge.dart';
import 'widgets/trigger_activity_tile.dart';

/// Screen displaying overall security posture, authenticated anti-theft tracking control,
/// and reactive background trigger event history.
class DashboardView extends StatelessWidget {
  final DashboardViewModel viewModel;

  const DashboardView({
    super.key,
    required this.viewModel,
  });

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: viewModel,
      builder: (context, _) {
        final state = viewModel.postureState;

        return Scaffold(
          appBar: AppBar(
            title: const Text('Security Posture'),
            actions: [
              IconButton(
                key: const Key('dashboard_refresh_button'),
                icon: const Icon(Icons.refresh),
                tooltip: 'Refresh Posture',
                onPressed: viewModel.isProcessing ? null : viewModel.refresh,
              ),
            ],
          ),
          body: RefreshIndicator(
            onRefresh: viewModel.refresh,
            child: ListView(
              padding: const EdgeInsets.all(16.0),
              children: [
                if (viewModel.isProcessing)
                  const Padding(
                    padding: EdgeInsets.only(bottom: 12.0),
                    child: LinearProgressIndicator(value: 0.5),
                  ),
                if (viewModel.errorMessage != null)
                  Container(
                    key: const Key('dashboard_error_banner'),
                    margin: const EdgeInsets.only(bottom: 16.0),
                    padding: const EdgeInsets.all(12.0),
                    decoration: BoxDecoration(
                      color: Colors.red.shade900.withValues(alpha: 0.2),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: Colors.redAccent),
                    ),
                    child: Row(
                      children: [
                        const Icon(Icons.error_outline, color: Colors.redAccent),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            viewModel.errorMessage!,
                            style: const TextStyle(color: Colors.redAccent),
                          ),
                        ),
                      ],
                    ),
                  ),

                // Posture Overview Card
                Card(
                  elevation: 2,
                  child: Padding(
                    padding: const EdgeInsets.all(16.0),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            Text(
                              'Overall Status',
                              style: Theme.of(context).textTheme.titleMedium,
                            ),
                            PostureBadge(level: state.overallPosture),
                          ],
                        ),
                        const SizedBox(height: 12),
                        Text(
                          state.statusSummary,
                          key: const Key('posture_summary_text'),
                          style: Theme.of(context).textTheme.bodyLarge,
                        ),
                        const SizedBox(height: 8),
                        Text(
                          'Last evaluated: ${state.lastEvaluatedAt.toLocal().toString().split('.').first}',
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),

                // Authenticated Permission Gate: Location Tracking Switch Tile
                Card(
                  elevation: 2,
                  child: SwitchListTile(
                    key: const Key('tracking_switch_tile'),
                    title: const Text('Anti-Theft Location Tracking'),
                    subtitle: Text(
                      state.isTrackingActive
                          ? 'Active • Event-driven significant motion updates'
                          : 'Inactive • Biometric challenge required to modify',
                    ),
                    value: state.isTrackingActive,
                    secondary: Icon(
                      state.isTrackingActive
                          ? Icons.location_searching
                          : Icons.location_disabled,
                      color: state.isTrackingActive ? Colors.green : Colors.grey,
                    ),
                    onChanged: viewModel.isProcessing
                        ? null
                        : (bool value) {
                            viewModel.toggleTrackingWithAuth(desiredState: value);
                          },
                  ),
                ),
                const SizedBox(height: 20),

                // Recent Trigger Activity Feed
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(
                      'Background Activity Feed',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    Text(
                      '${viewModel.recentEvents.length} events',
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ],
                ),
                const SizedBox(height: 8),

                if (viewModel.recentEvents.isEmpty)
                  const Card(
                    child: Padding(
                      padding: EdgeInsets.all(24.0),
                      child: Center(
                        child: Text(
                          'No security events recorded yet.\nBackground triggers operate reactively on OS events.',
                          textAlign: TextAlign.center,
                        ),
                      ),
                    ),
                  )
                else
                  ...viewModel.recentEvents.reversed.take(15).map(
                        (event) => TriggerActivityTile(event: event),
                      ),
              ],
            ),
          ),
        );
      },
    );
  }
}
