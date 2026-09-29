import 'package:flutter/material.dart';

import '../viewmodels/settings_viewmodel.dart';

/// Screen displaying device identity, system metadata, capability tier,
/// and cloud profile synchronization status.
class SettingsView extends StatelessWidget {
  final SettingsViewModel viewModel;

  const SettingsView({
    super.key,
    required this.viewModel,
  });

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: viewModel,
      builder: (context, _) {
        final profile = viewModel.deviceProfile;
        final metadata = profile?.metadata;

        return Scaffold(
          appBar: AppBar(
            title: const Text('Device & Cloud Settings'),
          ),
          body: ListView(
            padding: const EdgeInsets.all(16.0),
            children: [
              if (viewModel.isSyncing)
                const Padding(
                  padding: EdgeInsets.only(bottom: 12.0),
                  child: LinearProgressIndicator(value: 0.5),
                ),

              // Device Identity Card
              Card(
                elevation: 2,
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Device Identity',
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                      const SizedBox(height: 8),
                      SelectableText(
                        profile?.deviceId ?? 'Generating app-scoped identifier...',
                        key: const Key('device_id_text'),
                        style: const TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 13,
                        ),
                      ),
                      const SizedBox(height: 12),
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          const Text('Capability Tier:'),
                          Text(
                            viewModel.capabilityTier.name.toUpperCase(),
                            style: const TextStyle(fontWeight: FontWeight.bold),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),

              // Hardware Metadata Card
              Card(
                elevation: 2,
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Hardware & Platform Metadata',
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                      const SizedBox(height: 12),
                      _buildInfoRow('OS Version', metadata?.osVersion ?? 'Unknown'),
                      _buildInfoRow('Platform', metadata?.platform ?? 'Unknown'),
                      _buildInfoRow('Model', metadata?.deviceModel ?? 'Unknown'),
                      _buildInfoRow('Manufacturer', metadata?.manufacturer ?? 'Unknown'),
                      _buildInfoRow('Architecture', metadata?.hardwareArchitecture ?? 'Unknown'),
                      _buildInfoRow('API Level', '${metadata?.apiLevel ?? 0}'),
                      _buildInfoRow('Physical Device', '${metadata?.isPhysical ?? true}'),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),

              // Cloud Profile Sync Card
              Card(
                elevation: 2,
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Cloud Firestore Synchronization',
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                      const SizedBox(height: 12),
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          const Text('Offline Queued Mutations:'),
                          Text(
                            '${viewModel.offlineQueueCount}',
                            key: const Key('offline_queue_text'),
                            style: const TextStyle(fontWeight: FontWeight.bold),
                          ),
                        ],
                      ),
                      if (viewModel.statusMessage != null) ...[
                        const SizedBox(height: 8),
                        Text(
                          viewModel.statusMessage!,
                          key: const Key('sync_status_text'),
                          style: TextStyle(
                            color: Theme.of(context).colorScheme.primary,
                            fontSize: 13,
                          ),
                        ),
                      ],
                      const SizedBox(height: 16),
                      Row(
                        children: [
                          Expanded(
                            child: ElevatedButton.icon(
                              key: const Key('manual_sync_button'),
                              icon: const Icon(Icons.cloud_upload_outlined),
                              label: const Text('Sync Now'),
                              onPressed: viewModel.isSyncing
                                  ? null
                                  : viewModel.triggerManualSync,
                            ),
                          ),
                          const SizedBox(width: 8),
                          Expanded(
                            child: OutlinedButton.icon(
                              key: const Key('flush_queue_button'),
                              icon: const Icon(Icons.refresh),
                              label: const Text('Flush Queue'),
                              onPressed: viewModel.isSyncing
                                  ? null
                                  : viewModel.flushOfflineQueue,
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildInfoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4.0),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label, style: const TextStyle(color: Colors.grey)),
          Text(value, style: const TextStyle(fontWeight: FontWeight.w500)),
        ],
      ),
    );
  }
}
