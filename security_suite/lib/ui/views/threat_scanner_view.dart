import 'package:flutter/material.dart';

import '../../data/models/device_profile.dart';
import '../../data/models/threat_report.dart';
import '../viewmodels/threat_scanner_viewmodel.dart';

/// Screen presenting the adaptive malware scanner scaled to device capability tier.
class ThreatScannerView extends StatelessWidget {
  final ThreatScannerViewModel viewModel;

  const ThreatScannerView({
    super.key,
    required this.viewModel,
  });

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: viewModel,
      builder: (context, _) {
        final tier = viewModel.currentTier;
        final report = viewModel.latestReport;
        final isScanning = viewModel.isScanning;

        return Scaffold(
          appBar: AppBar(
            title: const Text('Adaptive Threat Scanner'),
          ),
          body: ListView(
            padding: const EdgeInsets.all(16.0),
            children: [
              // Capability Tier Badge Card
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
                            'Engine Configuration',
                            style: Theme.of(context).textTheme.titleMedium,
                          ),
                          Container(
                            key: const Key('capability_tier_badge'),
                            padding: const EdgeInsets.symmetric(
                              horizontal: 10,
                              vertical: 4,
                            ),
                            decoration: BoxDecoration(
                              color: tier == CapabilityTier.modern
                                  ? Colors.blue.shade900.withValues(alpha: 0.3)
                                  : Colors.orange.shade900.withValues(alpha: 0.3),
                              borderRadius: BorderRadius.circular(8),
                              border: Border.all(
                                color: tier == CapabilityTier.modern
                                    ? Colors.blueAccent
                                    : Colors.orangeAccent,
                              ),
                            ),
                            child: Text(
                              tier == CapabilityTier.modern
                                  ? 'MODERN (<80MB)'
                                  : 'LEGACY (<35MB)',
                              style: TextStyle(
                                color: tier == CapabilityTier.modern
                                    ? Colors.blueAccent
                                    : Colors.orangeAccent,
                                fontWeight: FontWeight.bold,
                                fontSize: 12,
                              ),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 8),
                      Text(
                        tier == CapabilityTier.modern
                          ? 'Modern Tier: Deep heuristics, Shannon entropy analysis, and permissions graph inspection.'
                          : 'Legacy Tier: Lean SHA-256 binary signature matching optimized for low memory footprint.',
                        style: Theme.of(context).textTheme.bodyMedium,
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),

              // Action Trigger Button
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  key: const Key('trigger_scan_button'),
                  icon: isScanning
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.radar),
                  label: Text(isScanning ? 'Scanning System...' : 'Trigger Adaptive Scan'),
                  style: ElevatedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 14),
                  ),
                  onPressed: isScanning ? null : () => viewModel.triggerScan(),
                ),
              ),
              const SizedBox(height: 16),

              if (isScanning) ...[
                const Center(
                  child: Padding(
                    padding: EdgeInsets.symmetric(vertical: 24.0),
                    child: Column(
                      children: [
                        CircularProgressIndicator(
                          key: Key('scan_progress_indicator'),
                        ),
                        SizedBox(height: 16),
                        Text('Inspecting installed packages and binary signatures...'),
                      ],
                    ),
                  ),
                ),
              ],

              if (viewModel.errorMessage != null)
                Container(
                  padding: const EdgeInsets.all(12),
                  margin: const EdgeInsets.only(bottom: 16),
                  decoration: BoxDecoration(
                    color: Colors.red.shade900.withValues(alpha: 0.2),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: Colors.redAccent),
                  ),
                  child: Text(
                    viewModel.errorMessage!,
                    style: const TextStyle(color: Colors.redAccent),
                  ),
                ),

              // Scan Report View
              if (report != null && !isScanning) ...[
                Card(
                  key: const Key('scan_report_card'),
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
                              report.hasThreats
                                  ? 'Threats Detected'
                                  : 'System Clean',
                              style: TextStyle(
                                fontSize: 18,
                                fontWeight: FontWeight.bold,
                                color: report.hasThreats
                                    ? Colors.redAccent
                                    : Colors.greenAccent,
                              ),
                            ),
                            Text(
                              '${report.totalScanned} scanned in ${report.memoryConsumptionMb.toStringAsFixed(1)} MB RAM',
                              style: Theme.of(context).textTheme.bodySmall,
                            ),
                          ],
                        ),
                        const SizedBox(height: 8),
                        Text(
                          'Scan tier: ${report.tier.name.toUpperCase()} • Timestamp: ${report.scanTimestamp.toLocal().toString().split('.').first}',
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),

                if (report.threatDetails.isEmpty)
                  const Card(
                    child: Padding(
                      padding: EdgeInsets.all(24.0),
                      child: Center(
                        child: Text(
                          'No malicious signatures or anomalous permission combinations detected.',
                          textAlign: TextAlign.center,
                        ),
                      ),
                    ),
                  )
                else ...[
                  Text(
                    'Identified Threat Findings (${report.threatDetails.length})',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 8),
                  ListView.builder(
                    key: const Key('threat_list'),
                    shrinkWrap: true,
                    physics: const NeverScrollableScrollPhysics(),
                    itemCount: report.threatDetails.length,
                    itemBuilder: (context, index) {
                      final threat = report.threatDetails[index];
                      return Card(
                        margin: const EdgeInsets.symmetric(vertical: 4),
                        child: ListTile(
                          leading: CircleAvatar(
                            backgroundColor: _getSeverityColor(threat.severity).withValues(alpha: 0.2),
                            child: Icon(
                              Icons.bug_report,
                              color: _getSeverityColor(threat.severity),
                            ),
                          ),
                          title: Text(
                            threat.target,
                            style: const TextStyle(fontWeight: FontWeight.bold),
                          ),
                          subtitle: Text(
                            '${threat.detectionType} • ${threat.description}',
                          ),
                          trailing: Container(
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                            decoration: BoxDecoration(
                              color: _getSeverityColor(threat.severity),
                              borderRadius: BorderRadius.circular(4),
                            ),
                            child: Text(
                              threat.severity.name.toUpperCase(),
                              style: const TextStyle(
                                color: Colors.white,
                                fontWeight: FontWeight.bold,
                                fontSize: 11,
                              ),
                            ),
                          ),
                        ),
                      );
                    },
                  ),
                ],
              ],
            ],
          ),
        );
      },
    );
  }

  Color _getSeverityColor(ThreatSeverity severity) {
    switch (severity) {
      case ThreatSeverity.critical:
        return Colors.red;
      case ThreatSeverity.high:
        return Colors.deepOrange;
      case ThreatSeverity.medium:
        return Colors.orange;
      case ThreatSeverity.low:
        return Colors.amber;
    }
  }
}
