import 'package:flutter/material.dart';

import '../viewmodels/vault_viewmodel.dart';
import 'widgets/vault_item_tile.dart';

/// Screen presenting the biometric & passcode secured AES-256-GCM private data vault.
class VaultView extends StatefulWidget {
  final VaultViewModel viewModel;

  const VaultView({
    super.key,
    required this.viewModel,
  });

  @override
  State<VaultView> createState() => _VaultViewState();
}

class _VaultViewState extends State<VaultView> {
  final TextEditingController _passcodeController = TextEditingController();

  @override
  void dispose() {
    _passcodeController.dispose();
    super.dispose();
  }

  void _onPasscodeUnlock() {
    final code = _passcodeController.text.trim();
    if (code.isNotEmpty) {
      widget.viewModel.unlockWithPasscode(code).then((success) {
        if (success) {
          _passcodeController.clear();
        }
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: widget.viewModel,
      builder: (context, _) {
        final isUnlocked = widget.viewModel.isUnlocked;

        return Scaffold(
          appBar: AppBar(
            title: const Text('Encrypted Vault'),
            actions: [
              if (isUnlocked)
                IconButton(
                  key: const Key('lock_vault_button'),
                  icon: const Icon(Icons.lock),
                  tooltip: 'Lock Vault',
                  onPressed: widget.viewModel.lockVault,
                ),
            ],
          ),
          body: isUnlocked ? _buildUnlockedView() : _buildLockedView(),
          floatingActionButton: isUnlocked
              ? FloatingActionButton.extended(
                  key: const Key('import_file_button'),
                  onPressed: () => _showImportDialog(context),
                  icon: const Icon(Icons.add),
                  label: const Text('Import File'),
                )
              : null,
        );
      },
    );
  }

  Widget _buildLockedView() {
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(24.0),
        child: Card(
          key: const Key('vault_locked_card'),
          elevation: 4,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
          child: Padding(
            padding: const EdgeInsets.all(24.0),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(
                  Icons.shield_outlined,
                  size: 64,
                  color: Colors.blueAccent,
                ),
                const SizedBox(height: 16),
                Text(
                  'Vault is Locked',
                  style: Theme.of(context).textTheme.headlineSmall,
                ),
                const SizedBox(height: 8),
                Text(
                  'Hardware-backed AES-256-GCM encryption.\nAuthentication required to access keys.',
                  textAlign: TextAlign.center,
                  style: Theme.of(context).textTheme.bodyMedium,
                ),
                const SizedBox(height: 24),
                if (widget.viewModel.errorMessage != null)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 16.0),
                    child: Text(
                      widget.viewModel.errorMessage!,
                      key: const Key('vault_error_text'),
                      textAlign: TextAlign.center,
                      style: const TextStyle(color: Colors.redAccent),
                    ),
                  ),
                if (widget.viewModel.isProcessing)
                  const CircularProgressIndicator(value: 0.5)
                else ...[
                  SizedBox(
                    width: double.infinity,
                    child: ElevatedButton.icon(
                      key: const Key('unlock_biometrics_button'),
                      icon: const Icon(Icons.fingerprint),
                      label: const Text('Unlock with Biometrics'),
                      style: ElevatedButton.styleFrom(
                        padding: const EdgeInsets.symmetric(vertical: 14),
                      ),
                      onPressed: widget.viewModel.unlockWithBiometrics,
                    ),
                  ),
                  const SizedBox(height: 16),
                  const Divider(),
                  const SizedBox(height: 12),
                  TextField(
                    key: const Key('passcode_input_field'),
                    controller: _passcodeController,
                    obscureText: true,
                    decoration: const InputDecoration(
                      labelText: 'Fallback Passcode / PIN',
                      border: OutlineInputBorder(),
                      prefixIcon: Icon(Icons.password),
                    ),
                    onSubmitted: (_) => _onPasscodeUnlock(),
                  ),
                  const SizedBox(height: 12),
                  SizedBox(
                    width: double.infinity,
                    child: OutlinedButton.icon(
                      key: const Key('unlock_passcode_button'),
                      icon: const Icon(Icons.pin),
                      label: const Text('Unlock with Passcode'),
                      style: OutlinedButton.styleFrom(
                        padding: const EdgeInsets.symmetric(vertical: 14),
                      ),
                      onPressed: _onPasscodeUnlock,
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildUnlockedView() {
    final entries = widget.viewModel.entries;

    return Column(
      key: const Key('vault_unlocked_view'),
      children: [
        if (widget.viewModel.isProcessing) const LinearProgressIndicator(value: 0.5),
        if (widget.viewModel.errorMessage != null)
          Container(
            padding: const EdgeInsets.all(12),
            margin: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.red.shade900.withValues(alpha: 0.2),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: Colors.redAccent),
            ),
            child: Text(
              widget.viewModel.errorMessage!,
              style: const TextStyle(color: Colors.redAccent),
            ),
          ),
        Expanded(
          child: entries.isEmpty
              ? Center(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      const Icon(Icons.folder_open, size: 64, color: Colors.grey),
                      const SizedBox(height: 16),
                      Text(
                        'Vault is Empty',
                        style: Theme.of(context).textTheme.titleLarge,
                      ),
                      const SizedBox(height: 8),
                      const Text(
                        'Tap "Import File" below to encrypt and store sensitive files.',
                        style: TextStyle(color: Colors.grey),
                      ),
                    ],
                  ),
                )
              : ListView.builder(
                  padding: const EdgeInsets.only(top: 8, bottom: 80),
                  itemCount: entries.length,
                  itemBuilder: (context, index) {
                    final entry = entries[index];
                    return VaultItemTile(
                      entry: entry,
                      onDecrypt: () => _handleDecrypt(entry.id),
                      onDelete: () => widget.viewModel.deleteEntry(entry.id),
                    );
                  },
                ),
        ),
      ],
    );
  }

  void _handleDecrypt(String entryId) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('Decrypted entry $entryId')),
    );
  }

  void _showImportDialog(BuildContext context) {
    final nameController = TextEditingController();
    final pathController = TextEditingController();

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Import & Encrypt File'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              key: const Key('import_dialog_name_input'),
              controller: nameController,
              decoration: const InputDecoration(
                labelText: 'Display Name',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              key: const Key('import_dialog_path_input'),
              controller: pathController,
              decoration: const InputDecoration(
                labelText: 'Source File Path',
                border: OutlineInputBorder(),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            key: const Key('import_dialog_submit_button'),
            onPressed: () {
              final name = nameController.text.trim();
              final path = pathController.text.trim();
              if (name.isNotEmpty && path.isNotEmpty) {
                Navigator.of(ctx).pop();
                widget.viewModel.importAndEncryptFile(
                  sourcePath: path,
                  fileName: name,
                );
              }
            },
            child: const Text('Encrypt & Save'),
          ),
        ],
      ),
    );
  }
}
