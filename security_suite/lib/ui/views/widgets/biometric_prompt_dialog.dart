import 'package:flutter/material.dart';

/// Modal dialog for passcode authentication fallback when biometrics fail or are unavailable.
class BiometricPromptDialog extends StatefulWidget {
  final String title;
  final String description;
  final bool allowBiometricRetry;
  final VoidCallback? onBiometricRetry;

  const BiometricPromptDialog({
    super.key,
    this.title = 'Security Authentication',
    this.description = 'Enter your vault/device passcode to authenticate.',
    this.allowBiometricRetry = false,
    this.onBiometricRetry,
  });

  /// Displays the dialog and returns the entered passcode string if submitted, or null if cancelled.
  static Future<String?> show(
    BuildContext context, {
    String title = 'Security Authentication',
    String description = 'Enter your vault/device passcode to authenticate.',
    bool allowBiometricRetry = false,
    VoidCallback? onBiometricRetry,
  }) {
    return showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => BiometricPromptDialog(
        title: title,
        description: description,
        allowBiometricRetry: allowBiometricRetry,
        onBiometricRetry: onBiometricRetry,
      ),
    );
  }

  @override
  State<BiometricPromptDialog> createState() => _BiometricPromptDialogState();
}

class _BiometricPromptDialogState extends State<BiometricPromptDialog> {
  final TextEditingController _passcodeController = TextEditingController();
  String? _error;

  @override
  void dispose() {
    _passcodeController.dispose();
    super.dispose();
  }

  void _submit() {
    final text = _passcodeController.text.trim();
    if (text.isEmpty) {
      setState(() {
        _error = 'Please enter your passcode.';
      });
      return;
    }
    Navigator.of(context).pop(text);
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      key: const Key('biometric_prompt_dialog'),
      title: Row(
        children: [
          const Icon(Icons.lock_outline, color: Colors.blueAccent),
          const SizedBox(width: 8),
          Expanded(child: Text(widget.title)),
        ],
      ),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              widget.description,
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            const SizedBox(height: 16),
            TextField(
              key: const Key('dialog_passcode_input'),
              controller: _passcodeController,
              obscureText: true,
              autofocus: true,
              keyboardType: TextInputType.text,
              decoration: InputDecoration(
                labelText: 'Passcode / PIN',
                errorText: _error,
                border: const OutlineInputBorder(),
                prefixIcon: const Icon(Icons.password),
              ),
              onSubmitted: (_) => _submit(),
            ),
            if (widget.allowBiometricRetry && widget.onBiometricRetry != null) ...[
              const SizedBox(height: 12),
              Center(
                child: TextButton.icon(
                  key: const Key('dialog_retry_biometrics_button'),
                  onPressed: () {
                    Navigator.of(context).pop(null);
                    widget.onBiometricRetry!();
                  },
                  icon: const Icon(Icons.fingerprint),
                  label: const Text('Use Biometrics Instead'),
                ),
              ),
            ],
          ],
        ),
      ),
      actions: [
        TextButton(
          key: const Key('dialog_cancel_button'),
          onPressed: () => Navigator.of(context).pop(null),
          child: const Text('Cancel'),
        ),
        ElevatedButton(
          key: const Key('dialog_submit_button'),
          onPressed: _submit,
          child: const Text('Unlock'),
        ),
      ],
    );
  }
}
