import 'package:flutter/material.dart';

import '../../../data/models/vault_entry.dart';

/// List tile representing an encrypted item in the vault.
class VaultItemTile extends StatelessWidget {
  final VaultEntry entry;
  final VoidCallback onDecrypt;
  final VoidCallback onDelete;

  const VaultItemTile({
    super.key,
    required this.entry,
    required this.onDecrypt,
    required this.onDelete,
  });

  @override
  Widget build(BuildContext context) {
    final sizeFormatted = _formatBytes(entry.fileSize);
    final dateFormatted =
        '${entry.createdAt.year}-${entry.createdAt.month.toString().padLeft(2, '0')}-${entry.createdAt.day.toString().padLeft(2, '0')}';

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      child: ListTile(
        leading: const CircleAvatar(
          backgroundColor: Colors.blueGrey,
          child: Icon(Icons.lock, color: Colors.white, size: 20),
        ),
        title: Text(
          entry.title,
          style: const TextStyle(fontWeight: FontWeight.bold),
        ),
        subtitle: Text(
          '${entry.originalFileName} • $sizeFormatted • $dateFormatted',
          style: Theme.of(context).textTheme.bodySmall,
        ),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            IconButton(
              key: Key('decrypt_entry_${entry.id}'),
              icon: const Icon(Icons.file_download_outlined, color: Colors.blueAccent),
              tooltip: 'Decrypt & Export',
              onPressed: onDecrypt,
            ),
            IconButton(
              key: Key('delete_entry_${entry.id}'),
              icon: const Icon(Icons.delete_outline, color: Colors.redAccent),
              tooltip: 'Secure Shred',
              onPressed: onDelete,
            ),
          ],
        ),
      ),
    );
  }

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(2)} MB';
  }
}
