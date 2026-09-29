import 'dart:convert';

/// Represents a secure encrypted entry stored in the AES-256-GCM vault.
class VaultEntry {
  final String id;
  final String title;
  final String originalFileName;
  final String mimeType;
  final String encryptedFilePath;
  final int fileSize;
  final DateTime createdAt;
  final bool isEncrypted;
  final String? tag;

  const VaultEntry({
    required this.id,
    required this.title,
    required this.originalFileName,
    required this.mimeType,
    required this.encryptedFilePath,
    required this.fileSize,
    required this.createdAt,
    this.isEncrypted = true,
    this.tag,
  });

  /// Creates a copy with optional updated fields.
  VaultEntry copyWith({
    String? id,
    String? title,
    String? originalFileName,
    String? mimeType,
    String? encryptedFilePath,
    int? fileSize,
    DateTime? createdAt,
    bool? isEncrypted,
    String? tag,
  }) {
    return VaultEntry(
      id: id ?? this.id,
      title: title ?? this.title,
      originalFileName: originalFileName ?? this.originalFileName,
      mimeType: mimeType ?? this.mimeType,
      encryptedFilePath: encryptedFilePath ?? this.encryptedFilePath,
      fileSize: fileSize ?? this.fileSize,
      createdAt: createdAt ?? this.createdAt,
      isEncrypted: isEncrypted ?? this.isEncrypted,
      tag: tag ?? this.tag,
    );
  }

  /// Converts the entry to a JSON-compatible map.
  Map<String, dynamic> toMap() {
    return {
      'id': id,
      'title': title,
      'originalFileName': originalFileName,
      'mimeType': mimeType,
      'encryptedFilePath': encryptedFilePath,
      'fileSize': fileSize,
      'createdAt': createdAt.toIso8601String(),
      'isEncrypted': isEncrypted,
      if (tag != null) 'tag': tag,
    };
  }

  /// Reconstructs a VaultEntry from a map.
  factory VaultEntry.fromMap(Map<String, dynamic> map) {
    return VaultEntry(
      id: map['id'] as String,
      title: map['title'] as String,
      originalFileName: map['originalFileName'] as String,
      mimeType: map['mimeType'] as String,
      encryptedFilePath: map['encryptedFilePath'] as String,
      fileSize: map['fileSize'] as int,
      createdAt: DateTime.parse(map['createdAt'] as String),
      isEncrypted: map['isEncrypted'] as bool? ?? true,
      tag: map['tag'] as String?,
    );
  }

  /// Serializes the entry to a JSON string.
  String toJson() => jsonEncode(toMap());

  /// Deserializes a VaultEntry from a JSON string.
  factory VaultEntry.fromJson(String source) =>
      VaultEntry.fromMap(jsonDecode(source) as Map<String, dynamic>);

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    return other is VaultEntry &&
        other.id == id &&
        other.title == title &&
        other.originalFileName == originalFileName &&
        other.mimeType == mimeType &&
        other.encryptedFilePath == encryptedFilePath &&
        other.fileSize == fileSize &&
        other.createdAt == createdAt &&
        other.isEncrypted == isEncrypted &&
        other.tag == tag;
  }

  @override
  int get hashCode {
    return Object.hash(
      id,
      title,
      originalFileName,
      mimeType,
      encryptedFilePath,
      fileSize,
      createdAt,
      isEncrypted,
      tag,
    );
  }

  @override
  String toString() {
    return 'VaultEntry(id: $id, title: $title, originalFileName: $originalFileName, '
        'fileSize: $fileSize, isEncrypted: $isEncrypted, tag: $tag)';
  }
}
