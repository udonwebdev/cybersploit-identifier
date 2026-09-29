/// Pure Dart abstraction for platform secure key-value storage (KeyStore/Keychain).
abstract class ISecureStorageService {
  /// Writes [value] associated with [key].
  Future<void> write({required String key, required String value});

  /// Reads the value associated with [key], or null if absent.
  Future<String?> read({required String key});

  /// Deletes the entry for [key].
  Future<void> delete({required String key});

  /// Returns true if [key] exists in storage.
  Future<bool> containsKey({required String key});

  /// Deletes all entries.
  Future<void> deleteAll();

  /// Reads all key-value entries.
  Future<Map<String, String>> readAll();
}
