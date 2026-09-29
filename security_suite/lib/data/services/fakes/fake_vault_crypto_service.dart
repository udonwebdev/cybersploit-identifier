import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

import '../../../core/errors/security_exceptions.dart';
import '../contracts/i_vault_crypto_service.dart';

/// Fake implementation of IVaultCryptoService that performs real mathematical
/// AES-256-GCM encryption/decryption using package:cryptography, but runs fully
/// in memory without platform channel dependencies.
class FakeVaultCryptoService implements IVaultCryptoService {
  final AesGcm _aesGcm;

  static const List<int> magicSecv = [0x53, 0x45, 0x43, 0x56];
  static const List<int> magicVaul = [0x56, 0x41, 0x55, 0x4C];
  static const int formatVersion = 0x01;
  static const int headerLength = 33;

  FakeVaultCryptoService({
    AesGcm? aesGcm,
  }) : _aesGcm = aesGcm ?? AesGcm.with256bits();

  @override
  Future<Uint8List> encryptBytes({
    required Uint8List plaintext,
    required SecretKey masterKey,
    Uint8List? additionalData,
  }) async {
    final nonce = _aesGcm.newNonce();
    final secretBox = await _aesGcm.encrypt(
      plaintext,
      secretKey: masterKey,
      nonce: nonce,
      aad: additionalData ?? const <int>[],
    );

    final bb = BytesBuilder(copy: false);
    bb.add(magicSecv);
    bb.addByte(formatVersion);
    bb.add(secretBox.nonce);
    bb.add(secretBox.mac.bytes);
    bb.add(secretBox.cipherText);

    return bb.takeBytes();
  }

  @override
  Future<Uint8List> decryptBytes({
    required Uint8List encryptedContainer,
    required SecretKey masterKey,
    Uint8List? additionalData,
  }) async {
    final parsed = parseContainer(encryptedContainer);

    final secretBox = SecretBox(
      parsed.ciphertext,
      nonce: parsed.nonce,
      mac: Mac(parsed.tag),
    );

    try {
      final decrypted = await _aesGcm.decrypt(
        secretBox,
        secretKey: masterKey,
        aad: additionalData ?? const <int>[],
      );
      return Uint8List.fromList(decrypted);
    } on SecretBoxAuthenticationError catch (e) {
      throw CryptographicIntegrityException(
        'Decryption failed: Authentication tag mismatch or corrupted ciphertext.',
        e,
      );
    } catch (e) {
      throw CryptographicIntegrityException('Decryption failed: $e', e);
    }
  }

  @override
  Future<EncryptedVaultPayload> encryptFile({
    required String sourcePath,
    required String destinationPath,
    required SecretKey masterKey,
    Uint8List? additionalData,
  }) async {
    final sourceFile = File(sourcePath);
    if (!await sourceFile.exists()) {
      throw SecurityException('Source file does not exist: $sourcePath');
    }

    final rawBytes = await sourceFile.readAsBytes();
    try {
      final encryptedBytes = await encryptBytes(
        plaintext: rawBytes,
        masterKey: masterKey,
        additionalData: additionalData,
      );

      final destFile = File(destinationPath);
      final tempDestFile = File('$destinationPath.tmp_${DateTime.now().microsecondsSinceEpoch}');
      await tempDestFile.writeAsBytes(encryptedBytes, flush: true);
      await tempDestFile.rename(destFile.path);

      return parseContainer(encryptedBytes);
    } finally {
      zeroFill(rawBytes);
    }
  }

  @override
  Future<String> decryptFile({
    required String encryptedFilePath,
    required String decryptedDestinationPath,
    required SecretKey masterKey,
    Uint8List? additionalData,
  }) async {
    final encFile = File(encryptedFilePath);
    if (!await encFile.exists()) {
      throw SecurityException('Encrypted file does not exist: $encryptedFilePath');
    }

    final containerBytes = await encFile.readAsBytes();
    final decryptedBytes = await decryptBytes(
      encryptedContainer: containerBytes,
      masterKey: masterKey,
      additionalData: additionalData,
    );

    try {
      final destFile = File(decryptedDestinationPath);
      final tempDestFile = File('$decryptedDestinationPath.tmp_${DateTime.now().microsecondsSinceEpoch}');
      await tempDestFile.writeAsBytes(decryptedBytes, flush: true);
      await tempDestFile.rename(destFile.path);
      return destFile.path;
    } finally {
      zeroFill(decryptedBytes);
    }
  }

  @override
  Future<SecretKey> deriveKeyFromPasscode({
    required String passcode,
    required Uint8List salt,
    int iterations = 1000,
  }) async {
    final pbkdf2Instance = Pbkdf2(
      macAlgorithm: Hmac.sha256(),
      iterations: iterations,
      bits: 256,
    );
    return await pbkdf2Instance.deriveKey(
      secretKey: SecretKey(utf8.encode(passcode)),
      nonce: salt,
    );
  }

  @override
  Future<SecretKey> generateMasterKey() async {
    return await _aesGcm.newSecretKey();
  }

  @override
  EncryptedVaultPayload parseContainer(Uint8List containerBytes) {
    if (containerBytes.length < headerLength) {
      throw CryptographicIntegrityException(
        'Truncated vault container: Length is ${containerBytes.length}, expected >= $headerLength bytes.',
      );
    }

    final magic = containerBytes.sublist(0, 4);
    final isSecv = magic[0] == magicSecv[0] &&
        magic[1] == magicSecv[1] &&
        magic[2] == magicSecv[2] &&
        magic[3] == magicSecv[3];
    final isVaul = magic[0] == magicVaul[0] &&
        magic[1] == magicVaul[1] &&
        magic[2] == magicVaul[2] &&
        magic[3] == magicVaul[3];

    if (!isSecv && !isVaul) {
      throw CryptographicIntegrityException(
        'Invalid container magic header: 0x${magic.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}',
      );
    }

    final version = containerBytes[4];
    if (version != formatVersion) {
      throw CryptographicIntegrityException(
        'Unsupported vault format version: $version (expected $formatVersion).',
      );
    }

    final nonce = containerBytes.sublist(5, 17);
    final tag = containerBytes.sublist(17, 33);
    final ciphertext = containerBytes.sublist(33);

    return EncryptedVaultPayload(
      rawBytes: containerBytes,
      magic: magic,
      version: version,
      nonce: nonce,
      tag: tag,
      ciphertext: ciphertext,
    );
  }

  @override
  void zeroFill(Uint8List buffer) {
    buffer.fillRange(0, buffer.length, 0);
  }
}
