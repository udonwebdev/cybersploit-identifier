import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:security_suite/core/di/service_locator.dart';
import 'package:security_suite/data/repositories/vault_repository.dart';
import 'package:security_suite/data/services/contracts/i_biometric_auth_service.dart';
import 'package:security_suite/data/services/fakes/fake_biometric_auth_service.dart';
import 'package:security_suite/ui/viewmodels/vault_viewmodel.dart';
import 'package:security_suite/ui/views/vault_view.dart';

void main() {
  late FakeBiometricAuthService fakeBiometricService;
  late VaultRepository vaultRepo;
  late VaultViewModel viewModel;
  late Directory tempDir;

  setUp(() async {
    tempDir = await Directory.systemTemp.createTemp('sec_vault_widget_test_');

    fakeBiometricService = FakeBiometricAuthService(
      isHardwareAvailable: true,
      isEnrolled: true,
      shouldSucceed: true,
      availableTypes: [BiometricType.fingerprint],
    );

    await setupServiceLocator(
      useFakes: true,
      customBiometricService: fakeBiometricService,
    );

    vaultRepo = sl<VaultRepository>();
    await vaultRepo.setupVault(fallbackPasscode: '123456');
    vaultRepo.lockVault();

    viewModel = VaultViewModel(vaultRepository: vaultRepo);
  });

  tearDown(() async {
    viewModel.dispose();
    await resetServiceLocator();
    if (await tempDir.exists()) {
      await tempDir.delete(recursive: true);
    }
  });

  Widget buildTestableWidget() {
    return MaterialApp(
      home: VaultView(viewModel: viewModel),
    );
  }

  group('VaultView Widget Tests', () {
    testWidgets('renders locked state banner and authentication actions when locked',
        (tester) async {
      await tester.pumpWidget(buildTestableWidget());
      await tester.pumpAndSettle();

      expect(find.text('Encrypted Vault'), findsOneWidget);
      expect(find.byKey(const Key('vault_locked_card')), findsOneWidget);
      expect(find.text('Vault is Locked'), findsOneWidget);
      expect(find.byKey(const Key('unlock_biometrics_button')), findsOneWidget);
      expect(find.byKey(const Key('passcode_input_field')), findsOneWidget);
      expect(find.byKey(const Key('unlock_passcode_button')), findsOneWidget);
      expect(find.byKey(const Key('import_file_button')), findsNothing);
    });

    testWidgets('unlocks vault via biometric button tap', (tester) async {
      fakeBiometricService.shouldSucceed = true;

      await tester.pumpWidget(buildTestableWidget());
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('unlock_biometrics_button')));
      await tester.pumpAndSettle();

      expect(viewModel.isUnlocked, isTrue);
      expect(find.byKey(const Key('vault_unlocked_view')), findsOneWidget);
      expect(find.byKey(const Key('import_file_button')), findsOneWidget);
      expect(find.byKey(const Key('lock_vault_button')), findsOneWidget);
    });

    testWidgets('unlocks vault via passcode entry and allows locking again', (tester) async {
      await tester.pumpWidget(buildTestableWidget());
      await tester.pumpAndSettle();

      // Enter passcode
      await tester.enterText(find.byKey(const Key('passcode_input_field')), '123456');
      await tester.tap(find.byKey(const Key('unlock_passcode_button')));
      await tester.pumpAndSettle();

      expect(viewModel.isUnlocked, isTrue);
      expect(find.byKey(const Key('vault_unlocked_view')), findsOneWidget);

      // Tap lock button
      await tester.tap(find.byKey(const Key('lock_vault_button')));
      await tester.pumpAndSettle();

      expect(viewModel.isUnlocked, isFalse);
      expect(find.byKey(const Key('vault_locked_card')), findsOneWidget);
    });

    testWidgets('displays error message when passcode is incorrect', (tester) async {
      await tester.pumpWidget(buildTestableWidget());
      await tester.pumpAndSettle();

      await tester.enterText(find.byKey(const Key('passcode_input_field')), 'wrongpin');
      await tester.tap(find.byKey(const Key('unlock_passcode_button')));
      await tester.pumpAndSettle();

      expect(viewModel.isUnlocked, isFalse);
      expect(find.byKey(const Key('vault_error_text')), findsOneWidget);
      expect(find.textContaining('Invalid passcode'), findsOneWidget);
    });

    testWidgets('shows import file dialog when import button tapped', (tester) async {
      fakeBiometricService.shouldSucceed = true;

      await tester.pumpWidget(buildTestableWidget());
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('unlock_biometrics_button')));
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('import_file_button')));
      await tester.pumpAndSettle();

      expect(find.text('Import & Encrypt File'), findsOneWidget);
      expect(find.byKey(const Key('import_dialog_name_input')), findsOneWidget);
      expect(find.byKey(const Key('import_dialog_path_input')), findsOneWidget);
      expect(find.byKey(const Key('import_dialog_submit_button')), findsOneWidget);
    });
  });
}
