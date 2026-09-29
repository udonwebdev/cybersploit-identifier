import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:security_suite/core/di/service_locator.dart';
import 'package:security_suite/data/repositories/device_repository.dart';
import 'package:security_suite/ui/viewmodels/settings_viewmodel.dart';
import 'package:security_suite/ui/views/settings_view.dart';

void main() {
  late DeviceRepository deviceRepo;
  late SettingsViewModel viewModel;

  setUp(() async {
    await setupServiceLocator(useFakes: true);
    deviceRepo = sl<DeviceRepository>();
    viewModel = SettingsViewModel(deviceRepository: deviceRepo);
  });

  tearDown(() async {
    viewModel.dispose();
    await resetServiceLocator();
  });

  Widget buildTestableWidget() {
    return MaterialApp(
      home: SettingsView(viewModel: viewModel),
    );
  }

  group('SettingsView Widget Tests', () {
    testWidgets('renders device identifier, capability tier, and sync actions',
        (tester) async {
      await tester.pumpWidget(buildTestableWidget());
      await tester.pumpAndSettle();

      expect(find.text('Device & Cloud Settings'), findsOneWidget);
      expect(find.byKey(const Key('device_id_text')), findsOneWidget);
      expect(find.byKey(const Key('offline_queue_text')), findsOneWidget);
      expect(find.byKey(const Key('manual_sync_button')), findsOneWidget);
      expect(find.byKey(const Key('flush_queue_button')), findsOneWidget);
    });

    testWidgets('tapping sync button triggers cloud sync and shows status',
        (tester) async {
      await tester.pumpWidget(buildTestableWidget());
      await tester.pumpAndSettle();

      await tester.ensureVisible(find.byKey(const Key('manual_sync_button')));
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('manual_sync_button')));
      await tester.pump();
      await tester.runAsync(() async {
        await Future.delayed(const Duration(milliseconds: 200));
      });
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('sync_status_text')), findsOneWidget);
      final textWidget =
          tester.widget<Text>(find.byKey(const Key('sync_status_text')));
      expect(textWidget.data, contains('completed'));
    });

    testWidgets('tapping flush queue button flushes offline queue and shows status',
        (tester) async {
      await tester.pumpWidget(buildTestableWidget());
      await tester.pumpAndSettle();

      await tester.ensureVisible(find.byKey(const Key('flush_queue_button')));
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('flush_queue_button')));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 200));
      await tester.pump(const Duration(milliseconds: 200));

      expect(find.byKey(const Key('sync_status_text')), findsOneWidget);
      expect(find.textContaining('flushed'), findsOneWidget);
    });
  });
}
