import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:security_suite/core/di/service_locator.dart';
import 'package:security_suite/main.dart';

void main() {
  setUp(() async {
    await setupServiceLocator(useFakes: true);
  });

  tearDown(() async {
    await resetServiceLocator();
  });

  testWidgets('Root SecuritySuiteApp launches and renders navigation tabs and Dashboard',
      (WidgetTester tester) async {
    await tester.pumpWidget(const MyApp());
    await tester.pumpAndSettle();

    // Verify main navigation bar and destinations exist
    expect(find.byKey(const Key('main_navigation_bar')), findsOneWidget);
    expect(find.byKey(const Key('nav_dashboard')), findsOneWidget);
    expect(find.byKey(const Key('nav_vault')), findsOneWidget);
    expect(find.byKey(const Key('nav_scanner')), findsOneWidget);
    expect(find.byKey(const Key('nav_settings')), findsOneWidget);

    // Verify initial screen is Dashboard with Posture Badge & Tracking Switch
    expect(find.text('Security Posture'), findsOneWidget);
    expect(find.byKey(const Key('posture_badge')), findsOneWidget);
    expect(find.byKey(const Key('tracking_switch_tile')), findsOneWidget);
  });

  testWidgets('Navigation bar switches between views', (WidgetTester tester) async {
    await tester.pumpWidget(const MyApp());
    await tester.pumpAndSettle();

    // Tap Vault tab
    await tester.tap(find.byKey(const Key('nav_vault')));
    await tester.pumpAndSettle();
    expect(find.text('Encrypted Vault'), findsOneWidget);
    expect(find.byKey(const Key('vault_locked_card')), findsOneWidget);

    // Tap Scanner tab
    await tester.tap(find.byKey(const Key('nav_scanner')));
    await tester.pumpAndSettle();
    expect(find.text('Adaptive Threat Scanner'), findsOneWidget);
    expect(find.byKey(const Key('trigger_scan_button')), findsOneWidget);

    // Tap Settings tab
    await tester.tap(find.byKey(const Key('nav_settings')));
    await tester.pumpAndSettle();
    expect(find.text('Device & Cloud Settings'), findsOneWidget);
    expect(find.byKey(const Key('manual_sync_button')), findsOneWidget);
  });
}
