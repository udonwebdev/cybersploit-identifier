import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:security_suite/data/services/fakes/fake_auth_service.dart';
import 'package:security_suite/ui/viewmodels/auth_viewmodel.dart';
import 'package:security_suite/ui/views/auth_view.dart';

void main() {
  group('AuthView Widget Tests', () {
    late FakeAuthService fakeAuthService;
    late AuthViewModel viewModel;

    setUp(() {
      fakeAuthService = FakeAuthService();
      viewModel = AuthViewModel(authService: fakeAuthService);
    });

    Widget createTestWidget() {
      return MaterialApp(
        home: AuthView(viewModel: viewModel),
      );
    }

    testWidgets('renders welcome branding and entry buttons on initial load', (tester) async {
      await tester.pumpWidget(createTestWidget());
      await tester.pumpAndSettle();

      expect(find.text('CYBERSPLOI IDENTIFIER'), findsOneWidget);
      expect(find.byKey(const Key('auth_welcome_login_btn')), findsOneWidget);
      expect(find.byKey(const Key('auth_welcome_register_btn')), findsOneWidget);
    });

    testWidgets('navigating to login shows email and password fields', (tester) async {
      await tester.pumpWidget(createTestWidget());
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('auth_welcome_login_btn')));
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('auth_email_field')), findsOneWidget);
      expect(find.byKey(const Key('auth_password_field')), findsOneWidget);
      expect(find.byKey(const Key('auth_submit_login_btn')), findsOneWidget);
      expect(find.byKey(const Key('auth_nav_forgot_btn')), findsOneWidget);
    });

    testWidgets('navigating to register displays confirm password field', (tester) async {
      await tester.pumpWidget(createTestWidget());
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('auth_welcome_register_btn')));
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('auth_email_field')), findsOneWidget);
      expect(find.byKey(const Key('auth_password_field')), findsOneWidget);
      expect(find.byKey(const Key('auth_confirm_password_field')), findsOneWidget);
      expect(find.byKey(const Key('auth_submit_register_btn')), findsOneWidget);
    });

    testWidgets('submitting valid registration updates viewModel state', (tester) async {
      await tester.pumpWidget(createTestWidget());
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('auth_welcome_register_btn')));
      await tester.pumpAndSettle();

      await tester.enterText(find.byKey(const Key('auth_email_field')), 'operator@cybersploi.com');
      await tester.enterText(find.byKey(const Key('auth_password_field')), 'armoredPassword99');
      await tester.enterText(find.byKey(const Key('auth_confirm_password_field')), 'armoredPassword99');

      await tester.tap(find.byKey(const Key('auth_submit_register_btn')));
      await tester.pumpAndSettle();

      expect(viewModel.isAuthenticated, isTrue);
      expect(viewModel.currentUser?.email, equals('operator@cybersploi.com'));
    });
  });
}
