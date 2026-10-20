import 'package:flutter_test/flutter_test.dart';
import 'package:security_suite/data/services/fakes/fake_auth_service.dart';
import 'package:security_suite/ui/viewmodels/auth_viewmodel.dart';

void main() {
  group('AuthViewModel Unit Tests', () {
    late FakeAuthService fakeAuthService;
    late AuthViewModel viewModel;

    setUp(() {
      fakeAuthService = FakeAuthService();
      viewModel = AuthViewModel(authService: fakeAuthService);
    });

    test('initial state is unauthenticated and screen state is welcome', () {
      expect(viewModel.isAuthenticated, isFalse);
      expect(viewModel.currentUser, isNull);
      expect(viewModel.screenState, equals(AuthScreenState.welcome));
      expect(viewModel.errorMessage, isNull);
    });

    test('register success updates state to authenticated', () async {
      final success = await viewModel.register(
        email: 'test@cybersploi.com',
        password: 'securePassword123',
      );

      expect(success, isTrue);
      expect(viewModel.isAuthenticated, isTrue);
      expect(viewModel.currentUser?.email, equals('test@cybersploi.com'));
      expect(viewModel.screenState, equals(AuthScreenState.authenticated));
    });

    test('register failure displays readable error', () async {
      fakeAuthService.shouldFail = true;
      fakeAuthService.failureMessage = 'weak-password';

      final success = await viewModel.register(
        email: 'bad@test.com',
        password: '123',
      );

      expect(success, isFalse);
      expect(viewModel.isAuthenticated, isFalse);
      expect(viewModel.errorMessage, contains('Password must be at least 6 characters'));
    });

    test('signIn success authenticates existing user', () async {
      // First register
      await fakeAuthService.registerWithEmailAndPassword(
        email: 'owner@cybersploi.com',
        password: 'password123',
      );
      await fakeAuthService.signOut();

      // Sign in via viewModel
      final success = await viewModel.signIn(
        email: 'owner@cybersploi.com',
        password: 'password123',
      );

      expect(success, isTrue);
      expect(viewModel.isAuthenticated, isTrue);
      expect(viewModel.currentUser?.email, equals('owner@cybersploi.com'));
    });

    test('signIn failure shows incorrect password or user not found message', () async {
      final success = await viewModel.signIn(
        email: 'nonexistent@cybersploi.com',
        password: 'wrong',
      );

      expect(success, isFalse);
      expect(viewModel.isAuthenticated, isFalse);
      expect(viewModel.errorMessage, contains('Account not found for this email address.'));
    });

    test('sendPasswordReset sets success status message', () async {
      await fakeAuthService.registerWithEmailAndPassword(
        email: 'recover@cybersploi.com',
        password: 'password123',
      );

      final success = await viewModel.sendPasswordReset(email: 'recover@cybersploi.com');

      expect(success, isTrue);
      expect(viewModel.statusMessage, contains('Password reset link sent to recover@cybersploi.com'));
      expect(viewModel.errorMessage, isNull);
    });

    test('signOut clears authenticated session and transitions to login screen', () async {
      await viewModel.register(
        email: 'user@cybersploi.com',
        password: 'password123',
      );
      expect(viewModel.isAuthenticated, isTrue);

      await viewModel.signOut();
      expect(viewModel.isAuthenticated, isFalse);
      expect(viewModel.currentUser, isNull);
      expect(viewModel.screenState, equals(AuthScreenState.login));
    });
  });
}
