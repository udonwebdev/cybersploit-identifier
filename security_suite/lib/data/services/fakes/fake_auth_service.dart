import 'dart:async';
import '../contracts/i_auth_service.dart';

/// Test double / in-memory fake implementation of [IAuthService].
class FakeAuthService implements IAuthService {
  final StreamController<AuthUser?> _authStateController =
      StreamController<AuthUser?>.broadcast();

  final Map<String, String> _userDatabase = {}; // email -> password
  final Map<String, AuthUser> _users = {}; // email -> AuthUser

  AuthUser? _currentUser;
  bool shouldFail = false;
  String? failureMessage;

  FakeAuthService({AuthUser? initialUser}) {
    if (initialUser != null) {
      _currentUser = initialUser;
      if (initialUser.email != null) {
        _users[initialUser.email!] = initialUser;
        _userDatabase[initialUser.email!] = 'password123';
      }
    }
  }

  @override
  Stream<AuthUser?> get authStateChanges => _authStateController.stream;

  @override
  AuthUser? get currentUser => _currentUser;

  @override
  Future<AuthUser> registerWithEmailAndPassword({
    required String email,
    required String password,
  }) async {
    if (shouldFail) {
      throw Exception(failureMessage ?? 'Registration failed');
    }
    if (_userDatabase.containsKey(email)) {
      throw Exception('email-already-in-use');
    }
    if (password.length < 6) {
      throw Exception('weak-password');
    }

    final user = AuthUser(
      uid: 'fake_uid_',
      email: email,
      isEmailVerified: false,
    );
    _userDatabase[email] = password;
    _users[email] = user;
    _currentUser = user;
    _authStateController.add(user);
    return user;
  }

  @override
  Future<AuthUser> signInWithEmailAndPassword({
    required String email,
    required String password,
  }) async {
    if (shouldFail) {
      throw Exception(failureMessage ?? 'Authentication failed');
    }
    if (!_userDatabase.containsKey(email)) {
      throw Exception('user-not-found');
    }
    if (_userDatabase[email] != password) {
      throw Exception('wrong-password');
    }

    final user = _users[email]!;
    _currentUser = user;
    _authStateController.add(user);
    return user;
  }

  @override
  Future<void> sendPasswordResetEmail({required String email}) async {
    if (shouldFail) {
      throw Exception(failureMessage ?? 'Failed to send password reset email');
    }
    if (!_userDatabase.containsKey(email)) {
      throw Exception('user-not-found');
    }
  }

  @override
  Future<void> sendEmailVerification() async {
    if (shouldFail) {
      throw Exception(failureMessage ?? 'Failed to send verification email');
    }
    if (_currentUser == null) {
      throw Exception('no-current-user');
    }
  }

  @override
  Future<void> reloadUser() async {
    // Simulates reloading user and toggling email verification if requested in test
  }

  @override
  Future<void> signOut() async {
    _currentUser = null;
    _authStateController.add(null);
  }

  void dispose() {
    _authStateController.close();
  }
}
