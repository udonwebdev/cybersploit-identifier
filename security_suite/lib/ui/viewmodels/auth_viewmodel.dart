import 'package:flutter/foundation.dart';
import '../../data/services/contracts/i_auth_service.dart';

enum AuthScreenState {
  welcome,
  login,
  register,
  forgotPassword,
  verifyEmail,
  authenticated,
}

/// ViewModel coordinating authentication flows and reactive UI state.
class AuthViewModel extends ChangeNotifier {
  final IAuthService _authService;

  AuthUser? _currentUser;
  AuthScreenState _screenState = AuthScreenState.welcome;
  bool _isLoading = false;
  String? _errorMessage;
  String? _statusMessage;

  // ignore: prefer_initializing_formals
  AuthViewModel({required IAuthService authService}) : _authService = authService {
    _currentUser = _authService.currentUser;
    if (_currentUser != null) {
      _screenState = AuthScreenState.authenticated;
    }
    _authService.authStateChanges.listen((user) {
      _currentUser = user;
      if (user != null) {
        _screenState = AuthScreenState.authenticated;
      } else {
        if (_screenState == AuthScreenState.authenticated) {
          _screenState = AuthScreenState.login;
        }
      }
      notifyListeners();
    });
  }

  AuthUser? get currentUser => _currentUser;
  AuthScreenState get screenState => _screenState;
  bool get isLoading => _isLoading;
  bool get isAuthenticated => _currentUser != null;
  String? get errorMessage => _errorMessage;
  String? get statusMessage => _statusMessage;

  void setScreenState(AuthScreenState state) {
    _screenState = state;
    _errorMessage = null;
    _statusMessage = null;
    notifyListeners();
  }

  Future<bool> register({required String email, required String password}) async {
    _setLoading(true);
    _clearMessages();
    try {
      final user = await _authService.registerWithEmailAndPassword(
        email: email,
        password: password,
      );
      _currentUser = user;
      _screenState = AuthScreenState.authenticated;
      _setLoading(false);
      return true;
    } catch (e) {
      _errorMessage = _cleanErrorMessage(e.toString());
      _setLoading(false);
      return false;
    }
  }

  Future<bool> signIn({required String email, required String password}) async {
    _setLoading(true);
    _clearMessages();
    try {
      final user = await _authService.signInWithEmailAndPassword(
        email: email,
        password: password,
      );
      _currentUser = user;
      _screenState = AuthScreenState.authenticated;
      _setLoading(false);
      return true;
    } catch (e) {
      _errorMessage = _cleanErrorMessage(e.toString());
      _setLoading(false);
      return false;
    }
  }

  Future<bool> sendPasswordReset({required String email}) async {
    _setLoading(true);
    _clearMessages();
    try {
      await _authService.sendPasswordResetEmail(email: email);
      _statusMessage = 'Password reset link sent to ${email.trim()}';
      _setLoading(false);
      return true;
    } catch (e) {
      _errorMessage = _cleanErrorMessage(e.toString());
      _setLoading(false);
      return false;
    }
  }

  Future<void> sendEmailVerification() async {
    _setLoading(true);
    _clearMessages();
    try {
      await _authService.sendEmailVerification();
      _statusMessage = 'Verification email sent';
    } catch (e) {
      _errorMessage = _cleanErrorMessage(e.toString());
    } finally {
      _setLoading(false);
    }
  }

  Future<void> reloadUser() async {
    try {
      await _authService.reloadUser();
      _currentUser = _authService.currentUser;
      notifyListeners();
    } catch (_) {}
  }

  Future<void> signOut() async {
    _setLoading(true);
    try {
      await _authService.signOut();
      _currentUser = null;
      _screenState = AuthScreenState.login;
    } finally {
      _setLoading(false);
    }
  }

  void _setLoading(bool loading) {
    _isLoading = loading;
    notifyListeners();
  }

  void _clearMessages() {
    _errorMessage = null;
    _statusMessage = null;
    notifyListeners();
  }

  String _cleanErrorMessage(String raw) {
    if (raw.contains('user-not-found')) return 'Account not found for this email address.';
    if (raw.contains('wrong-password')) return 'Incorrect password entered.';
    if (raw.contains('email-already-in-use')) return 'An account already exists for this email.';
    if (raw.contains('weak-password')) return 'Password must be at least 6 characters.';
    if (raw.contains('invalid-email')) return 'Please enter a valid email address.';
    return raw.replaceFirst('Exception: ', '').replaceAll(RegExp(r'\[.*?\]'), '').trim();
  }
}
