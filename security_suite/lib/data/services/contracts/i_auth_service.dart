import 'dart:async';

/// Domain user model decoupling the app from Firebase-specific types.
class AuthUser {
  final String uid;
  final String? email;
  final bool isEmailVerified;
  final bool isAnonymous;

  const AuthUser({
    required this.uid,
    this.email,
    this.isEmailVerified = false,
    this.isAnonymous = false,
  });

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is AuthUser &&
          runtimeType == other.runtimeType &&
          uid == other.uid &&
          email == other.email &&
          isEmailVerified == other.isEmailVerified;

  @override
  int get hashCode => uid.hashCode ^ email.hashCode ^ isEmailVerified.hashCode;
}

/// Abstract contract for authentication and account recovery operations.
abstract class IAuthService {
  /// Emits the current authenticated user or null on logout.
  Stream<AuthUser?> get authStateChanges;

  /// Current authenticated user snapshot.
  AuthUser? get currentUser;

  /// Register with email and password.
  Future<AuthUser> registerWithEmailAndPassword({
    required String email,
    required String password,
  });

  /// Sign in with email and password.
  Future<AuthUser> signInWithEmailAndPassword({
    required String email,
    required String password,
  });

  /// Send password reset link to user email.
  Future<void> sendPasswordResetEmail({required String email});

  /// Send email verification to currently signed-in user.
  Future<void> sendEmailVerification();

  /// Reload current user profile to refresh email verification status.
  Future<void> reloadUser();

  /// Sign out current user session.
  Future<void> signOut();
}
