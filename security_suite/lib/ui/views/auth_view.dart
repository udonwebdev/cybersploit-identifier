import 'package:flutter/material.dart';
import '../viewmodels/auth_viewmodel.dart';

/// Authentication flow screen supporting Welcome, Login, Register, and Forgot Password
class AuthView extends StatefulWidget {
  final AuthViewModel viewModel;

  const AuthView({super.key, required this.viewModel});

  @override
  State<AuthView> createState() => _AuthViewState();
}

class _AuthViewState extends State<AuthView> {
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  final _confirmPasswordController = TextEditingController();
  final _formKey = GlobalKey<FormState>();

  @override
  void dispose() {
    _emailController.dispose();
    _passwordController.dispose();
    _confirmPasswordController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: widget.viewModel,
      builder: (context, _) {
        final state = widget.viewModel.screenState;

        return Scaffold(
          body: SafeArea(
            child: Center(
              child: SingleChildScrollView(
                padding: const EdgeInsets.symmetric(horizontal: 24.0, vertical: 16.0),
                child: Form(
                  key: _formKey,
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      // Header Logo & Branding
                      Center(
                        child: ClipRRect(
                          borderRadius: BorderRadius.circular(16),
                          child: Image.asset(
                            'assets/images/cybersploit_emblem.png',
                            height: 72,
                            width: 72,
                            fit: BoxFit.contain,
                          ),
                        ),
                      ),
                      const SizedBox(height: 16),
                      Text(
                        'CYBERSPLOI IDENTIFIER',
                        textAlign: TextAlign.center,
                        style: Theme.of(context).textTheme.titleMedium?.copyWith(
                              fontWeight: FontWeight.bold,
                              letterSpacing: 1.5,
                            ),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        _getSubtitle(state),
                        textAlign: TextAlign.center,
                        style: Theme.of(context).textTheme.bodySmall?.copyWith(
                              color: Colors.grey.shade400,
                            ),
                      ),
                      const SizedBox(height: 32),

                      // Error Banner
                      if (widget.viewModel.errorMessage != null)
                        Container(
                          key: const Key('auth_error_banner'),
                          margin: const EdgeInsets.only(bottom: 16),
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: Colors.red.shade900.withValues(alpha: 0.2),
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(color: Colors.redAccent),
                          ),
                          child: Row(
                            children: [
                              const Icon(Icons.error_outline, color: Colors.redAccent, size: 20),
                              const SizedBox(width: 8),
                              Expanded(
                                child: Text(
                                  widget.viewModel.errorMessage!,
                                  style: const TextStyle(color: Colors.redAccent, fontSize: 13),
                                ),
                              ),
                            ],
                          ),
                        ),

                      // Success / Status Banner
                      if (widget.viewModel.statusMessage != null)
                        Container(
                          key: const Key('auth_status_banner'),
                          margin: const EdgeInsets.only(bottom: 16),
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: Colors.green.shade900.withValues(alpha: 0.2),
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(color: Colors.greenAccent),
                          ),
                          child: Row(
                            children: [
                              const Icon(Icons.check_circle_outline, color: Colors.greenAccent, size: 20),
                              const SizedBox(width: 8),
                              Expanded(
                                child: Text(
                                  widget.viewModel.statusMessage!,
                                  style: const TextStyle(color: Colors.greenAccent, fontSize: 13),
                                ),
                              ),
                            ],
                          ),
                        ),

                      // Email Field (Used in login, register, forgot password)
                      if (state != AuthScreenState.welcome) ...[
                        TextFormField(
                          key: const Key('auth_email_field'),
                          controller: _emailController,
                          keyboardType: TextInputType.emailAddress,
                          decoration: const InputDecoration(
                            labelText: 'Account Email',
                            prefixIcon: Icon(Icons.email_outlined),
                            border: OutlineInputBorder(),
                          ),
                          validator: (value) {
                            if (value == null || value.trim().isEmpty) {
                              return 'Please enter your email';
                            }
                            if (!value.contains('@') || !value.contains('.')) {
                              return 'Enter a valid email address';
                            }
                            return null;
                          },
                        ),
                        const SizedBox(height: 16),
                      ],

                      // Password Field (Used in login & register)
                      if (state == AuthScreenState.login || state == AuthScreenState.register) ...[
                        TextFormField(
                          key: const Key('auth_password_field'),
                          controller: _passwordController,
                          obscureText: true,
                          decoration: const InputDecoration(
                            labelText: 'Master Password',
                            prefixIcon: Icon(Icons.lock_outline),
                            border: OutlineInputBorder(),
                          ),
                          validator: (value) {
                            if (value == null || value.isEmpty) {
                              return 'Please enter your password';
                            }
                            if (state == AuthScreenState.register && value.length < 6) {
                              return 'Password must be at least 6 characters';
                            }
                            return null;
                          },
                        ),
                        const SizedBox(height: 16),
                      ],

                      // Confirm Password (Register only)
                      if (state == AuthScreenState.register) ...[
                        TextFormField(
                          key: const Key('auth_confirm_password_field'),
                          controller: _confirmPasswordController,
                          obscureText: true,
                          decoration: const InputDecoration(
                            labelText: 'Confirm Password',
                            prefixIcon: Icon(Icons.lock_reset),
                            border: OutlineInputBorder(),
                          ),
                          validator: (value) {
                            if (value != _passwordController.text) {
                              return 'Passwords do not match';
                            }
                            return null;
                          },
                        ),
                        const SizedBox(height: 24),
                      ],

                      // Main Action Buttons
                      if (widget.viewModel.isLoading)
                        const Center(child: CircularProgressIndicator())
                      else
                        _buildPrimaryAction(context, state),

                      const SizedBox(height: 16),

                      // Navigation Switchers
                      _buildNavigationLinks(context, state),
                    ],
                  ),
                ),
              ),
            ),
          ),
        );
      },
    );
  }

  String _getSubtitle(AuthScreenState state) {
    switch (state) {
      case AuthScreenState.welcome:
        return 'Mobile Endpoint Security & Anti-Theft Protection';
      case AuthScreenState.login:
        return 'Sign in to access your secure device enclave';
      case AuthScreenState.register:
        return 'Create an owner account to enroll this device';
      case AuthScreenState.forgotPassword:
        return 'Enter your email to receive recovery instructions';
      default:
        return '';
    }
  }

  Widget _buildPrimaryAction(BuildContext context, AuthScreenState state) {
    switch (state) {
      case AuthScreenState.welcome:
        return Column(
          children: [
            FilledButton.icon(
              key: const Key('auth_welcome_login_btn'),
              icon: const Icon(Icons.login),
              label: const Text('Sign In to Existing Account'),
              style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(48)),
              onPressed: () => widget.viewModel.setScreenState(AuthScreenState.login),
            ),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              key: const Key('auth_welcome_register_btn'),
              icon: const Icon(Icons.person_add_outlined),
              label: const Text('Enroll as New Device Owner'),
              style: OutlinedButton.styleFrom(minimumSize: const Size.fromHeight(48)),
              onPressed: () => widget.viewModel.setScreenState(AuthScreenState.register),
            ),
          ],
        );
      case AuthScreenState.login:
        return FilledButton(
          key: const Key('auth_submit_login_btn'),
          style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(48)),
          onPressed: () {
            if (_formKey.currentState?.validate() ?? false) {
              widget.viewModel.signIn(
                email: _emailController.text.trim(),
                password: _passwordController.text,
              );
            }
          },
          child: const Text('Sign In'),
        );
      case AuthScreenState.register:
        return FilledButton(
          key: const Key('auth_submit_register_btn'),
          style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(48)),
          onPressed: () {
            if (_formKey.currentState?.validate() ?? false) {
              widget.viewModel.register(
                email: _emailController.text.trim(),
                password: _passwordController.text,
              );
            }
          },
          child: const Text('Create Account & Enroll'),
        );
      case AuthScreenState.forgotPassword:
        return FilledButton(
          key: const Key('auth_submit_forgot_btn'),
          style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(48)),
          onPressed: () {
            if (_formKey.currentState?.validate() ?? false) {
              widget.viewModel.sendPasswordReset(email: _emailController.text.trim());
            }
          },
          child: const Text('Send Recovery Link'),
        );
      default:
        return const SizedBox.shrink();
    }
  }

  Widget _buildNavigationLinks(BuildContext context, AuthScreenState state) {
    if (state == AuthScreenState.login) {
      return Column(
        children: [
          TextButton(
            key: const Key('auth_nav_forgot_btn'),
            onPressed: () => widget.viewModel.setScreenState(AuthScreenState.forgotPassword),
            child: const Text('Forgot Master Password?'),
          ),
          Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Text('Need an account?'),
              TextButton(
                key: const Key('auth_nav_to_register_btn'),
                onPressed: () => widget.viewModel.setScreenState(AuthScreenState.register),
                child: const Text('Register'),
              ),
            ],
          ),
        ],
      );
    } else if (state == AuthScreenState.register) {
      return Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Text('Already have an account?'),
          TextButton(
            key: const Key('auth_nav_to_login_btn'),
            onPressed: () => widget.viewModel.setScreenState(AuthScreenState.login),
            child: const Text('Sign In'),
          ),
        ],
      );
    } else if (state == AuthScreenState.forgotPassword) {
      return TextButton(
        key: const Key('auth_back_to_login_btn'),
        onPressed: () => widget.viewModel.setScreenState(AuthScreenState.login),
        child: const Text('Back to Sign In'),
      );
    }
    return const SizedBox.shrink();
  }
}
