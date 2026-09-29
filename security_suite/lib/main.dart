import 'package:flutter/material.dart';

import 'core/di/service_locator.dart';
import 'ui/viewmodels/dashboard_viewmodel.dart';
import 'ui/viewmodels/settings_viewmodel.dart';
import 'ui/viewmodels/threat_scanner_viewmodel.dart';
import 'ui/viewmodels/vault_viewmodel.dart';
import 'ui/views/dashboard_view.dart';
import 'ui/views/settings_view.dart';
import 'ui/views/threat_scanner_view.dart';
import 'ui/views/vault_view.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  if (!sl.isRegistered<DashboardViewModel>()) {
    await setupServiceLocator();
  }
  runApp(const SecuritySuiteApp());
}

/// Root application widget for the security suite.
class SecuritySuiteApp extends StatelessWidget {
  const SecuritySuiteApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Identifier',
      debugShowCheckedModeBanner: false,
      themeMode: ThemeMode.system,
      theme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.light,
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.blueAccent,
          brightness: Brightness.light,
        ),
      ),
      darkTheme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.blueAccent,
          brightness: Brightness.dark,
        ),
      ),
      home: const MainNavigationShell(),
    );
  }
}

/// Convenience alias maintaining backward-compatibility with default template test runners.
class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const SecuritySuiteApp();
  }
}

/// Navigation shell hosting the bottom navigation bar and the 4 primary feature views.
class MainNavigationShell extends StatefulWidget {
  const MainNavigationShell({super.key});

  @override
  State<MainNavigationShell> createState() => _MainNavigationShellState();
}

class _MainNavigationShellState extends State<MainNavigationShell> {
  int _currentIndex = 0;

  late final DashboardViewModel _dashboardViewModel;
  late final VaultViewModel _vaultViewModel;
  late final ThreatScannerViewModel _threatScannerViewModel;
  late final SettingsViewModel _settingsViewModel;

  @override
  void initState() {
    super.initState();
    _dashboardViewModel = sl<DashboardViewModel>();
    _vaultViewModel = sl<VaultViewModel>();
    _threatScannerViewModel = sl<ThreatScannerViewModel>();
    _settingsViewModel = sl<SettingsViewModel>();
  }

  @override
  void dispose() {
    _dashboardViewModel.dispose();
    _vaultViewModel.dispose();
    _threatScannerViewModel.dispose();
    _settingsViewModel.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final views = [
      DashboardView(viewModel: _dashboardViewModel),
      VaultView(viewModel: _vaultViewModel),
      ThreatScannerView(viewModel: _threatScannerViewModel),
      SettingsView(viewModel: _settingsViewModel),
    ];

    return Scaffold(
      body: IndexedStack(
        index: _currentIndex,
        children: views,
      ),
      bottomNavigationBar: NavigationBar(
        key: const Key('main_navigation_bar'),
        selectedIndex: _currentIndex,
        onDestinationSelected: (index) {
          setState(() {
            _currentIndex = index;
          });
        },
        destinations: const [
          NavigationDestination(
            key: Key('nav_dashboard'),
            icon: Icon(Icons.shield_outlined),
            selectedIcon: Icon(Icons.shield),
            label: 'Dashboard',
          ),
          NavigationDestination(
            key: Key('nav_vault'),
            icon: Icon(Icons.lock_outline),
            selectedIcon: Icon(Icons.lock),
            label: 'Vault',
          ),
          NavigationDestination(
            key: Key('nav_scanner'),
            icon: Icon(Icons.radar_outlined),
            selectedIcon: Icon(Icons.radar),
            label: 'Scanner',
          ),
          NavigationDestination(
            key: Key('nav_settings'),
            icon: Icon(Icons.settings_outlined),
            selectedIcon: Icon(Icons.settings),
            label: 'Settings',
          ),
        ],
      ),
    );
  }
}
