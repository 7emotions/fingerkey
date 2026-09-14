/// Settings page pushed from the approval screen's AppBar gear. Holds the
/// persistent approval-sound toggle (stored in [KeyStore] under
/// `sound_enabled`), the battery-optimization exemption entry (task 13), and
/// the paired-computer management entries that used to live in the gear
/// bottom sheet: per-computer "Forget X" (keeps the key) and "Reset identity"
/// (wipes the key + roster).
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'key_store.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({
    super.key,
    required this.keyStore,
    required this.roster,
    required this.onForget,
    required this.onReset,
  });

  final KeyStore keyStore;

  /// The current roster snapshot from the approval screen, used for the
  /// "forget" list.
  final List<RosterComputer> roster;

  /// Forget one computer (keeps the device key). Called after this page is
  /// popped; the approval screen re-reads the roster via its own callback.
  final void Function(RosterComputer computer) onForget;

  /// Full identity reset (wipe key + roster). Called after this page is
  /// popped; the caller falls back to the pairing screen. Returns a Future so
  /// the caller can await the wipe before resetting the service-side link
  /// (task 21).
  final Future<void> Function() onReset;

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen>
    with WidgetsBindingObserver {
  /// Native battery-optimization plumbing (PowerChannel.kt, task 13).
  static const MethodChannel _powerChannel =
      MethodChannel('com.phonefprint.auth/power');

  /// Default true, matching [KeyStore.loadSoundEnabled]'s fallback.
  bool _soundEnabled = true;
  bool _loaded = false;

  /// Whether the app already holds the battery-optimization exemption.
  /// `null` while the native answer is still loading; the entry is hidden
  /// until it resolves to `false`.
  bool? _batteryExempt;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    widget.keyStore.loadSoundEnabled().then((enabled) {
      if (!mounted) return;
      setState(() {
        _soundEnabled = enabled;
        _loaded = true;
      });
    });
    _loadBatteryState();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  /// The exemption dialog covers the app; when the user comes back, re-read
  /// the state so the entry hides itself once the grant was accepted.
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _loadBatteryState();
    }
  }

  Future<void> _loadBatteryState() async {
    bool exempt;
    try {
      exempt = await _powerChannel
              .invokeMethod<bool>('isIgnoringBatteryOptimizations') ??
          false;
    } on MissingPluginException {
      exempt = false; // Tests / non-Android hosts have no native handler.
    } on PlatformException {
      exempt = false;
    }
    if (!mounted) return;
    setState(() => _batteryExempt = exempt);
  }

  /// Opens the SYSTEM exemption dialog. Only ever fired from this tile's tap;
  /// the user decides in the system UI, the app never enables it silently.
  Future<void> _requestIgnoreBattery() async {
    try {
      await _powerChannel
          .invokeMethod<void>('requestIgnoreBatteryOptimizations');
    } on MissingPluginException {
      return;
    } on PlatformException catch (e) {
      debugPrint('phone-fprint-auth: battery request failed: $e');
    }
  }

  Future<void> _setSoundEnabled(bool enabled) async {
    setState(() => _soundEnabled = enabled);
    await widget.keyStore.setSoundEnabled(enabled);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: SafeArea(
        child: ListView(
          children: [
            SwitchListTile(
              secondary: const Icon(Icons.volume_up),
              title: const Text('审批提示音'),
              subtitle: const Text('收到审批请求时播放提示音'),
              value: _soundEnabled,
              onChanged: _loaded ? _setSoundEnabled : null,
            ),
            const Divider(),
            if (_batteryExempt == false)
              ListTile(
                leading: const Icon(Icons.battery_saver),
                title: const Text('Ignore battery optimizations'),
                subtitle: const Text(
                    'Keep the approval link alive in the background'),
                onTap: _requestIgnoreBattery,
              ),
            if (_batteryExempt == false) const Divider(),
            ListTile(
              leading: const Icon(Icons.computer),
              title: Text(
                'Paired computers (${widget.roster.length})',
                style: Theme.of(context).textTheme.labelLarge,
              ),
            ),
            for (final computer in widget.roster)
              ListTile(
                leading: const Icon(Icons.link_off),
                title: Text('Forget ${computer.name}'),
                subtitle: Text(
                  computer.fingerprint,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                ),
                onTap: () {
                  Navigator.pop(context);
                  widget.onForget(computer);
                },
              ),
            const Divider(),
            ListTile(
              leading: const Icon(Icons.delete_forever,
                  color: Color(0xFFF0B4B4)),
              title: const Text(
                'Reset identity',
                style: TextStyle(color: Color(0xFFF0B4B4)),
              ),
              subtitle: const Text('Delete this phone\'s key and all pairings'),
              onTap: () {
                Navigator.pop(context);
                widget.onReset();
              },
            ),
          ],
        ),
      ),
    );
  }
}
