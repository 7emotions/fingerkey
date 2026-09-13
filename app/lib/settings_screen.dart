/// Settings page pushed from the approval screen's AppBar gear. Holds the
/// persistent approval-sound toggle (stored in [KeyStore] under
/// `sound_enabled`) and the paired-computer management entries that used to
/// live in the gear bottom sheet: per-computer "Forget X" (keeps the key)
/// and "Reset identity" (wipes the key + roster).
library;

import 'package:flutter/material.dart';

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
  /// popped; the caller falls back to the pairing screen.
  final VoidCallback onReset;

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  /// Default true, matching [KeyStore.loadSoundEnabled]'s fallback.
  bool _soundEnabled = true;
  bool _loaded = false;

  @override
  void initState() {
    super.initState();
    widget.keyStore.loadSoundEnabled().then((enabled) {
      if (!mounted) return;
      setState(() {
        _soundEnabled = enabled;
        _loaded = true;
      });
    });
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
