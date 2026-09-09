/// First-launch pairing over Bluetooth SPP: connect to the daemon computer
/// by selecting it from a discovery list, then register this phone's
/// Ed25519 public key on the computer.
library;

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'bt_link.dart';
import 'key_store.dart';

class PairingScreen extends StatefulWidget {
  const PairingScreen({
    super.key,
    required this.keyStore,
    required this.identity,
    required this.onPaired,
    this.link,
  });

  final KeyStore keyStore;
  final DeviceIdentity identity;

  /// Invoked once the phone is connected to the daemon computer and the
  /// operator has registered the public key there; the caller switches to
  /// the approval screen with [btAddress] persisted.
  final void Function(DeviceIdentity identity, String btAddress) onPaired;

  /// The Bluetooth link; injectable for tests, defaults to the real
  /// platform channel.
  final BtLink? link;

  @override
  State<PairingScreen> createState() => _PairingScreenState();
}

class _PairingScreenState extends State<PairingScreen> {
  /// Discovery yields devices for a bounded time; stop listening after
  /// this and let the operator re-scan.
  static const Duration _discoveryTimeout = Duration(seconds: 15);

  /// Sliding-window cap on the device list: a busy RF environment yields
  /// far more peripherals than are useful, so keep only the most recent.
  static const int _maxDevices = 50;

  late final BtLink _link;
  StreamSubscription<BtDevice>? _discoverySub;
  Timer? _discoveryTimer;

  bool _discovering = false;
  bool _hasScanned = false;
  String? _connectingAddress;
  String? _connectedAddress;
  String? _discoveryError;
  final List<BtDevice> _devices = [];
  final TextEditingController _filterController = TextEditingController();
  String _filter = '';

  @override
  void initState() {
    super.initState();
    _link = widget.link ?? BtLink();
    // Emit the pubkey to logcat so an agent on the machine can retrieve it
    // with `adb logcat -d | grep 'phone-fprint-auth pubkey'` and run
    // `sudo phone-approve pair <name> <pubkey>` without the user copying it.
    debugPrint('phone-fprint-auth pubkey: ${widget.identity.publicKeyBase64}');
  }

  @override
  void dispose() {
    _discoveryTimer?.cancel();
    unawaited(_discoverySub?.cancel());
    _filterController.dispose();
    super.dispose();
  }

  Future<void> _scan() async {
    if (_discovering) return;
    final enabled = await _link.checkEnabled();
    if (!enabled) {
      _showError('Bluetooth is disabled — enable it and scan again.');
      return;
    }
    final granted = await _link.requestPermissions();
    if (!granted) {
      _showError('Bluetooth permission denied.');
      return;
    }
    await _discoverySub?.cancel();
    _discoveryTimer?.cancel();
    setState(() {
      _discovering = true;
      _hasScanned = true;
      _discoveryError = null;
      _devices.clear();
    });
    _discoverySub = _link.discover().listen(
      _onDevice,
      onError: (Object e) {
        _stopDiscovery();
        if (!mounted) return;
        setState(() => _discoveryError = 'Discovery failed: $e');
      },
      onDone: _stopDiscovery,
    );
    _discoveryTimer = Timer(_discoveryTimeout, _stopDiscovery);
  }

  void _stopDiscovery() {
    _discoveryTimer?.cancel();
    _discoveryTimer = null;
    unawaited(_discoverySub?.cancel());
    _discoverySub = null;
    if (!mounted) return;
    setState(() => _discovering = false);
  }

  void _onDevice(BtDevice device) {
    if (!mounted) return;
    // Many nearby BT peripherals report no name — pure noise here.
    if (device.name.isEmpty) return;
    setState(() {
      final index = _devices.indexWhere((d) => d.address == device.address);
      if (index >= 0) {
        _devices[index] = device; // refresh the name
      } else {
        if (_devices.length >= _maxDevices) {
          _devices.removeAt(0); // drop the oldest beyond the cap
        }
        _devices.add(device);
      }
    });
  }

  /// Bonds (Android pairing dialog) and connects to [device], then persists
  /// its address. The operator still has to register the public key on the
  /// computer — the screen stays put until they tap START LISTENING.
  Future<void> _selectDevice(BtDevice device) async {
    if (_connectingAddress != null) return;
    _stopDiscovery();
    setState(() => _connectingAddress = device.address);
    try {
      await _link.bond(device.address);
      try {
        await _link.connect(device.address);
      } on PlatformException catch (e) {
        // An already-active socket means the link is up (e.g. re-pairing
        // while the old socket is still live) — treat it as connected.
        if (e.code != 'already_connected') rethrow;
      }
      await widget.keyStore.setBtAddress(device.address);
      if (!mounted) return;
      setState(() => _connectedAddress = device.address);
    } catch (e) {
      if (!mounted) return;
      setState(() => _connectedAddress = null);
      _showError('Could not connect to ${device.address}: $e');
    } finally {
      if (mounted) setState(() => _connectingAddress = null);
    }
  }

  void _showError(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(message)));
  }

  Future<void> _copyPublicKey() async {
    await Clipboard.setData(
        ClipboardData(text: widget.identity.publicKeyBase64));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Public key copied to clipboard')),
    );
  }

  void _continue() {
    final address = _connectedAddress;
    if (address == null) return;
    widget.onPaired(widget.identity, address);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final visibleDevices = _devices
        .where((d) => d.name.toLowerCase().contains(_filter))
        .toList();
    return Scaffold(
      appBar: AppBar(title: const Text('PAIR DEVICE')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(24),
          children: [
            Text('CONNECT TO COMPUTER', style: theme.textTheme.titleLarge),
            const SizedBox(height: 8),
            Text(
              'Run `sudo phone-approve bt-pair` on the computer, then pick '
              'it from the list below.',
              style: theme.textTheme.bodyMedium,
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: _discovering || _connectedAddress != null
                  ? null
                  : _scan,
              icon: const Icon(Icons.bluetooth_searching),
              label: Text(_discovering ? 'SCANNING…' : 'SCAN FOR COMPUTER'),
            ),
            if (_discoveryError != null) ...[
              const SizedBox(height: 8),
              Text(
                _discoveryError!,
                style: theme.textTheme.bodySmall
                    ?.copyWith(color: theme.colorScheme.error),
              ),
            ],
            const SizedBox(height: 12),
            if (_devices.isNotEmpty) ...[
              TextField(
                controller: _filterController,
                decoration: InputDecoration(
                  hintText: 'Filter by name',
                  prefixIcon: const Icon(Icons.search),
                  suffixIcon: _filter.isEmpty
                      ? null
                      : IconButton(
                          icon: const Icon(Icons.clear),
                          onPressed: () {
                            _filterController.clear();
                            setState(() => _filter = '');
                          },
                        ),
                  isDense: true,
                  border: const OutlineInputBorder(),
                ),
                onChanged: (value) =>
                    setState(() => _filter = value.toLowerCase()),
              ),
              const SizedBox(height: 12),
            ],
            if (_devices.isEmpty &&
                !_discovering &&
                _hasScanned &&
                _discoveryError == null)
              Text(
                'No devices found — make sure the computer is discoverable '
                'and scan again.',
                style: theme.textTheme.bodySmall,
              ),
            if (_devices.isNotEmpty && visibleDevices.isEmpty)
              Text(
                'No devices match your filter.',
                style: theme.textTheme.bodySmall,
              ),
            for (final device in visibleDevices) _deviceTile(theme, device),
            const Divider(height: 32),
            Text('AUTHORIZE THIS DEVICE', style: theme.textTheme.titleLarge),
            const SizedBox(height: 8),
            Text(
              'On the computer, register this phone with the public key '
              'below:',
              style: theme.textTheme.bodyMedium,
            ),
            const SizedBox(height: 8),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: theme.colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(8),
              ),
              child: const SelectableText(
                'sudo phone-approve pair my-phone <pubkey>',
                style: TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
            ),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: theme.colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(8),
              ),
              child: SelectableText(
                widget.identity.publicKeyBase64,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
            ),
            const SizedBox(height: 8),
            Align(
              alignment: Alignment.centerRight,
              child: TextButton.icon(
                onPressed: _copyPublicKey,
                icon: const Icon(Icons.copy, size: 18),
                label: const Text('COPY'),
              ),
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: _connectedAddress == null ? null : _continue,
              icon: const Icon(Icons.fingerprint),
              label: const Text('START LISTENING'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _deviceTile(ThemeData theme, BtDevice device) {
    final connecting = _connectingAddress == device.address;
    final connected = _connectedAddress == device.address;
    return Card(
      child: ListTile(
        enabled: _connectingAddress == null && _connectedAddress == null,
        leading: Icon(
          connected ? Icons.bluetooth_connected : Icons.computer,
        ),
        title: Text(device.name.isEmpty ? '(unnamed device)' : device.name),
        subtitle: Text(
          device.address,
          style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
        ),
        trailing: connecting
            ? const SizedBox(
                width: 20,
                height: 20,
                child: CircularProgressIndicator(strokeWidth: 2),
              )
            : connected
                ? const Icon(Icons.check_circle)
                : const Icon(Icons.chevron_right),
        onTap: () => _selectDevice(device),
      ),
    );
  }
}
