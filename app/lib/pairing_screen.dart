/// QR pairing over LAN: scan the computer's `phonefprint://ip:port?
/// fp=hex&t=token&n=name` code, connect (pinning the leaf cert to `fp`)
/// with a short timeout, fall back to NSD browse when the direct dial fails,
/// and register this phone's key by answering with `hello{token}`. On
/// `registered` the computer is added to the roster and [onPaired] fires.
library;

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import 'daemon_client.dart';
import 'key_store.dart';
import 'tcp_tls_link.dart';

/// Builds the in-screen QR scanner. Injectable so tests can substitute a
/// button without spinning up a camera.
typedef ScannerBuilder =
    Widget Function(BuildContext context, ValueChanged<String> onScanned);

/// One parsed `phonefprint://` pairing code.
class PairRequest {
  const PairRequest({
    required this.ip,
    required this.port,
    required this.fp,
    required this.token,
    required this.name,
  });

  factory PairRequest.parse(String raw) {
    final uri = Uri.tryParse(raw.trim());
    if (uri == null || uri.scheme != 'phonefprint') {
      throw const FormatException('not a phonefprint:// URI');
    }
    final host = uri.host;
    final fp = uri.queryParameters['fp'];
    if (host.isEmpty || fp == null || fp.isEmpty) {
      throw const FormatException('missing host or fp');
    }
    return PairRequest(
      ip: host,
      port: uri.hasPort ? uri.port : 4443,
      fp: fp,
      token: uri.queryParameters['t'] ?? '',
      name: uri.queryParameters['n'] ?? '',
    );
  }

  final String ip;
  final int port;
  final String fp;
  final String token;
  final String name;
}

/// Runs the pairing exchange for a parsed [qr]: direct-connect (with a short
/// timeout, so a dead IP cannot burn the 60s token TTL) then, on failure,
/// fall back to NSD browse matched by fingerprint. On `registered` the
/// computer is added to the roster. Returns the [RosterComputer] added.
Future<RosterComputer> pairFromQr({
  required String qr,
  required DeviceIdentity identity,
  required KeyStore keyStore,
  required DaemonClient Function() clientFactory,
  required Future<List<TcpComputer>> Function() browse,
}) async {
  final request = PairRequest.parse(qr);
  final lastAddr = '${request.ip}:${request.port}';

  Future<void> connect(String host, int port) async {
    final client = clientFactory();
    try {
      final welcome = await client
          .connect(
            host: host,
            port: port,
            fp: request.fp,
            token: request.token,
          )
          .timeout(const Duration(seconds: 5));
      if (!welcome.registered) {
        throw const PairRejected('connection refused (key not accepted)');
      }
    } finally {
      try {
        await client.dispose();
      } catch (_) {
        // The key is already registered on the daemon; a teardown failure
        // must not fail the pairing.
      }
    }
  }

  try {
    await connect(request.ip, request.port);
  } on PairRejected {
    rethrow;
  } on PlatformException catch (e) {
    if (e.code != 'connect_failed') rethrow;
    // Only a genuine TCP connect failure reaches here: the hello was never
    // sent, so the one-time token is still valid. Browse for the same
    // fingerprint and try its advertised address instead.
    TcpComputer? match;
    for (final c in await browse()) {
      if (c.fp.toLowerCase() == request.fp.toLowerCase()) {
        match = c;
        break;
      }
    }
    if (match == null) {
      throw const PairNotFound('computer not found on the network');
    }
    await connect(match.host, match.port);
  } catch (e) {
    debugPrint('phone-fprint-auth: direct dial failed, no fallback: $e');
    rethrow;
  }

  final computer = RosterComputer(
    name: request.name,
    fingerprint: request.fp,
    lastAddr: lastAddr,
  );
  await keyStore.addComputer(
    name: request.name,
    fingerprint: request.fp,
    lastAddr: lastAddr,
  );
  return computer;
}

class PairRejected implements Exception {
  const PairRejected(this.message);
  final String message;
  @override
  String toString() => message;
}

class PairNotFound implements Exception {
  const PairNotFound(this.message);
  final String message;
  @override
  String toString() => message;
}

class PairingScreen extends StatefulWidget {
  const PairingScreen({
    super.key,
    required this.keyStore,
    required this.identity,
    required this.onPaired,
    this.clientFactory,
    this.browse,
    this.scannerBuilder,
  });

  final KeyStore keyStore;
  final DeviceIdentity identity;

  /// Invoked once the QR pairing added a computer to the roster; the caller
  /// switches to the approval screen.
  final void Function(DeviceIdentity identity) onPaired;

  /// Test seam: creates the per-attempt [DaemonClient].
  final DaemonClient Function()? clientFactory;

  /// Test seam: mDNS browse.
  final Future<List<TcpComputer>> Function()? browse;

  /// Test seam: builds the scanner UI (defaults to a [MobileScanner]).
  final ScannerBuilder? scannerBuilder;

  @override
  State<PairingScreen> createState() => PairingScreenState();
}

class PairingScreenState extends State<PairingScreen> {
  bool _pairing = false;
  bool _paired = false;

  /// Whether the camera scanner is active. It starts off (the user presses a
  /// button to turn it on) and is turned off the moment a code is detected, so
  /// a failed pairing cannot re-scan the same (one-time) token in a loop.
  bool _scanning = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    // Emit the pubkey to logcat so an agent on the machine can retrieve it
    // with `adb logcat -d | grep 'phone-fprint-auth pubkey'`.
    debugPrint('phone-fprint-auth pubkey: ${widget.identity.publicKeyBase64}');
  }

  DaemonClient _client() => widget.clientFactory?.call() ??
      DaemonClient(pubkey: widget.identity.publicKeyBase64);

  Future<List<TcpComputer>> _browse() =>
      widget.browse?.call() ?? TcpTlsLink.browse();

  void _onDetect(BarcodeCapture capture) {
    for (final barcode in capture.barcodes) {
      final raw = barcode.rawValue;
      if (raw != null && raw.startsWith('phonefprint://')) {
        unawaited(handleQr(raw));
        return;
      }
    }
  }

  /// Handles one scanned QR payload: parse → connect → `registered` →
  /// addComputer → [onPaired]. Public for tests to drive without a camera.
  Future<void> handleQr(String raw) async {
    if (_pairing || _paired || !_scanning) return;
    setState(() {
      _scanning = false;
      _pairing = true;
      _error = null;
    });
    try {
      await pairFromQr(
        qr: raw,
        identity: widget.identity,
        keyStore: widget.keyStore,
        clientFactory: _client,
        browse: _browse,
      );
      if (!mounted) return;
      _paired = true;
      widget.onPaired(widget.identity);
    } catch (e) {
      debugPrint('phone-fprint-auth: pairing failed: $e');
      if (!mounted) return;
      setState(() => _error = 'Pairing failed: $e');
    } finally {
      if (mounted) setState(() => _pairing = false);
    }
  }

  void _startScan() {
    setState(() {
      _scanning = true;
      _error = null;
    });
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(title: const Text('PAIR DEVICE')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(24),
          children: [
            Text('SCAN THE PAIRING CODE', style: theme.textTheme.titleLarge),
            const SizedBox(height: 8),
            Text(
              'On the computer, run `sudo phone-approve pair-qr <name>` and '
              'scan the QR code it prints.',
              style: theme.textTheme.bodyMedium,
            ),
            const SizedBox(height: 16),
            SizedBox(
              height: 240,
              child: ClipRRect(
                borderRadius: BorderRadius.circular(12),
                child: _pairing
                    ? const ColoredBox(
                        color: Color(0xFF1A1D22),
                        child: Center(child: CircularProgressIndicator()),
                      )
                    : _scanning
                        ? (widget.scannerBuilder?.call(context, handleQr) ??
                            MobileScanner(onDetect: _onDetect))
                        : ColoredBox(
                            color: const Color(0xFF1A1D22),
                            child: Center(
                              child: TextButton.icon(
                                onPressed: _startScan,
                                icon: const Icon(Icons.qr_code_scanner),
                                label: Text(
                                  _error != null ? 'SCAN AGAIN' : 'START SCAN',
                                ),
                              ),
                            ),
                          ),
              ),
            ),
            if (_error != null) ...[
              const SizedBox(height: 12),
              Text(
                _error!,
                style: theme.textTheme.bodySmall
                    ?.copyWith(color: theme.colorScheme.error),
              ),
            ],
            const SizedBox(height: 12),
            Text(
              'This device key:',
              style: theme.textTheme.labelSmall
                  ?.copyWith(color: theme.colorScheme.outline),
            ),
            const SizedBox(height: 4),
            Text(
              widget.identity.publicKeyBase64,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            ),
          ],
        ),
      ),
    );
  }
}
