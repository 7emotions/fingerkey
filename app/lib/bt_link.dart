/// Bluetooth Classic SPP link to the daemon: a thin Dart wrapper over the
/// native platform channel implemented in
/// `android/.../com/phonefprint/auth/BtSppChannel.kt`.
///
/// MethodChannel "com.phonefprint.auth/bt": checkEnabled, requestPermissions,
/// startDiscovery, bond, connect, send, disconnect. EventChannel
/// "com.phonefprint.auth/bt_events" streams the socket/discovery events.
library;

import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart';

/// One Bluetooth device surfaced during discovery.
class BtDevice {
  const BtDevice({required this.name, required this.address});

  final String name;
  final String address;
}

/// One event from the native link.
///
/// [status] is `connected`, `disconnected`, `data` or `error`; discovery
/// results arrive as events with a null [status] carrying [name]/[address].
class BtEvent {
  const BtEvent({
    this.status,
    this.address,
    this.data,
    this.message,
    this.name,
  });

  /// Parses a platform-channel event map. `data` events carry their payload
  /// as a base64 string.
  factory BtEvent.fromMap(Map<dynamic, dynamic> map) {
    final dataB64 = map['data'];
    return BtEvent(
      status: map['status'] as String?,
      address: map['address'] as String?,
      data: dataB64 is String ? base64.decode(dataB64) : null,
      message: map['message'] as String?,
      name: map['name'] as String?,
    );
  }

  final String? status;
  final String? address;
  final Uint8List? data;
  final String? message;
  final String? name;
}

/// Wrapper around the `BtSppChannel` platform channels.
class BtLink {
  BtLink({MethodChannel? channel, EventChannel? events})
      : _channel = channel ?? const MethodChannel(channelName),
        _events = events ?? const EventChannel(eventsChannelName);

  static const String channelName = 'com.phonefprint.auth/bt';
  static const String eventsChannelName = 'com.phonefprint.auth/bt_events';

  final MethodChannel _channel;
  final EventChannel _events;

  late final Stream<BtEvent> _eventStream =
      _events.receiveBroadcastStream().map(
            (dynamic event) => BtEvent.fromMap(event as Map<dynamic, dynamic>),
          );

  /// The native link's event stream (connected/disconnected/data/error plus
  /// discovery results). Broadcast: safe for multiple concurrent listeners.
  Stream<BtEvent> get events => _eventStream;

  /// True when the device's Bluetooth adapter is enabled.
  Future<bool> checkEnabled() async =>
      await _channel.invokeMethod<bool>('checkEnabled') ?? false;

  /// Requests the runtime Bluetooth permissions; true when granted.
  Future<bool> requestPermissions() async =>
      await _channel.invokeMethod<bool>('requestPermissions') ?? false;

  /// Starts discovery and yields each found device. The native side streams
  /// `{name, address}` maps until discovery ends; this view filters them out
  /// of the shared event stream.
  Stream<BtDevice> discover() async* {
    await _channel.invokeMethod<bool>('startDiscovery');
    yield* _eventStream
        .where((e) => e.status == null && e.address != null)
        .map((e) => BtDevice(name: e.name ?? '', address: e.address!));
  }

  /// Pairs (bonds) with the device at [address].
  Future<void> bond(String address) async {
    await _channel.invokeMethod<bool>(
      'bond',
      <String, dynamic>{'address': address},
    );
  }

  /// Dials the SPP server on the device at [address].
  Future<void> connect(String address) async {
    await _channel.invokeMethod<bool>(
      'connect',
      <String, dynamic>{'address': address},
    );
  }

  /// Sends raw bytes over the link (base64 over the method channel; the
  /// native side writes the decoded bytes to the socket). Callers are
  /// responsible for framing: wrap the payload in a 4-byte length-prefixed
  /// frame before sending.
  Future<void> send(Uint8List payload) async {
    await _channel.invokeMethod<bool>(
      'send',
      <String, dynamic>{'data': base64.encode(payload)},
    );
  }

  /// Closes the socket.
  Future<void> disconnect() async {
    await _channel.invokeMethod<void>('disconnect');
  }
}
