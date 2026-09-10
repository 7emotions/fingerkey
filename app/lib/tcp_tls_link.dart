/// LAN TCP+TLS link to the daemon: a thin Dart wrapper over the native
/// platform channel implemented in
/// `android/.../com/phonefprint/auth/TcpTlsChannel.kt`.
///
/// MethodChannel "com.phonefprint.auth/tcp": connect, send, disconnect,
/// browse. EventChannel "com.phonefprint.auth/tcp_events" streams the
/// socket events. Because the app keeps one live socket per roster computer
/// ("connect all"), the native side keys every connection by an id that
/// [connect] returns and every event carries.
library;

import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart';

/// One computer discovered over mDNS (Android NSD) browsing.
class TcpComputer {
  const TcpComputer({
    required this.name,
    required this.host,
    required this.port,
    required this.fp,
  });

  factory TcpComputer.fromMap(Map<dynamic, dynamic> map) => TcpComputer(
        name: map['name'] as String? ?? '',
        host: map['host'] as String? ?? '',
        port: map['port'] as int? ?? 0,
        fp: map['fp'] as String? ?? '',
      );

  /// Display name: the mDNS instance name (the machine hostname).
  final String name;

  /// Numeric IPv4 host to dial.
  final String host;

  /// TLS listener port.
  final int port;

  /// Lowercase-hex SHA-256 fingerprint of the LEAF certificate's DER.
  final String fp;

  /// `host:port` for persisting as a roster `lastAddr`.
  String get lastAddr => '$host:$port';
}

/// One event from the native link, tagged with the connection id it belongs
/// to. [status] is `connected`, `disconnected`, `data` or `error`.
class TcpEvent {
  const TcpEvent({this.id, this.status, this.data, this.message});

  factory TcpEvent.fromMap(Map<dynamic, dynamic> map) {
    final dataB64 = map['data'];
    return TcpEvent(
      id: map['id'] as int?,
      status: map['status'] as String?,
      data: dataB64 is String ? base64.decode(dataB64) : null,
      message: map['message'] as String?,
    );
  }

  final int? id;
  final String? status;
  final Uint8List? data;
  final String? message;
}

/// One TCP+TLS connection to a single daemon computer. The app holds several
/// of these at once, one per roster computer; all share the single native
/// MethodChannel/EventChannel, distinguishing their sockets by the connection
/// id [connect] returns.
class TcpTlsLink {
  TcpTlsLink({MethodChannel? channel, EventChannel? events})
      : _channel = channel ?? const MethodChannel(channelName),
        _eventsChannel = events ?? const EventChannel(eventsChannelName);

  static const String channelName = 'com.phonefprint.auth/tcp';
  static const String eventsChannelName = 'com.phonefprint.auth/tcp_events';

  final MethodChannel _channel;
  final EventChannel _eventsChannel;

  /// Connection id assigned by the native side once [connect] succeeds.
  int? _id;

  /// The single shared event stream (one native EventChannel subscription for
  /// the whole app). Broadcast so every link can filter its own id off it.
  Stream<TcpEvent>? _events;

  Stream<TcpEvent> get _sharedEvents => _events ??= _eventsChannel
      .receiveBroadcastStream()
      .map((dynamic event) =>
          TcpEvent.fromMap(event as Map<dynamic, dynamic>));

  /// This connection's events (`connected`/`disconnected`/`data`/`error`),
  /// filtered to the id [connect] returned. Safe for multiple listeners.
  Stream<TcpEvent> get events =>
      _sharedEvents.where((e) => e.id == _id && e.status != null);

  /// Dials the daemon's TLS listener at [host]:[port], pinning the LEAF
  /// certificate's SHA-256 to [fp]. Throws a [PlatformException] with code
  /// `fingerprint_mismatch` when the presented leaf certificate does not
  /// match. Returns the connection id that subsequent [send]/[disconnect]
  /// and this link's [events] are keyed by.
  Future<int> connect(String host, int port, String fp) async {
    final id = await _channel.invokeMethod<int>('connect', <String, dynamic>{
      'host': host,
      'port': port,
      'fp': fp,
    });
    if (id == null) {
      throw PlatformException(
        code: 'connect_failed',
        message: 'connect returned no connection id',
      );
    }
    _id = id;
    return id;
  }

  /// Sends raw bytes over the link (base64 over the method channel; the
  /// native side writes the decoded bytes to the socket). Callers are
  /// responsible for framing: wrap the payload in a 4-byte length-prefixed
  /// frame before sending.
  Future<void> send(Uint8List payload) async {
    final id = _id;
    if (id == null) {
      throw PlatformException(
        code: 'not_connected',
        message: 'connect() must succeed before send()',
      );
    }
    await _channel.invokeMethod<void>('send', <String, dynamic>{
      'id': id,
      'data': base64.encode(payload),
    });
  }

  /// Closes this connection's socket.
  Future<void> disconnect() async {
    final id = _id;
    _id = null;
    if (id == null) return;
    await _channel.invokeMethod<void>('disconnect', <String, dynamic>{
      'id': id,
    });
  }

  /// Browsing is connection-less: it runs once and returns the reachable
  /// computers. Exposed as a static because no single [TcpTlsLink] owns the
  /// discovery.
  static Future<List<TcpComputer>> browse() async {
    const channel = MethodChannel(channelName);
    final List<dynamic>? raw = await channel.invokeMethod<List<dynamic>>(
      'browse',
    );
    if (raw == null) return const [];
    return raw
        .map((dynamic e) => TcpComputer.fromMap(e as Map<dynamic, dynamic>))
        .toList();
  }
}
