/// Thin Dart client for the native approval overlay window
/// (`com.phonefprint.auth/overlay`, see `OverlayWindow.kt`).
///
/// The overlay is owned by the headless service engine, so this client is
/// meant to be used from the background isolate (`mainBackground`); task 11
/// wires pending sessions to [show], task 12 routes [decisions] to the
/// biometric flow.
library;

import 'dart:async';

import 'package:flutter/services.dart';

/// Client for the native overlay MethodChannel/EventChannel pair.
class OverlayChannel {
  OverlayChannel._();

  static const MethodChannel _method =
      MethodChannel('com.phonefprint.auth/overlay');
  static const EventChannel _events =
      EventChannel('com.phonefprint.auth/overlay_events');

  /// Shows the approval card for one pending request. [request] mirrors
  /// [PendingSession.toJson] (`id`, `user`, `service`, `reason`, `command`,
  /// `expiresAt` in ms). Returns `shown`, or `permission_required` when the
  /// SYSTEM_ALERT_WINDOW access is missing (the user is routed to the
  /// Settings grant page).
  static Future<String> show(Map<String, dynamic> request) async {
    final Object? result = await _method.invokeMethod<dynamic>('show', request);
    return result as String? ?? '';
  }

  /// Hides the overlay window, if one is showing.
  static Future<void> hide() async {
    await _method.invokeMethod<dynamic>('hide');
  }

  /// Button presses and timeouts from the overlay:
  /// `{"type": "decision", "id": ..., "decision": "approve"|"deny"}` and
  /// `{"type": "expired", "id": ...}`.
  static Stream<Map<String, dynamic>> decisions() => _events
      .receiveBroadcastStream()
      .map((dynamic event) => Map<String, dynamic>.from(event as Map));
}
