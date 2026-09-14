/// Thin Dart client for the native approval overlay window
/// (`com.phonefprint.auth/overlay`, see `OverlayWindow.kt`).
///
/// The overlay is owned by the headless service engine, so this client is
/// meant to be used from the background isolate (`mainBackground`); task 11
/// wired pending sessions to [show]. Task 12 routes the buttons: DENY comes
/// back as a decision event here (the service isolate signs and posts it),
/// while APPROVE launches the main Activity with the session payload
/// (OverlayLaunchBridge.kt) and never emits a decision event.
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
  /// `expiresAt` in ms, plus the full payload the overlay keeps for the
  /// APPROVE handoff) plus an optional `palette` map of hex colors
  /// (app_theme.dart) that the overlay resolves at runtime; every entry is
  /// forwarded unchanged to the native side. Returns `shown`, or
  /// `permission_required` when the SYSTEM_ALERT_WINDOW access is missing
  /// (the user is routed to the Settings grant page).
  static Future<String> show(Map<String, dynamic> request) async {
    final Object? result = await _method.invokeMethod<dynamic>('show', request);
    return result as String? ?? '';
  }

  /// Hides the overlay window, if one is showing.
  static Future<void> hide() async {
    await _method.invokeMethod<dynamic>('hide');
  }

  /// Hides the overlay card for one session (native `OverlayWindow.hideForId`,
  /// task 21). Idempotent: a no-op when no card for [id] is showing.
  static Future<void> hideForId(String id) async {
    await _method.invokeMethod<dynamic>(
        'hideForId', <String, dynamic>{'id': id});
  }

  /// DENY presses and timeouts from the overlay:
  /// `{"type": "decision", "id": ..., "decision": "deny", "source": ...}`
  /// and `{"type": "expired", "id": ...}`. APPROVE taps never appear here —
  /// they launch the main Activity (task 12).
  static Stream<Map<String, dynamic>> decisions() => _events
      .receiveBroadcastStream()
      .map((dynamic event) => Map<String, dynamic>.from(event as Map));
}
