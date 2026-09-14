/// Single source of truth for the app palette.
///
/// Both the UI engine (`main.dart`) and the headless service isolate
/// (`service_bridge.dart`, which owns the native approval overlay) derive
/// their colors from here, so the overlay can never drift from the app's
/// design language. [ColorScheme.fromSeed] is pure Dart (it lives in
/// material_color_utilities), so [buildColorScheme] and [overlayPalette] are
/// safe to call from the background isolate without any platform view.
library;

import 'package:flutter/material.dart';

/// The amber accent every color derives from (seed) or pairs with.
const Color kAccent = Color(0xFFFFB000);

/// The page/scaffold surface behind cards (a near-black, cooler than the
/// warm M3 card surfaces it carries).
const Color kPageSurface = Color(0xFF0B0E11);

/// The app's dark Material-3 scheme: amber seed over the page surface.
ColorScheme buildColorScheme() => ColorScheme.fromSeed(
      seedColor: kAccent,
      brightness: Brightness.dark,
    ).copyWith(surface: kPageSurface);

/// Soft accent overlay alpha (hex 0x26), used by the native overlay's tonal
/// fingerprint chip.
const int kAccentSoftAlpha = 0x26;

/// The palette the native approval overlay needs, as hex strings WITHOUT a
/// leading `#` (Kotlin re-adds it: `Color.parseColor("#$hex")`).
///
/// [cs] defaults to [buildColorScheme()]. This map rides inside the overlay
/// `show` payload, so the overlay resolves its colors from the exact scheme
/// the app is running — runtime sync, no hardcoded copy.
Map<String, String> overlayPalette([ColorScheme? cs]) {
  final scheme = cs ?? buildColorScheme();
  String hex(Color color) => color
      .toARGB32()
      .toRadixString(16)
      .padLeft(8, '0')
      .substring(2)
      .toUpperCase();
  return <String, String>{
    'card': hex(scheme.surfaceContainer),
    'cardHigh': hex(scheme.surfaceContainerHigh),
    'border': hex(scheme.outlineVariant),
    'track': hex(scheme.surfaceContainerHighest),
    'accent': hex(scheme.primary),
    'onAccent': hex(scheme.onPrimary),
    'accentSoftAlpha': '$kAccentSoftAlpha',
    'text': hex(scheme.onSurface),
    'muted': hex(scheme.onSurfaceVariant),
    'label': hex(scheme.outline),
    'denyStroke': hex(scheme.outline),
  };
}
