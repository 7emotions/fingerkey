import 'package:flutter_test/flutter_test.dart';
import 'package:auth/app_theme.dart';

void main() {
  test('buildColorScheme keeps the page surface and amber seed', () {
    final scheme = buildColorScheme();
    expect(scheme.surface, kPageSurface);
    expect(scheme.primary, isNot(kAccent)); // M3 tone-maps the seed; that's the app's real accent.
  });

  test('overlayPalette exposes the full overlay contract, warm', () {
    final palette = overlayPalette();
    expect(
      palette.keys.toSet(),
      <String>{
        'card',
        'cardHigh',
        'border',
        'track',
        'accent',
        'onAccent',
        'accentSoftAlpha',
        'text',
        'muted',
        'label',
        'denyStroke',
      },
    );
    // The old hardcoded overlay card was a cool blue-grey; the theme-derived
    // card must be the warm M3 surfaceContainer family instead.
    expect(palette['card'], isNot('161A20'));
    // These literals are the warm fallbacks hardcoded in OverlayWindow.kt —
    // assert equality so a Flutter/MCU upgrade that shifts the scheme is
    // caught here and the Kotlin defaults can be re-synced deliberately.
    expect(
      palette,
      <String, String>{
        'card': '241F17',
        'cardHigh': '2F2921',
        'border': '4F4539',
        'track': '3A342B',
        'accent': 'F2BE6E',
        'onAccent': '432C00',
        'accentSoftAlpha': '38',
        'text': 'EDE1D4',
        'muted': 'D2C4B4',
        'label': '9B8F80',
        'denyStroke': '9B8F80',
      },
    );
  });
}
