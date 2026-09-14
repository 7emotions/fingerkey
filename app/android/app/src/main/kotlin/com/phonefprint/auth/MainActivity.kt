package com.phonefprint.auth

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.embedding.engine.dart.DartExecutor
import io.flutter.plugins.GeneratedPluginRegistrant

/**
 * UI host for the approval flow. SINGLE OWNERSHIP: this engine owns no
 * daemon socket. The persistent links live in the headless engine of
 * [ApprovalForegroundService] (started in [onCreate]); this engine:
 *  - shares the process [io.flutter.embedding.engine.FlutterEngineGroup]
 *    (one VM) via [provideFlutterEngine],
 *  - delegates pairing-time channel traffic to the service's single
 *    [TcpTlsChannel] through [TcpTlsChannelDelegate],
 *  - renders the service's pending stream via the cross-engine Dart bridge
 *    (lib/service_bridge.dart), never dialing for approvals.
 *
 * Overlay APPROVE taps (task 12) land here via [OverlayWindow]'s launch
 * Intent; the payload is handed to [OverlayLaunchBridge], which replays it
 * to the Dart approval screen so the biometric prompt runs here ONCE — this
 * Activity is the only place [local_auth] may run.
 */
class MainActivity : FlutterFragmentActivity() {

    companion object {
        private const val REQUEST_POST_NOTIFICATIONS = 1401
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Keep the approval link alive whenever the app is in use.
        ApprovalForegroundService.start(this)
        // An overlay APPROVE tap launches this Activity with the session
        // payload; store it for the Dart approval flow (task 12).
        OverlayLaunchBridge.ingest(intent)
        // Android 13+ (API 33) hides notifications until the user grants
        // POST_NOTIFICATIONS at runtime. Request it here on first launch so
        // the high-priority approval heads-up (ApprovalNotifier) is not
        // silently dropped on fresh installs.
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(
                arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                REQUEST_POST_NOTIFICATIONS,
            )
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        OverlayLaunchBridge.ingest(intent)
    }

    override fun provideFlutterEngine(context: Context): FlutterEngine? =
        // Spawn from the shared group so this engine and the service's
        // headless engine run in one VM (same isolate group).
        EngineHolder.engineGroup(context)
            .createAndRunEngine(context, DartExecutor.DartEntrypoint.createDefault())

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        // provideFlutterEngine takes over the automatic plugin registration.
        GeneratedPluginRegistrant.registerWith(flutterEngine)
        // Delegate every TLS channel call to the service-owned instance.
        flutterEngine.plugins.add(
            TcpTlsChannelDelegate { EngineHolder.serviceChannel(applicationContext) },
        )
        // Replay overlay-APPROVE payloads to the UI isolate (task 12).
        flutterEngine.plugins.add(OverlayLaunchBridge())
        // Settings plumbing (task 13): battery-optimization state + the
        // user-triggered exemption dialog, and the roster-configured marker
        // consumed by the boot receiver. The marker is also registered on the
        // service engine (ApprovalForegroundService) because roster writes
        // happen in both.
        PowerChannel.register(flutterEngine.dartExecutor.binaryMessenger, applicationContext)
        KeepalivePrefs.register(flutterEngine.dartExecutor.binaryMessenger, applicationContext)
    }
}
